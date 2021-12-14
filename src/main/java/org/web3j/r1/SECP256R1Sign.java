package org.web3j.r1;

import lombok.extern.slf4j.Slf4j;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.web3j.crypto.TransactionEncoder.asRlpValues;
import static org.web3j.utils.Assertions.verifyPrecondition;

@Slf4j
public final class SECP256R1Sign {
    private SECP256R1Sign() {
    }

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256r1");
    private static final int DEFAULT_HEADER_BYTE = 27;
    private static final int PADDED_BYTE_LENGTH = 32;

    static final ECDomainParameters CURVE =
            new ECDomainParameters(
                    CURVE_PARAMS.getCurve(),
                    CURVE_PARAMS.getG(),
                    CURVE_PARAMS.getN(),
                    CURVE_PARAMS.getH());

    static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

    public static ECDSASignatureR1 sign(final byte[] transactionHash, final ECKeyPair keyPair) {
        final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));

        final ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(keyPair.getPrivateKey(), CURVE);
        signer.init(true, privKey);

        final BigInteger[] signatureComponents = signer.generateSignature(transactionHash);

        return new ECDSASignatureR1(signatureComponents[0], signatureComponents[1]);
    }

    /**
     * Given the components of a signature and a selector value, recover and return the public key
     * that generated the signature according to the algorithm in SEC1v2 section 4.1.6.
     *
     * <p>The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the
     * correct one. Because the key recovery operation yields multiple potential keys, the correct
     * key must either be stored alongside the signature, or you must be willing to try each recId
     * in turn until you find one that outputs the key you are expecting.
     *
     * <p>If this method returns null it means recovery was not possible and recId should be
     * iterated.
     *
     * <p>Given the above two points, a correct usage of this method is inside a for loop from 0 to
     * 3, and if the output is null OR a key that is not the one you expect, you try again with the
     * next recId.
     *
     * @param recId Which possible key to recover.
     * @param sig the R and S components of the signature, wrapped.
     * @param message Hash of the data that was signed.
     * @return An ECKey containing only the public part, or null if recovery wasn't possible.
     */
    public static BigInteger recoverFromSignature(final int recId, final ECDSASignatureR1 sig, final byte[] message) {
        verifyPrecondition(recId >= 0, "recId must be positive");
        verifyPrecondition(sig.r.signum() >= 0, "r must be positive");
        verifyPrecondition(sig.s.signum() >= 0, "s must be positive");
        verifyPrecondition(message != null, "message cannot be null");

        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = CURVE.getN(); // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = sig.r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion
        //        routine specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R
        //        using the conversion routine specified in Section 2.3.4. If this conversion
        //        routine outputs "invalid", then do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = SecP256R1Curve.q;
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are
        // two possibilities. So it's encoded in the recId.
        ECPoint r = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers
        //        responsibility).
        if (!r.multiply(n).isInfinity()) {
            return null;
        }
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = new BigInteger(1, message);
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via
        //        iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s **
        // Where -e is the modular additive R) + (mi(r) * -e ** G)inverse of e, that is z such that z + e = 0 (mod n).
        // In the above equation ** is point multiplication and + is point addition (the EC group
        // operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For
        // example the additive inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and
        // -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.r.modInverse(n);
        BigInteger srInv = rInv.multiply(sig.s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, r, srInv);

        byte[] qBytes = q.getEncoded(false);
        // We remove the prefix
        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }

    /** Decompress a compressed public key (x co-ord and low-bit of y-coord). */
    private static ECPoint decompressKey(final BigInteger xBN, final boolean yBit) {
        final X9IntegerConverter x9 = new X9IntegerConverter();
        final byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }

    public static int recoverKeyIndex(final ECDSASignatureR1 sig, final byte[] hash, ECPublicKey ecPublicKey) {
        final BigInteger publicKey = Numeric.toBigInt(toByteArray(ecPublicKey));
        for (int i = 0; i < 4; i++) {
            final BigInteger k = SECP256R1Sign.recoverFromSignature(i, sig, hash);
            log.debug("recovered key: {}", k);
            if (k != null && k.equals(publicKey)) {
                return i;
            }
        }
        return -1;
    }

    public static String createSignedTransaction(final ECDSASignatureR1 canonicalised, final RawTransaction rawTransaction,
                                                 final byte[] messageHash, final ECPublicKey ecPublicKey) {
        final int recId = SECP256R1Sign.recoverKeyIndex(canonicalised, messageHash, ecPublicKey);
        if (recId == -1) {
            //throw new RecoverableKeyException("Could not recover public key");
        }

        int headerByte = recId + DEFAULT_HEADER_BYTE;
        byte[] v = new byte[]{(byte)headerByte};
        byte[] r = Numeric.toBytesPadded(canonicalised.r, PADDED_BYTE_LENGTH);
        byte[] s = Numeric.toBytesPadded(canonicalised.s, PADDED_BYTE_LENGTH);
        Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);

        byte[] signedDataBytes = encode(rawTransaction, signatureData);

        // Uncomment and use below to quickly debug
        // signedDataBytes = TransactionEncoder.signMessage(rawTransaction, Credentials.create(besuAccountSenderPrivateKey));

        return Numeric.toHexString(signedDataBytes);
    }

    private static ECDSASignatureR1 getEcdsaSignatureR1(String privateKey, String publicKey, byte[] messageHash) {
        final byte[] signature;
        final ECDSASignatureR1 initialSignature;
        log.debug("signing transaction without caas for public key {}", publicKey);
        Credentials credentials = Credentials.create(privateKey);
        initialSignature = SECP256R1Sign.sign(messageHash, credentials.getEcKeyPair());
        // understanding canonicalised refer to https://labs.mastercard.com/confluence_internal/display/BCORE/Transaction+signing+-+web3j%2C+EthSigner+and+CaaS)
        return initialSignature.toCanonicalised();
    }

    public static String signTransaction(final RawTransaction rawTransaction, final String privateKey, final String publicKey) {
        final String signedTransactionData;
        final ECPublicKey ecPublicKey = EthPublicKeyUtils.createPublicKey(publicKey);
        byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
        final byte[] messageHash = Hash.sha3(encodedTransaction);

        final ECDSASignatureR1 canonicalised = getEcdsaSignatureR1(privateKey, publicKey, messageHash);
        signedTransactionData = SECP256R1Sign.createSignedTransaction(canonicalised, rawTransaction, messageHash, ecPublicKey);
        return signedTransactionData;
    }

    private static byte[] encode(RawTransaction rawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> values = asRlpValues(rawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    private static byte[] toByteArray(final ECPublicKey publicKey) {
        final java.security.spec.ECPoint ecPoint = publicKey.getW();
        final Bytes xBytes = Bytes32.wrap(asUnsignedByteArray(32, ecPoint.getAffineX()));
        final Bytes yBytes = Bytes32.wrap(asUnsignedByteArray(32, ecPoint.getAffineY()));
        return Bytes.concatenate(xBytes, yBytes).toArray();
    }

    public static BigInteger getR(byte[] signature) {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
    }

    public static BigInteger getS(byte[] signature) {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        int startS = startR + 2 + lengthR;
        int lengthS = signature[startS + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
    }
}
