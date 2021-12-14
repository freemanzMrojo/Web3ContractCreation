package org.web3j.r1;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.tuweni.bytes.Bytes;
import org.web3j.utils.Numeric;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.nimbusds.jose.jwk.KeyType.EC;

@Slf4j
public final class EthPublicKeyUtils {
    private static final int PUBLIC_KEY_SIZE = 64;
    private static final String SECP_256_R1 = "secp256r1";

    private EthPublicKeyUtils() {
    }

    public static ECPublicKey createPublicKey(final String publicKey) {
        byte[] hexPublc = new byte[0];
        try {
            hexPublc = Hex.decodeHex(publicKey);
        } catch (final DecoderException exception) {
            log.debug("There was an issue when attempting to decode the public key: {}", exception.getMessage());
        }
        return createPublicKey(Bytes.of(hexPublc));
    }

    private static ECPublicKey createPublicKey(final Bytes value) {
        checkArgument(value.size() == PUBLIC_KEY_SIZE, "Invalid public key size must be 64 bytes");
        final Bytes x = value.slice(0, 32);
        final Bytes y = value.slice(32, 32);
        final ECPoint ecPoint = new ECPoint(Numeric.toBigInt(x.toArrayUnsafe()), Numeric.toBigInt(y.toArrayUnsafe()));
        return createPublicKey(ecPoint);
    }

    private static ECPublicKey createPublicKey(final ECPoint publicPoint) {
        try {
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC.getValue());
            parameters.init(new ECGenParameterSpec(SECP_256_R1));
            final ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            final ECPublicKeySpec pubSpec = new ECPublicKeySpec(publicPoint, ecParameters);
            final KeyFactory kf = KeyFactory.getInstance(EC.getValue());
            return (ECPublicKey) kf.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e) {
            throw new IllegalStateException("Unable to create Ethereum public key", e);
        }
    }
}
