package org.web3j.r1;

import org.web3j.crypto.ECDSASignature;

import java.math.BigInteger;

public class ECDSASignatureR1 extends ECDSASignature {

    public ECDSASignatureR1(final BigInteger r, final BigInteger s) {
        super(r, s);
    }

    /**
     * @return true if the S component is "low", that means it is below {@link SECP256R1Sign#HALF_CURVE_ORDER}.
     * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">BIP62</a>.
     */
    @Override
    public boolean isCanonical() {
        return s.compareTo(SECP256R1Sign.HALF_CURVE_ORDER) <= 0;
    }

    /**
     * Will automatically adjust the S component to be less than or equal to half the curve order,
     * if necessary. This is required because for every signature (r,s) the signature (r, -s (mod
     * N)) is a valid signature of the same message. However, we dislike the ability to modify the
     * bits of a Bitcoin transaction after it's been signed, as that violates various assumed
     * invariants. Thus in future only one of those forms will be considered legal and the other
     * will be banned.
     *
     * @return the signature in a canonicalised form.
     */
    @Override
    public ECDSASignatureR1 toCanonicalised() {
        if (!isCanonical()) {
            // The order of the curve is the number of valid points that exist on that curve.
            // If S is in the upper half of the number of valid points, then bring it back to
            // the lower half. Otherwise, imagine that
            //    N = 10
            //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
            //    10 - 8 == 2, giving us always the latter solution, which is canonical.
            return new ECDSASignatureR1(r, SECP256R1Sign.CURVE.getN().subtract(s));
        } else {
            return this;
        }
    }
}
