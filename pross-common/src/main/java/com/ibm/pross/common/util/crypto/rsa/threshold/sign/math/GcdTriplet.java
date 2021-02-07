package com.ibm.pross.common.util.crypto.rsa.threshold.sign.math;

import java.math.BigInteger;

public class GcdTriplet {
    private final BigInteger g;
    private final BigInteger x;
    private final BigInteger y;

    public GcdTriplet(final BigInteger g, final BigInteger x, final BigInteger y) {
        this.g = g;
        this.x = x;
        this.y = y;
    }

    /**
     * Represents gcd(a, b)
     *
     * @return
     */
    public BigInteger getG() {
        return g;
    }

    /**
     * Represents the co-efficient of b in the identity: ax + by = gcd(a, b)
     *
     * @return
     */
    public BigInteger getY() {
        return y;
    }

    /**
     * Represents the co-efficient of b in the identity: ax + by = gcd(a, b)
     *
     * @return
     */
    public BigInteger getX() {
        return x;
    }


    /**
     * Returns a triplet representing the greatest common divisor between a and b
     * (g), as well as the coefficients x and y that satisfy Bézout's identity: ax +
     * by = gcd(a, b)
     *
     * @param a
     * @param b
     * @return (g, x, y)
     */
    public static GcdTriplet extendedGreatestCommonDivisor(BigInteger a, BigInteger b) {
        if (a.equals(BigInteger.ZERO)) {
            return new GcdTriplet(b, BigInteger.ZERO, BigInteger.ONE);
        } else {
           GcdTriplet t = extendedGreatestCommonDivisor(b.mod(a), a);
            BigInteger g = t.getG();
            BigInteger x = t.getX();
            BigInteger y = t.getY();
            return new GcdTriplet(g, y.subtract(b.divide(a).multiply(x)), x);
        }
    }
}
