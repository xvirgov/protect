package com.ibm.pross.client.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class RsaPublicParameters extends KeyParameters {
    private final BigInteger exponent;
    private final BigInteger modulus;
    // Public verification parameters
    private final BigInteger verificationKey;
    private final List<BigInteger> shareVerificationKeys = new ArrayList<>();
    public RsaPublicParameters(BigInteger exponent, BigInteger modulus, BigInteger verificationKey, List<BigInteger> shareVerificationKeys,
                               Long epoch) {
        super(epoch);

        this.exponent = exponent;
        this.modulus = modulus;
        this.verificationKey = verificationKey;
        this.shareVerificationKeys.addAll(shareVerificationKeys);
    }

    @Override
    public String toString() {
        return "RsaPublicParameters{" +
                "epoch=" + epoch +
                ", exponent=" + exponent +
                ", modulus=" + modulus +
                ", verificationKey=" + verificationKey +
                ", shareVerificationKeys=" + shareVerificationKeys +
                '}';
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getVerificationKey() {
        return verificationKey;
    }

    public List<BigInteger> getShareVerificationKeys() {
        return shareVerificationKeys;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RsaPublicParameters)) return false;
        if (!super.equals(o)) return false;
        RsaPublicParameters that = (RsaPublicParameters) o;
        return getExponent().equals(that.getExponent()) && getModulus().equals(that.getModulus()) && getVerificationKey().equals(that.getVerificationKey()) && getShareVerificationKeys().equals(that.getShareVerificationKeys());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getExponent(), getModulus(), getVerificationKey(), getShareVerificationKeys());
    }
}
