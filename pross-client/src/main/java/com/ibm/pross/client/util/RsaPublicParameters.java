package com.ibm.pross.client.util;

import java.math.BigInteger;
import java.util.Objects;

public class RsaPublicParameters extends SecretParameters {

    private final BigInteger exponent;
    private final BigInteger modulus;

    public RsaPublicParameters(BigInteger exponent, BigInteger modulus, Long epoch) {
        super(epoch);

        this.exponent = exponent;
        this.modulus = modulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RsaPublicParameters)) return false;
        if (!super.equals(o)) return false;
        RsaPublicParameters that = (RsaPublicParameters) o;
        return super.getEpoch().equals(that.getEpoch())
                && getExponent().equals(that.getExponent())
                && getModulus().equals(that.getModulus());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getExponent(), getModulus());
    }

    @Override
    public String toString() {
        return "RsaPublicParameters{" +
                "exponent=" + exponent +
                ", modulus=" + modulus +
                ", epoch=" + epoch +
                '}';
    }
}
