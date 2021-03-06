package com.ibm.pross.client.util;

import com.ibm.pross.common.util.SecretShare;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ProactiveRsaPublicParameters extends KeyParameters {
    private final BigInteger exponent;
    private final BigInteger modulus;
    // Public verification parameters
    private final BigInteger g;
    private final BigInteger d_pub;
    private final List<List<SecretShare>> feldmanVerificationValues;
    private final List<SecretShare> additiveVerificationValues;

    public ProactiveRsaPublicParameters(BigInteger exponent, BigInteger modulus, BigInteger g, BigInteger d_pub,
                                        List<List<SecretShare>> feldmanVerificationValues, List<SecretShare> additiveVerificationValues,
                                        Long epoch) {
        super(epoch);

        this.exponent = exponent;
        this.modulus = modulus;

        this.g = g;
        this.d_pub = d_pub;
        this.feldmanVerificationValues = feldmanVerificationValues;
        this.additiveVerificationValues = additiveVerificationValues;
    }

    public static List<SecretShare> computeAgentsFeldmanValues(List<List<SecretShare>> feldmanVerificationValues, int threshold, int numServers, BigInteger modulus) {
        List<BigInteger> multipliedFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            BigInteger accumulator = BigInteger.ONE;
            for (int j = 0; j < numServers; j++) {
                accumulator = accumulator.multiply(feldmanVerificationValues.get(j).get(i).getY());
            }
            multipliedFeldmanVerificationValues.add(accumulator);
        }

        List<SecretShare> agentsFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            BigInteger result = BigInteger.ONE;
            for (int j = 0; j < threshold; j++) {
                result = result.multiply(multipliedFeldmanVerificationValues.get(j).modPow(BigInteger.valueOf(i + 1).pow(j), modulus)).mod(modulus);
            }
            agentsFeldmanVerificationValues.add(new SecretShare(BigInteger.valueOf(i + 1), result));
        }

        return agentsFeldmanVerificationValues;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getD_pub() {
        return d_pub;
    }

    public List<List<SecretShare>> getFeldmanVerificationValues() {
        return feldmanVerificationValues;
    }

    public List<SecretShare> getAdditiveVerificationValues() {
        return additiveVerificationValues;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public List<SecretShare> computeAgentsFeldmanValues(int threshold, int numServers) {
        List<BigInteger> multipliedFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            BigInteger accumulator = BigInteger.ONE;
            for (int j = 0; j < numServers; j++) {
                accumulator = accumulator.multiply(feldmanVerificationValues.get(j).get(i).getY());
            }
            multipliedFeldmanVerificationValues.add(accumulator);
        }

        List<SecretShare> agentsFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            BigInteger result = BigInteger.ONE;
            for (int j = 0; j < threshold; j++) {
                result = result.multiply(multipliedFeldmanVerificationValues.get(j).modPow(BigInteger.valueOf(i + 1).pow(j), modulus)).mod(modulus);
            }
            agentsFeldmanVerificationValues.add(new SecretShare(BigInteger.valueOf(i + 1), result));
        }

        return agentsFeldmanVerificationValues;
    }

    public BigInteger computeAgentsFeldmanValues(int threshold, int numServers, int index) {
        List<BigInteger> multipliedFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            BigInteger accumulator = BigInteger.ONE;
            for (int j = 0; j < numServers; j++) {
                accumulator = accumulator.multiply(feldmanVerificationValues.get(j).get(i).getY());
            }
            multipliedFeldmanVerificationValues.add(accumulator);
        }

        BigInteger result = BigInteger.ONE;
        for (int j = 0; j < threshold; j++) {
            result = result.multiply(multipliedFeldmanVerificationValues.get(j).modPow(BigInteger.valueOf(index).pow(j), modulus)).mod(modulus);
        }

        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProactiveRsaPublicParameters)) return false;
        if (!super.equals(o)) return false;
        ProactiveRsaPublicParameters that = (ProactiveRsaPublicParameters) o;
        return getExponent().equals(that.getExponent()) && getModulus().equals(that.getModulus()) && getG().equals(that.getG()) &&
                getD_pub().equals(that.getD_pub()) && getFeldmanVerificationValues().equals(that.getFeldmanVerificationValues()) &&
                getAdditiveVerificationValues().equals(that.getAdditiveVerificationValues());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getExponent(), getModulus(), getG(), getD_pub(), getFeldmanVerificationValues(), getAdditiveVerificationValues());
    }

    @Override
    public String toString() {
        return "ProactiveRsaPublicParameters{" +
                "exponent=" + exponent +
                ", modulus=" + modulus +
                ", g=" + g +
                ", d_pub=" + d_pub +
                ", feldmanVerificationValues=" + feldmanVerificationValues +
                ", additiveVerificationValues=" + additiveVerificationValues +
                '}';
    }
}
