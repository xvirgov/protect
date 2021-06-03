package com.ibm.pross.client.util;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

import java.util.SortedMap;

public class EciesPublicParams {

    private final SortedMap<Integer, EcPoint> verificationValues;
    private final EcPoint publicKey;
    final long epoch;

    public EciesPublicParams(SortedMap<Integer, EcPoint> verificationValues, EcPoint publicKey, long epoch) {
        this.verificationValues = verificationValues;
        this.publicKey = publicKey;
        this.epoch = epoch;
    }

    public SortedMap<Integer, EcPoint> getVerificationValues() {
        return verificationValues;
    }

    public EcPoint getPublicKey() {
        return publicKey;
    }

    public long getEpoch() {
        return epoch;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EciesPublicParams)) return false;

        EciesPublicParams that = (EciesPublicParams) o;

        if (epoch != that.epoch) return false;
        if (verificationValues != null ? !verificationValues.equals(that.verificationValues) : that.verificationValues != null)
            return false;
        return publicKey != null ? publicKey.equals(that.publicKey) : that.publicKey == null;
    }

    @Override
    public int hashCode() {
        int result = verificationValues != null ? verificationValues.hashCode() : 0;
        result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
        result = 31 * result + (int) (epoch ^ (epoch >>> 32));
        return result;
    }

    @Override
    public String toString() {
        return "EciesPublicParams{" +
                "verificationValues=" + verificationValues +
                ", publicKey=" + publicKey +
                ", epoch=" + epoch +
                '}';
    }
}
