package com.ibm.pross.common.util.crypto.kyber;

import java.util.List;

public class KyberPublicParameters {

    // Threshold config
    private final int numServers;

    // Kyber public key
    private final List<Kyber.Polynomial> pk;

    // Security matrices
    private final Kyber.Matrix aCombined;
    private final Kyber.Matrix atCombined;

    private KyberPublicParameters(KyberPublicParametersBuilder kyberPublicParametersBuilder) {
        this.numServers = kyberPublicParametersBuilder.numServers;
        this.pk = kyberPublicParametersBuilder.pk;
        this.aCombined = kyberPublicParametersBuilder.aCombined;
        this.atCombined = kyberPublicParametersBuilder.atCombined;
    }

    public static class KyberPublicParametersBuilder {
        // Threshold config
        private int numServers;

        // Kyber public key
        private List<Kyber.Polynomial> pk;

        // Security matrices
        private Kyber.Matrix aCombined;
        private Kyber.Matrix atCombined;

        public KyberPublicParameters build() {
            return new KyberPublicParameters(this);
        }

        public KyberPublicParametersBuilder setNumServers(final int numServers) {
            this.numServers = numServers;
            return this;
        }

        public KyberPublicParametersBuilder setPk(final List<Kyber.Polynomial> pk) {
            this.pk = pk;
            return this;
        }

        public KyberPublicParametersBuilder setACombined(final Kyber.Matrix aCombined) {
            this.aCombined = aCombined;
            return this;
        }

        public KyberPublicParametersBuilder setAtCombined(final Kyber.Matrix atCombined) {
            this.atCombined = atCombined;
            return this;
        }
    }

    public int getNumServers() {
        return numServers;
    }

    public List<Kyber.Polynomial> getPk() {
        return pk;
    }

    public Kyber.Matrix getaCombined() {
        return aCombined;
    }

    public Kyber.Matrix getAtCombined() {
        return atCombined;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KyberPublicParameters)) return false;

        KyberPublicParameters that = (KyberPublicParameters) o;

        if (getNumServers() != that.getNumServers()) return false;
        if (getPk() != null ? !getPk().equals(that.getPk()) : that.getPk() != null) return false;
        if (getaCombined() != null ? !getaCombined().equals(that.getaCombined()) : that.getaCombined() != null)
            return false;
        return getAtCombined() != null ? getAtCombined().equals(that.getAtCombined()) : that.getAtCombined() == null;
    }

    @Override
    public int hashCode() {
        int result = getNumServers();
        result = 31 * result + (getPk() != null ? getPk().hashCode() : 0);
        result = 31 * result + (getaCombined() != null ? getaCombined().hashCode() : 0);
        result = 31 * result + (getAtCombined() != null ? getAtCombined().hashCode() : 0);
        return result;
    }
}
