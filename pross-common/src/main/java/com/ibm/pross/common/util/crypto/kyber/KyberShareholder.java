package com.ibm.pross.common.util.crypto.kyber;

import java.util.List;

public class KyberShareholder {

    // Public parameters
    private final KyberPublicParameters kyberPublicParameters;

    // Secret share
    private final List<Kyber.Polynomial> secretShare;

    private KyberShareholder(KyberShareholderBuilder kyberShareholderBuilder) {
        this.kyberPublicParameters = kyberShareholderBuilder.kyberPublicParameters;
        this.secretShare = kyberShareholderBuilder.secretShare;
    }

    public static class KyberShareholderBuilder {
        private KyberPublicParameters kyberPublicParameters;
        private List<Kyber.Polynomial> secretShare;

        public KyberShareholder build() {
            return new KyberShareholder(this);
        }

        public KyberShareholderBuilder setKyberPublicParameters(KyberPublicParameters kyberPublicParameters) {
            this.kyberPublicParameters = kyberPublicParameters;
            return this;
        }

        public KyberShareholderBuilder setSecretShare(List<Kyber.Polynomial> secretShare) {
            this.secretShare = secretShare;
            return this;
        }
    }

    public KyberPublicParameters getKyberPublicParameters() {
        return kyberPublicParameters;
    }

    public List<Kyber.Polynomial> getSecretShare() {
        return secretShare;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KyberShareholder)) return false;

        KyberShareholder that = (KyberShareholder) o;

        if (!getKyberPublicParameters().equals(that.getKyberPublicParameters())) return false;
        return getSecretShare().equals(that.getSecretShare());
    }

    @Override
    public int hashCode() {
        int result = getKyberPublicParameters().hashCode();
        result = 31 * result + getSecretShare().hashCode();
        return result;
    }
}
