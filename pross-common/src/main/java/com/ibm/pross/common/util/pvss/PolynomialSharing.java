package com.ibm.pross.common.util.pvss;

import com.ibm.pross.common.util.SecretShare;

import java.util.List;
import java.util.Objects;

public class PolynomialSharing {

    private List<SecretShare> shares;
    private List<SecretShare> b_i;

    public PolynomialSharing(List<SecretShare> shares, List<SecretShare> b_i) {
        this.shares = shares;
        this.b_i = b_i;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PolynomialSharing)) return false;

        PolynomialSharing that = (PolynomialSharing) o;

        if (getShares() != null ? !getShares().equals(that.getShares()) : that.getShares() != null) return false;
        return getB_i() != null ? getB_i().equals(that.getB_i()) : that.getB_i() == null;
    }

    @Override
    public int hashCode() {
        int result = getShares() != null ? getShares().hashCode() : 0;
        result = 31 * result + (getB_i() != null ? getB_i().hashCode() : 0);
        return result;
    }

    public List<SecretShare> getShares() {
        return shares;
    }

    public List<SecretShare> getB_i() {
        return b_i;
    }

    public PolynomialSharing setShares(List<SecretShare> shares) {
        this.shares = shares;
        return this;
    }

    public PolynomialSharing setB_i(List<SecretShare> b_i) {
        this.b_i = b_i;
        return this;
    }
}
