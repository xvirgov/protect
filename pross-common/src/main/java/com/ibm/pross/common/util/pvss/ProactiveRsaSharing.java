package com.ibm.pross.common.util.pvss;

import com.ibm.pross.common.util.SecretShare;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

public class ProactiveRsaSharing {

    private final int i;
    private List<SecretShare> d_i_j;
    private final SecretShare d_i_pub;
    private final List<SecretShare> w_i_j;

    public ProactiveRsaSharing(int i, List<SecretShare> d_i_j, SecretShare d_i_pub, List<SecretShare> w_i_j) {
        this.i = i;
        this.d_i_j = d_i_j;
        this.d_i_pub = d_i_pub;
        this.w_i_j = w_i_j;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProactiveRsaSharing)) return false;

        ProactiveRsaSharing that = (ProactiveRsaSharing) o;

        if (getI() != that.getI()) return false;
        if (getD_i_j() != null ? !getD_i_j().equals(that.getD_i_j()) : that.getD_i_j() != null) return false;
        if (getD_i_pub() != null ? !getD_i_pub().equals(that.getD_i_pub()) : that.getD_i_pub() != null) return false;
        return getW_i_j() != null ? getW_i_j().equals(that.getW_i_j()) : that.getW_i_j() == null;
    }

    @Override
    public int hashCode() {
        int result = getI();
        result = 31 * result + (getD_i_j() != null ? getD_i_j().hashCode() : 0);
        result = 31 * result + (getD_i_pub() != null ? getD_i_pub().hashCode() : 0);
        result = 31 * result + (getW_i_j() != null ? getW_i_j().hashCode() : 0);
        return result;
    }

    public int getI() {
        return i;
    }

    public List<SecretShare> getD_i_j() {
        return d_i_j;
    }

    public ProactiveRsaSharing setD_i_j(List<SecretShare> d_i_j) {
        this.d_i_j = d_i_j;
        return this;
    }

    public SecretShare getD_i_pub() {
        return d_i_pub;
    }

    public List<SecretShare> getW_i_j() {
        return w_i_j;
    }
}
