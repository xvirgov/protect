package com.ibm.pross.client.util;

import java.util.Objects;

public abstract class SecretParameters extends Object {

    public Long getEpoch() {
        return epoch;
    }

    final protected Long epoch;


    protected SecretParameters(Long epoch) {
        this.epoch = epoch;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SecretParameters)) return false;
        SecretParameters that = (SecretParameters) o;
        return getEpoch().equals(that.getEpoch());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getEpoch());
    }
}
