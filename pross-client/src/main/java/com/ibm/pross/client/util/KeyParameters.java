package com.ibm.pross.client.util;

import java.util.Objects;

public abstract class KeyParameters extends Object {

    public Long getEpoch() {
        return epoch;
    }

    final protected Long epoch;


    protected KeyParameters(Long epoch) {
        this.epoch = epoch;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyParameters)) return false;
        KeyParameters that = (KeyParameters) o;
        return getEpoch().equals(that.getEpoch());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getEpoch());
    }
}
