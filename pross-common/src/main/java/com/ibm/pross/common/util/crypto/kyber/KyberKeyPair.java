package com.ibm.pross.common.util.crypto.kyber;

import java.util.List;

public class KyberKeyPair {

    private List<Kyber.Polynomial> pk;
    private List<Kyber.Polynomial> sk;
    private byte[] publicSeed;

    public KyberKeyPair(List<Kyber.Polynomial> pk, List<Kyber.Polynomial> sk, byte[] publicSeed) {
        this.pk = pk;
        this.sk = sk;
        this.publicSeed = publicSeed;
    }

    public List<Kyber.Polynomial> getPk() {
        return pk;
    }

    public List<Kyber.Polynomial> getSk() {
        return sk;
    }

    public byte[] getPublicSeed() {
        return publicSeed;
    }
}
