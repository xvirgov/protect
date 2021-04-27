package com.ibm.pross.common.util.crypto.kyber;

import java.util.List;

public class KyberCiphertext {

    private List<Kyber.Polynomial> c1;
    private Kyber.Polynomial c2;

    public KyberCiphertext(List<Kyber.Polynomial> c1, Kyber.Polynomial c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public List<Kyber.Polynomial> getC1() {
        return c1;
    }

    public Kyber.Polynomial getC2() {
        return c2;
    }
}
