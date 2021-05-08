package com.ibm.pross.common.util.crypto.kyber;

import com.ibm.pross.common.util.serialization.Parse;

import java.util.ArrayList;
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

    public byte[] toByteArray() {
        List<byte[]> c1List = new ArrayList<>();
        for(int i = 0; i < Kyber.KYBER_K; i++) {
            c1List.add(KyberUtils.shortsToBytes(c1.get(i).poly));
        }
        byte[] concat1 = Parse.concatenate(c1List);
        return Parse.concatenate(concat1, KyberUtils.shortsToBytes(c2.poly));
    }

    public static KyberCiphertext getCiphertext(byte[] array) {
        byte[][] split1 = Parse.splitArrays(array);
        byte[][] split2 = Parse.splitArrays(split1[0]);

        List<Kyber.Polynomial> c1 = new ArrayList<>();
        for(int i = 0; i < Kyber.KYBER_K; i++) {
            c1.add(new Kyber.Polynomial(KyberUtils.bytesToShorts(split2[i])));
        }

        Kyber.Polynomial c2 = new Kyber.Polynomial(KyberUtils.bytesToShorts(split1[1]));

        return new KyberCiphertext(c1, c2);
    }
}
