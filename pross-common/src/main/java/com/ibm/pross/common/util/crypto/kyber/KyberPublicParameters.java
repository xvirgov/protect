package com.ibm.pross.common.util.crypto.kyber;

import org.json.simple.JSONObject;

import java.util.ArrayList;
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

    public JSONObject getJson() {
        JSONObject jsonObject = new JSONObject();

        for(int i = 0; i < Kyber.KYBER_K; i++) {
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                jsonObject.put("a_" + i + "_" + j,  KyberUtils.bytesToBase64(KyberUtils.shortsToBytes(aCombined.matrix.get(i).get(j).poly)));
                jsonObject.put("at_" + i + "_" + j,  KyberUtils.bytesToBase64(KyberUtils.shortsToBytes(atCombined.matrix.get(i).get(j).poly)));
            }
            jsonObject.put("pk_" + i, KyberUtils.bytesToBase64(KyberUtils.shortsToBytes(pk.get(i).poly)));
        }
        jsonObject.put("numServers", numServers);

        return jsonObject;
    }

    public static KyberPublicParameters getParams(JSONObject jsonObject) {
        List<Kyber.Polynomial> p = new ArrayList<>();
        List<List<Kyber.Polynomial>> a = new ArrayList<>();
        List<List<Kyber.Polynomial>> at = new ArrayList<>();

        for(int i = 0; i < Kyber.KYBER_K; i++) {
            p.add(new Kyber.Polynomial(KyberUtils.bytesToShorts(KyberUtils.base64ToBytes((String) jsonObject.get("pk_" + i)))));
            List<Kyber.Polynomial> ps = new ArrayList<>();
            List<Kyber.Polynomial> pts = new ArrayList<>();
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                Kyber.Polynomial pp = new Kyber.Polynomial(KyberUtils.bytesToShorts(KyberUtils.base64ToBytes((String) jsonObject.get("a_" + i + "_" + j))));
                ps.add(pp);
                Kyber.Polynomial pt = new Kyber.Polynomial(KyberUtils.bytesToShorts(KyberUtils.base64ToBytes((String) jsonObject.get("at_" + i + "_" + j))));
                pts.add(pt);
            }
            a.add(ps);
            at.add(pts);
        }

        Kyber.Matrix aM = new Kyber.Matrix(a);
        Kyber.Matrix atM = new Kyber.Matrix(at);

        int numServers = Integer.parseInt(jsonObject.get("numServers").toString());

        return new KyberPublicParametersBuilder()
                .setAtCombined(atM)
                .setACombined(aM)
                .setNumServers(numServers)
                .setPk(p)
                .build();
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
        if (!getPk().equals(that.getPk())) return false;
        if (!getaCombined().equals(that.getaCombined())) return false;
        return getAtCombined().equals(that.getAtCombined());
    }

    @Override
    public int hashCode() {
        int result = getNumServers();
        result = 31 * result + getPk().hashCode();
        result = 31 * result + getaCombined().hashCode();
        result = 31 * result + getAtCombined().hashCode();
        return result;
    }
}
