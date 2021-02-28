package com.ibm.pross.common.util.crypto.rsa.threshold.proactive;

import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaProactiveSharing;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class ProactiveRsaPublicParameters {

    private static final Logger logger = LogManager.getLogger(ProactiveRsaPublicParameters.class);

    // Threshold config
    private final int numServers;
    private final int threshold;

    // Crypto scheme parameters
    private final RSAPublicKey publicKey;
    private final BigInteger g;
    private final BigInteger d_pub;

    // Scheme security config
    private final BigInteger r; // caps the number of epochs
    private final int tau;
    private final int tauHat;
    private final BigInteger bigR;
    private final BigInteger coeffR;

    // Verification values
    private final List<SecretShare> w; // dimension: n
    private final List<List<SecretShare>> b; // dimension: nxt

    // Pre-computed values
    private final BigInteger L; // L = n!

    // Verification values
    private final List<SecretShare> bAgent;  // dimension: n

    // GCD values (for decryption)
    private final BigInteger aGcd;
    private final BigInteger bGcd;

    private ProactiveRsaPublicParameters(ProactiveRsaPublicParametersBuilder proactiveRsaPublicParametersBuilder) {
        this.numServers = proactiveRsaPublicParametersBuilder.numServers;
        this.threshold = proactiveRsaPublicParametersBuilder.threshold;
        this.publicKey = proactiveRsaPublicParametersBuilder.publicKey;
        this.g = proactiveRsaPublicParametersBuilder.g;
        this.d_pub = proactiveRsaPublicParametersBuilder.d_pub;
        this.r = proactiveRsaPublicParametersBuilder.r;
        this.tau = proactiveRsaPublicParametersBuilder.tau;
        this.tauHat = proactiveRsaPublicParametersBuilder.tauHat;
        this.bigR = proactiveRsaPublicParametersBuilder.bigR;
        this.coeffR = proactiveRsaPublicParametersBuilder.coeffR;
        this.w = proactiveRsaPublicParametersBuilder.w;
        this.b = proactiveRsaPublicParametersBuilder.b;
        this.L = proactiveRsaPublicParametersBuilder.L;
        this.bAgent = proactiveRsaPublicParametersBuilder.bAgent;
        this.aGcd = proactiveRsaPublicParametersBuilder.aGcd;
        this.bGcd = proactiveRsaPublicParametersBuilder.bGcd;
    }

    public static ProactiveRsaPublicParameters getParams(JSONObject jsonObject) throws NoSuchAlgorithmException, InvalidKeySpecException {

        BigInteger publicKeyExponent = new BigInteger(jsonObject.get("publicKeyExponent").toString());
        BigInteger modulus = new BigInteger(jsonObject.get("modulus").toString());
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicKeyExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);

        BigInteger g = new BigInteger(jsonObject.get("g").toString());
        BigInteger d_pub = new BigInteger(jsonObject.get("d_pub").toString());
        BigInteger L = new BigInteger(jsonObject.get("L").toString());
        BigInteger aGcd = new BigInteger(jsonObject.get("aGcd").toString());
        BigInteger bGcd = new BigInteger(jsonObject.get("bGcd").toString());
        int numServers = Integer.parseInt(jsonObject.get("numServers").toString());
        int threshold = Integer.parseInt(jsonObject.get("threshold").toString());
        BigInteger r =  new BigInteger(jsonObject.get("r").toString());
        int tau = Integer.parseInt(jsonObject.get("tau").toString());
        int tauHat = Integer.parseInt(jsonObject.get("tauHat").toString());
        BigInteger bigR = new BigInteger(jsonObject.get("bigR").toString());
        BigInteger coeffR = new BigInteger(jsonObject.get("coeffR").toString());

        JSONArray w_json = (JSONArray) jsonObject.get("w");
        JSONArray bAgent_json = (JSONArray) jsonObject.get("bAgent");

        List<SecretShare> w = new ArrayList<>();
        List<List<SecretShare>> b = new ArrayList<>();
        List<SecretShare> bAgent = new ArrayList<>();

        for(int i = 0; i < numServers; i++) {
            JSONArray b_i_json = (JSONArray) jsonObject.get("b_" + (i+1));
            List<SecretShare> b_i = new ArrayList<>();
            for(int j = 0; j < threshold; j++) {
                b_i.add(new SecretShare(BigInteger.valueOf(j+1), new BigInteger(b_i_json.get(j).toString())));
            }
            b.add(b_i);

            w.add(new SecretShare(BigInteger.valueOf(i+1), new BigInteger(w_json.get(i).toString())));
            bAgent.add(new SecretShare(BigInteger.valueOf(i+1), new BigInteger(bAgent_json.get(i).toString())));
        }

        return new ProactiveRsaPublicParametersBuilder()
                .setPublicKey(rsaPublicKey)
                .setB(b)
                .setbAgent(bAgent)
                .setG(g)
                .setD_pub(d_pub)
                .setL(L)
                .setaGcd(aGcd)
                .setbGcd(bGcd)
                .setR(r)
                .setTau(tau)
                .setNumServers(numServers)
                .setThreshold(threshold)
                .setTauHat(tauHat)
                .setBigR(bigR)
                .setCoeffR(coeffR)
                .setW(w)
                .build();
    }

    public JSONObject getJson() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("publicKeyExponent", publicKey.getPublicExponent().toString());
        jsonObject.put("modulus", publicKey.getModulus().toString());
        jsonObject.put("g", this.g.toString());
        jsonObject.put("d_pub", this.d_pub.toString());
        jsonObject.put("L", this.L.toString());
        jsonObject.put("aGcd", this.aGcd.toString());
        jsonObject.put("bGcd", this.bGcd.toString());

        jsonObject.put("numServers", String.valueOf(this.numServers));
        jsonObject.put("threshold", String.valueOf(this.threshold));
        jsonObject.put("r", this.r.toString());
        jsonObject.put("tau", String.valueOf(this.tau));
        jsonObject.put("tauHat", String.valueOf(this.tauHat));
        jsonObject.put("bigR", this.bigR.toString());
        jsonObject.put("coeffR", this.coeffR.toString());

        JSONArray w = new JSONArray();
        w.addAll(this.w.stream().map(x -> x.getY().toString()).collect(Collectors.toList()));
        jsonObject.put("w", w);

        JSONArray bAgent = new JSONArray();
        bAgent.addAll(this.bAgent.stream().map(x -> x.getY().toString()).collect(Collectors.toList()));
        jsonObject.put("bAgent", bAgent);

        for(int i = 0; i < numServers; i++) {
            JSONArray b_i = new JSONArray();
            b_i.addAll(this.b.get(i).stream().map(x -> x.getY().toString()).collect(Collectors.toList()));
            jsonObject.put("b_" + (i+1), b_i);
        }

        return jsonObject;
    }

    public static class ProactiveRsaPublicParametersBuilder {
        // Threshold config
        private int numServers;
        private int threshold;

        // Crypto scheme parameters
        private RSAPublicKey publicKey;
        private BigInteger g;
        private BigInteger d_pub;

        // Scheme security config
        private BigInteger r; // caps the number of epochs
        private int tau;
        private int tauHat;
        private BigInteger bigR;
        private BigInteger coeffR;

        // Verification values
        private List<SecretShare> w; // dimension: n
        private List<List<SecretShare>> b; // dimension: nxt

        // Pre-computed values
        private BigInteger L; // L = n!

        // Verification values
        private List<SecretShare> bAgent;  // dimension: n

        // GCD values (for decryption)
        private BigInteger aGcd;
        private BigInteger bGcd;

        public ProactiveRsaPublicParameters build() {
            ProactiveRsaPublicParameters proactiveRsaPublicParameters = new ProactiveRsaPublicParameters(this);
            validateProactiveRsaPublicParameters(proactiveRsaPublicParameters);
            return proactiveRsaPublicParameters;
        }

        public void validateProactiveRsaPublicParameters(ProactiveRsaPublicParameters proactiveRsaPublicParameters) {
            int numServers = proactiveRsaPublicParameters.numServers;
            int threshold = proactiveRsaPublicParameters.numServers;

            if (proactiveRsaPublicParameters.bAgent.size() != numServers)
                throw new RuntimeException("Invalid number of validation shares (bAgent)");

            if (proactiveRsaPublicParameters.w.size() != numServers)
                throw new RuntimeException("Invalid number of validation shares (w)");

            if (proactiveRsaPublicParameters.b.size() != numServers)
                throw new RuntimeException("Invalid number of validation shares (b)");
        }

        public ProactiveRsaPublicParametersBuilder setNumServers(int numServers) {
            this.numServers = numServers;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setThreshold(int threshold) {
            this.threshold = threshold;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setPublicKey(RSAPublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setG(BigInteger g) {
            this.g = g;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setD_pub(BigInteger d_pub) {
            this.d_pub = d_pub;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setR(BigInteger r) {
            this.r = r;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setTau(int tau) {
            this.tau = tau;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setTauHat(int tauHat) {
            this.tauHat = tauHat;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setBigR(BigInteger bigR) {
            this.bigR = bigR;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setCoeffR(BigInteger coeffR) {
            this.coeffR = coeffR;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setW(List<SecretShare> w) {
            this.w = w;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setB(List<List<SecretShare>> b) {
            this.b = b;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setL(BigInteger l) {
            L = l;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setbAgent(List<SecretShare> bAgent) {
            this.bAgent = bAgent;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setaGcd(BigInteger aGcd) {
            this.aGcd = aGcd;
            return this;
        }

        public ProactiveRsaPublicParametersBuilder setbGcd(BigInteger bGcd) {
            this.bGcd = bGcd;
            return this;
        }
    }

    public int getNumServers() {
        return numServers;
    }

    public int getThreshold() {
        return threshold;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getD_pub() {
        return d_pub;
    }

    public BigInteger getR() {
        return r;
    }

    public int getTau() {
        return tau;
    }

    public int getTauHat() {
        return tauHat;
    }

    public BigInteger getBigR() {
        return bigR;
    }

    public BigInteger getCoeffR() {
        return coeffR;
    }

    public List<SecretShare> getW() {
        return w;
    }

    public List<List<SecretShare>> getB() {
        return b;
    }

    public BigInteger getL() {
        return L;
    }

    public List<SecretShare> getbAgent() {
        return bAgent;
    }

    public BigInteger getaGcd() {
        return aGcd;
    }

    public BigInteger getbGcd() {
        return bGcd;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProactiveRsaPublicParameters)) return false;
        ProactiveRsaPublicParameters that = (ProactiveRsaPublicParameters) o;

        for (int i = 0; i < getB().size(); i++) {
            List<SecretShare> shares = getB().get(i);
            List<SecretShare> sharesOther = that.getB().get(i);

            if(!shares.equals(sharesOther))
                return false;
        }

        return getNumServers() == that.getNumServers() && getThreshold() == that.getThreshold() && getTau() == that.getTau() && getTauHat() == that.getTauHat() && getPublicKey().getPublicExponent().equals(that.getPublicKey().getPublicExponent()) && getPublicKey().getModulus().equals(that.getPublicKey().getModulus()) && getG().equals(that.getG()) && getD_pub().equals(that.getD_pub()) && getR().equals(that.getR()) && getBigR().equals(that.getBigR()) && getCoeffR().equals(that.getCoeffR()) && getW().equals(that.getW()) && getL().equals(that.getL()) && getbAgent().equals(that.getbAgent()) && getaGcd().equals(that.getaGcd()) && getbGcd().equals(that.getbGcd());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getNumServers(), getThreshold(), getPublicKey(), getG(), getD_pub(), getR(), getTau(), getTauHat(), getBigR(), getCoeffR(), getW(), getB(), getL(), getbAgent(), getaGcd(), getbGcd());
    }
}
