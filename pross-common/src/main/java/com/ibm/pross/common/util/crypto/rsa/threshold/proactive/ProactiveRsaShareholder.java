package com.ibm.pross.common.util.crypto.rsa.threshold.proactive;

import com.ibm.pross.common.util.SecretShare;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Representation of an agent (shareholder)
 */
public class ProactiveRsaShareholder {

    // Public parameters
    private final ProactiveRsaPublicParameters proactiveRsaPublicParameters;

    // Secret shares
    private BigInteger d_i;
    private List<SecretShare> s;
    private BigInteger s_i;

    private ProactiveRsaShareholder(ProactiveRsaShareholderBuilder proactiveRsaShareholderBuilder) {
        this.proactiveRsaPublicParameters = proactiveRsaShareholderBuilder.proactiveRsaPublicParameters;
        this.d_i = proactiveRsaShareholderBuilder.d_i;
        this.s = proactiveRsaShareholderBuilder.s;
        this.s_i = proactiveRsaShareholderBuilder.s_i;
    }

    public static ProactiveRsaShareholder getParams(JSONObject jsonObject) throws InvalidKeySpecException, NoSuchAlgorithmException {
        ProactiveRsaPublicParameters proactiveRsaPublicParameters = ProactiveRsaPublicParameters.getParams((JSONObject) jsonObject.get("proactiveRsaPublicParameters"));

        BigInteger d_i = new BigInteger(jsonObject.get("d_i").toString());
        BigInteger s_i = new BigInteger(jsonObject.get("s_i").toString());

        JSONArray s_json = (JSONArray) jsonObject.get("s");
        List<SecretShare> s = new ArrayList<>();
        for(int i = 0; i < proactiveRsaPublicParameters.getNumServers(); i++) {
            s.add(new SecretShare(BigInteger.valueOf(i+1), new BigInteger(s_json.get(i).toString())));
        }

        return new ProactiveRsaShareholderBuilder()
                .setD_i(d_i)
                .setS_i(s_i)
                .setS(s)
                .setProactiveRsaPublicParameters(proactiveRsaPublicParameters)
                .build();
    }

    public JSONObject getJson() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("d_i", this.d_i.toString());
        jsonObject.put("s_i", this.s_i.toString());

        JSONArray s = new JSONArray();
        s.addAll(this.s.stream().map(x -> x.getY().toString()).collect(Collectors.toList()));
        jsonObject.put("s", s);

        jsonObject.put("proactiveRsaPublicParameters", proactiveRsaPublicParameters.getJson());

        return jsonObject;
    }

    public static class ProactiveRsaShareholderBuilder {
        // Public parameters
        private ProactiveRsaPublicParameters proactiveRsaPublicParameters;

        // Secret shares
        private BigInteger d_i;
        private List<SecretShare> s;
        private BigInteger s_i;

        public ProactiveRsaShareholder build() {
            ProactiveRsaShareholder proactiveRsaShareholder = new ProactiveRsaShareholder(this);
            return proactiveRsaShareholder;
        }

        public ProactiveRsaShareholderBuilder setProactiveRsaPublicParameters(ProactiveRsaPublicParameters proactiveRsaPublicParameters) {
            this.proactiveRsaPublicParameters = proactiveRsaPublicParameters;
            return this;
        }

        public ProactiveRsaShareholderBuilder setD_i(BigInteger d_i) {
            this.d_i = d_i;
            return this;
        }

        public ProactiveRsaShareholderBuilder setS(List<SecretShare> s) {
            this.s = s;
            return this;
        }

        public ProactiveRsaShareholderBuilder setS_i(BigInteger s_i) {
            this.s_i = s_i;
            return this;
        }
    }

    public ProactiveRsaPublicParameters getProactiveRsaPublicParameters() {
        return proactiveRsaPublicParameters;
    }

    public BigInteger getD_i() {
        return d_i;
    }

    public List<SecretShare> getS() {
        return s;
    }

    public BigInteger getS_i() {
        return s_i;
    }

    public ProactiveRsaShareholder setD_i(BigInteger d_i) {
        this.d_i = d_i;
        return this;
    }

    public ProactiveRsaShareholder setS(List<SecretShare> s) {
        this.s = s;
        return this;
    }

    public ProactiveRsaShareholder setS_i(BigInteger s_i) {
        this.s_i = s_i;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProactiveRsaShareholder)) return false;
        ProactiveRsaShareholder that = (ProactiveRsaShareholder) o;
        return getProactiveRsaPublicParameters().equals(that.getProactiveRsaPublicParameters()) && getD_i().equals(that.getD_i()) && getS().equals(that.getS()) && getS_i().equals(that.getS_i());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getProactiveRsaPublicParameters(), getD_i(), getS(), getS_i());
    }
}
