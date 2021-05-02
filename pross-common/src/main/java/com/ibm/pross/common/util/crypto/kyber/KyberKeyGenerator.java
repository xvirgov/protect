package com.ibm.pross.common.util.crypto.kyber;

import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class KyberKeyGenerator {

    // parameters
    private static final Logger logger = LogManager.getLogger(KyberKeyGenerator.class);

    public static List<KyberShareholder> generateKyber(final int numServers)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return generateKyber(numServers, Kyber.KYBER_N, Kyber.KYBER_K, Kyber.KYBER_Q, Kyber.KYBER_ETA1, Kyber.KYBER_ETA2);
    }

    public static List<KyberShareholder> generateKyber(final int numServers, final int n, final int k, final int q,
                                                       final int eta_1, final int eta_2) {
        logger.info("Generating n keypairs for kyber...");
        List<KyberKeyPair> keyPairs = new ArrayList<>();
        for(int i = 0; i < numServers; i++) {
            keyPairs.add(Kyber.indcpa_keypair());
        }
        logger.info("[DONE]");

        logger.info("Generating on public key...");
        // generate A, At
        List<Kyber.Matrix> as = new ArrayList<>();
        List<Kyber.Matrix> ats = new ArrayList<>();
        for(int i = 0; i < numServers; i++) {
            as.add(Kyber.gen_matrix(keyPairs.get(i).getPublicSeed(), false));
            ats.add(Kyber.gen_matrix(keyPairs.get(i).getPublicSeed(), true));
        }

        List<Kyber.Polynomial> sk = new ArrayList<>();
        for(int i = 0; i < Kyber.KYBER_K; i++) {
            sk.add(new Kyber.Polynomial(new short[Kyber.KYBER_N]));
        }

        // initialize matrices
        List<List<Kyber.Polynomial>> aAccuList = new ArrayList<>();
        List<List<Kyber.Polynomial>> atAccuList = new ArrayList<>();
        for(int i = 0; i < Kyber.KYBER_K; i++) {
            List<Kyber.Polynomial> r = new ArrayList<>();
            List<Kyber.Polynomial> rt = new ArrayList<>();
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                r.add(new Kyber.Polynomial(new short[Kyber.KYBER_N]));
                rt.add(new Kyber.Polynomial(new short[Kyber.KYBER_N]));
            }
            aAccuList.add(r);
            atAccuList.add(rt);
        }

        Kyber.Matrix aCombined = new Kyber.Matrix(aAccuList);
        Kyber.Matrix atCombined = new Kyber.Matrix(atAccuList);

        for(int i = 0; i < numServers; i++) {
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                aCombined.matrix.set(j, Kyber.polyvec_add(aCombined.matrix.get(j), as.get(i).matrix.get(j)));
                atCombined.matrix.set(j, Kyber.polyvec_add(atCombined.matrix.get(j), ats.get(i).matrix.get(j)));
            }
        }

        for(int i = 0; i < numServers; i++) {
            sk = Kyber.polyvec_add(sk, keyPairs.get(i).getSk());
        }
        KyberKeyPair kyberKeyPairAfter = Kyber.indcpa_keypair_from_sk(aCombined, sk);
        logger.info("[DONE]");

        logger.info("Generating shareholders...");
        KyberPublicParameters kyberPublicParameters = new KyberPublicParameters.KyberPublicParametersBuilder()
                .setNumServers(numServers)
                .setPk(kyberKeyPairAfter.getPk())
                .setACombined(aCombined)
                .setAtCombined(atCombined)
                .build();

        List<KyberShareholder> kyberShareholders = new ArrayList<>();
        for(int i = 0; i < numServers; i++) {
            KyberShareholder kyberShareholder = new KyberShareholder.KyberShareholderBuilder()
                    .setKyberPublicParameters(kyberPublicParameters)
                    .setSecretShare(keyPairs.get(i).getSk())
                    .build();
            kyberShareholders.add(kyberShareholder);
        }
        logger.info("[DONE]");

        return kyberShareholders;
    }

}
