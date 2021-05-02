package com.ibm.pross.common.util.crypto.kyber;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.json.simple.JSONObject;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class KyberKeyGeneratorTest extends TestCase {

    @Test
    public void testKyberGeneratorEncDec() throws InvalidKeySpecException, NoSuchAlgorithmException {
        final int numServers = 30;

        List<KyberShareholder> kyberShareholders = KyberKeyGenerator.generateKyber(numServers);

        // Encrypt a message using the combined As and pks
        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update(new byte[]{1, 2});
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
        md2.update(new byte[]{2, 3});
        byte[] coins = md2.digest();
        md2.update(new byte[]{1, 2, 3});
        byte[] coins1 = md2.digest();

        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc_no_gen_mat(m, kyberShareholders.get(0).getKyberPublicParameters().getPk(), kyberShareholders.get(0).getKyberPublicParameters().getAtCombined(), coins);

        // generate decryption shares
        List<Kyber.Polynomial> decryptionShares = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            List<Kyber.Polynomial> c1 = new ArrayList<>();
            Kyber.Polynomial c2;
            for (int j = 0; j < Kyber.KYBER_K; j++) {
                c1.add(new Kyber.Polynomial(Arrays.copyOf(kyberCiphertext.getC1().get(j).poly, kyberCiphertext.getC1().get(j).poly.length)));
            }
            c2 = new Kyber.Polynomial(Arrays.copyOf(kyberCiphertext.getC2().poly, kyberCiphertext.getC2().poly.length));

            KyberCiphertext kyberCiphertextCpy = new KyberCiphertext(c1, c2);
            decryptionShares.add(Kyber.gen_dec_share(kyberCiphertextCpy, kyberShareholders.get(i).getSecretShare(), coins1));
        }

        // combine decryption shares
        byte[] after = Kyber.combine_dec_shares(kyberCiphertext, decryptionShares);

//        List<List<Kyber.Polynomial>> spp = new ArrayList<>();
//        for(int i = 0; i < numServers; i++) {
//            spp.add(kyberShareholders.get(i).getSecretShare());
//        }
//
//        byte[] after = Kyber.indcpa_dec_n(kyberCiphertext, spp);

        assertTrue(Arrays.equals(after, m));
    }

    @Test
    public void testKyberGeneratorJsonAndBack() throws InvalidKeySpecException, NoSuchAlgorithmException {
        final int numServers = 30;

        List<KyberShareholder> kyberShareholders = KyberKeyGenerator.generateKyber(numServers);

        List<JSONObject> kyberSharehooldersJson = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            kyberSharehooldersJson.add(kyberShareholders.get(i).getJson());
        }

        List<KyberShareholder> kyberShareholdersAfter = new ArrayList<>();
        for(int i = 0; i < numServers; i++) {
            kyberShareholdersAfter.add(KyberShareholder.getParams(kyberSharehooldersJson.get(i)));
        }

        for(int i = 0; i < numServers; i++) {
            assertTrue(kyberShareholders.get(i).equals(kyberShareholdersAfter.get(i)));
        }
    }

}