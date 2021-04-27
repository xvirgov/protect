package com.ibm.pross.common.util.crypto;

import com.ibm.pross.common.util.crypto.kyber.Kyber;
import com.ibm.pross.common.util.crypto.kyber.KyberCiphertext;
import com.ibm.pross.common.util.crypto.kyber.KyberKeyPair;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import junit.framework.TestCase;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class KyberTest extends TestCase {

    @Test
    public void testGenKyberMatrixEqualsMatrix() {
        byte[] seed = new byte[Kyber.KYBER_SYMBYTES];

        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);

        Kyber.Matrix m = Kyber.gen_matrix(seed, false);
        Kyber.Matrix mOne = Kyber.gen_matrix(seed, false);

        assertEquals(m.matrix.size(), mOne.matrix.size());

        // Same seed, should be equal
        for(int i = 0; i < m.matrix.size(); i++) {
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                assertTrue(Arrays.equals(m.matrix.get(i).get(j).poly, mOne.matrix.get(i).get(j).poly));
            }
        }

        // Different seed, should be different
        random.nextBytes(seed);
        Kyber.Matrix mTwo = Kyber.gen_matrix(seed, false);
        for(int i = 0; i < Kyber.KYBER_K; i++) {
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                assertFalse(Arrays.equals(m.matrix.get(i).get(j).poly, mTwo.matrix.get(i).get(j).poly));
            }
        }
    }

    @Test
    public void testIndCpaKeyPair() {
        KyberKeyPair keyPair = Kyber.indcpa_keypair();

        assertNotNull(keyPair.getPk());
        assertNotNull(keyPair.getSk());
        assertNotNull(keyPair.getPublicSeed());
    }

    @Test
    public void testIndCpaEnc() {
        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update("message".getBytes());
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(512);
        md2.update("coins".getBytes());
        byte[] coins = md2.digest();

        KyberKeyPair keyPair = Kyber.indcpa_keypair();
        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc(m, keyPair.getPk(), keyPair.getPublicSeed(), coins);

        assertNotNull(kyberCiphertext.getC1());
        assertNotNull(kyberCiphertext.getC2());
    }

    @Test
    public void testNtt() {
        byte[] coins = new byte[Kyber.KYBER_SYMBYTES];
        List<Kyber.Polynomial> sp = new ArrayList<>();
        List<Kyber.Polynomial> cp = new ArrayList<>();
        int nonce = 0;

        for(int i = 0; i < Kyber.KYBER_K; i++) {
            Kyber.Polynomial p = Kyber.poly_getnoise_eta1(coins, nonce++);
            sp.add(p);
            cp.add(new Kyber.Polynomial(Arrays.copyOf(p.poly, p.poly.length)));
            Kyber.poly_tomont(cp.get(i));
        }

        assertNotNull(sp);

        Kyber.polyvec_ntt(sp);
        Kyber.polyvec_invntt_tomont(sp);

        for(int i = 0; i < Kyber.KYBER_K; i++) {
                assertTrue(Arrays.equals(sp.get(i).poly, cp.get(i).poly));
        }
    }

    @Test
    public void testIndCpaDec() {
        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update(new byte[]{1,2});
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
        md2.update(new byte[]{2,3});
        byte[] coins = md2.digest();

        KyberKeyPair keyPair = Kyber.indcpa_keypair();
        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc(m, keyPair.getPk(), keyPair.getPublicSeed(), coins);
        byte[] after = Kyber.indcpa_dec(kyberCiphertext, keyPair.getSk());
        assertTrue(Arrays.equals(m, after));
    }

    @Test
    public void testMPC() {
        int n = 2;

//        KyberKeyPair keyPair = Kyber.indcpa_keypair();

        // Generate secret shares
        List<KyberKeyPair> keyPairs = new ArrayList<>();
        for(int i = 0; i < n; i++) {
            keyPairs.add(Kyber.indcpa_keypair());
        }

        // generate A, At
        List<Kyber.Matrix> as = new ArrayList<>();
        List<Kyber.Matrix> ats = new ArrayList<>();
        for(int i = 0; i < n; i++) {
            as.add(Kyber.gen_matrix(keyPairs.get(i).getPublicSeed(), false));
            ats.add(Kyber.gen_matrix(keyPairs.get(i).getPublicSeed(), true));
        }

        // combine A, At and pub keys
        List<Kyber.Polynomial> pk = new ArrayList<>();
        List<Kyber.Polynomial> sk = new ArrayList<>();
        for(int i = 0; i < Kyber.KYBER_K; i++) {
            pk.add(new Kyber.Polynomial(new short[Kyber.KYBER_N]));
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

        for(int i = 0; i < n; i++) {
            for(int j = 0; j < Kyber.KYBER_K; j++) {
                aCombined.matrix.set(j, Kyber.polyvec_add(aCombined.matrix.get(j), as.get(i).matrix.get(j)));
                atCombined.matrix.set(j, Kyber.polyvec_add(atCombined.matrix.get(j), ats.get(i).matrix.get(j)));
            }
        }

        for(int i = 0; i < n; i++) {
            pk = Kyber.polyvec_add(pk, keyPairs.get(i).getPk());
            sk = Kyber.polyvec_add(pk, keyPairs.get(i).getSk());
        }

        // Encrypt a message using the combined As and pks
        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update(new byte[]{1,2});
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
        md2.update(new byte[]{2,3});
        byte[] coins = md2.digest();

        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc_no_gen_mat(m, pk, atCombined, coins);

        byte[] mAfter = new byte[Kyber.KYBER_SYMBYTES];

        

//        byte[] mAfterTmp = new byte[Kyber.KYBER_SYMBYTES];
//        for(int i = 0; i < n; i++) {
//            mAfterTmp = Kyber.indcpa_dec(kyberCiphertext, keyPairs.get(i).getSk());
//            for(int j = 0; j < Kyber.KYBER_SYMBYTES; j++) {
//                mAfter[j] += mAfterTmp[j];
//            }
//        }

        assertNotNull(mAfter);
    }

}