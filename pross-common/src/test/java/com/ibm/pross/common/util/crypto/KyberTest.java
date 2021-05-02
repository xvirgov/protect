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
    public void testMpcIter() {
        int n = 2;
        List<KyberKeyPair> keyPairs = new ArrayList<>();
        for(int i = 0; i < n; i++) {
            keyPairs.add(Kyber.indcpa_keypair());
        }

        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update(new byte[]{1,2});
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
        md2.update(new byte[]{2,3});
        byte[] coins = md2.digest();

        // Test classic
        for (int i = 0; i < n; i++) {
            KyberCiphertext kyberCiphertext = Kyber.indcpa_enc(m, keyPairs.get(i).getPk(), keyPairs.get(i).getPublicSeed(), coins);
            byte[] after = Kyber.indcpa_dec(kyberCiphertext, keyPairs.get(i).getSk());
            assertTrue(Arrays.equals(m, after));
        }

//        // Test follow
//        byte[] kyberCiphertextIter = Arrays.copyOf(m, m.length);
//        for(int i = 0; i < n; i++) {
//
//        }

    }

    @Test
    public void testMPCSum() {
        int n = 30;

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
//                Kyber.polyvec_reduce(aCombined.matrix.get(j));
                atCombined.matrix.set(j, Kyber.polyvec_add(atCombined.matrix.get(j), ats.get(i).matrix.get(j)));
//                Kyber.polyvec_reduce(atCombined.matrix.get(j));
            }
        }

        for(int i = 0; i < n; i++) {
            pk = Kyber.polyvec_add(pk, keyPairs.get(i).getPk());
//            Kyber.polyvec_reduce(pk);
            sk = Kyber.polyvec_add(sk, keyPairs.get(i).getSk());
//            Kyber.polyvec_reduce(sk);
        }

//        List<Kyber.Polynomial> pkpv = new ArrayList<>();
//        for (int i = 0; i < Kyber.KYBER_K; i++) {
//            pkpv.add(Kyber.polyvec_basemul_acc_montgomery(aCombined.matrix.get(i), sk));
//            Kyber.poly_tomont(pkpv.get(i));
////            Kyber.poly_tomont(pk.get(i));
//        }

        KyberKeyPair kyberKeyPairAfter = Kyber.indcpa_keypair_from_sk(aCombined, sk);


//        for(int i = 0; i < Kyber.KYBER_K; i++) {
//            assertTrue(Arrays.equals(pk.get(i).poly, pkpv.get(i).poly));
//        }


        // Encrypt a message using the combined As and pks
        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update(new byte[]{1,2});
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
        md2.update(new byte[]{2,3});
        byte[] coins = md2.digest();

        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc_no_gen_mat(m, kyberKeyPairAfter.getPk(), atCombined, coins);

//        List<KyberCiphertext> kyberCiphertextList = new ArrayList<>();
//        for(int i =0; i < n; i++) {
//            kyberCiphertextList.add(Kyber.indcpa_enc(m, keyPairs.get(i).getPk(), keyPairs.get(i).getPublicSeed(), coins));
//        }


//        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc(m, keyPairs.get(0).getPk(), keyPairs.get(0).getPublicSeed(), coins);

//        byte[] mAfter = new byte[Kyber.KYBER_SYMBYTES];
//        byte[] mAfterTmp = new byte[Kyber.KYBER_SYMBYTES];
//        for(int i = 0; i < n; i++) {
//            mAfterTmp = Kyber.indcpa_dec(kyberCiphertext, keyPairs.get(i).getSk());
//            for(int j = 0; j < Kyber.KYBER_SYMBYTES; j++) {
//                mAfter[j] += mAfterTmp[j];
//            }
//        }
        List<List<Kyber.Polynomial>> spp = new ArrayList<>();
        for(int i = 0; i < n; i++) {
            spp.add(keyPairs.get(i).getSk());
        }

        byte[] after = Kyber.indcpa_dec_n(kyberCiphertext, spp);
//        byte[] after = Kyber.indcpa_dec(kyberCiphertext, sk);

//        for(int i = 0; i < Kyber.KYBER_SYMBYTES; i++) {
//            System.out.println(Integer.toBinaryString(m[i] & 0xFF) + " -- " + Integer.toBinaryString(after[i] & 0xFF));
//        }

//        for(int i = 0; i < after.length; i++) {
//            System.out.println(m[i] + " --> " + after[i]);
//            if(m[i] != after[i])
//                System.out.println("-------------------------------------");
//        }

        assertTrue(Arrays.equals(after, m));
    }

    @Test
    public void testMpcFinalSum() {
        int n = 2, nonce = 1;

        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
        md1.update(new byte[]{1,2});
        byte[] m = md1.digest();

        final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
        md2.update(new byte[]{2,3});
        byte[] coins = md2.digest();

        KyberKeyPair keyPair = Kyber.indcpa_keypair();
        KyberCiphertext kyberCiphertext = Kyber.indcpa_enc(m, keyPair.getPk(), keyPair.getPublicSeed(), coins);

        // split secrtet key
        List<Kyber.Polynomial> sp1 = new ArrayList<>();
        for(int i = 0; i < Kyber.KYBER_K; i++)
            sp1.add(Kyber.poly_getnoise_eta1(coins, nonce++));

        Kyber.polyvec_ntt(sp1);

        List<Kyber.Polynomial> sp2 = Kyber.polyvec_sub(keyPair.getSk(), sp1);
//        Kyber.polyvec_reduce(sp2);

        List<Kyber.Polynomial> check = Kyber.polyvec_add(sp1, sp2);

//        for(int i = 0; i < Kyber.KYBER_K; i++) {
//            for(int j = 0; j < Kyber.KYBER_N; j++) {
//                System.out.println(keyPair.getSk().get(i).poly[j] + " - " + sp1.get(i).poly[j] + " = " + sp2.get(i).poly[j]);
//                if(check.get(i).poly[j] != keyPair.getSk().get(i).poly[j])
//                    System.out.println("-----------------> " + i + " " + j + ": " + keyPair.getSk().get(i).poly[j] + " != " + check.get(i).poly[j]);
//            }
//        }

        List<List<Kyber.Polynomial>> spp = new ArrayList<>();
        List<List<Kyber.Polynomial>> spp2 = new ArrayList<>();
        spp2.add(keyPair.getSk());
        spp.add(sp1);
        spp.add(sp2);
        byte[] after_mpc = Kyber.indcpa_dec_n(kyberCiphertext, spp);
//        byte[] after = Kyber.indcpa_dec_n(kyberCiphertext, spp2, keyPair.getSk());
//        byte[] after2 = Kyber.indcpa_dec_n(kyberCiphertext, sp2, 2);
        assertTrue(Arrays.equals(m, after_mpc));
    }

}