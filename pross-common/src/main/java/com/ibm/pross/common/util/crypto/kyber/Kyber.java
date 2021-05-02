package com.ibm.pross.common.util.crypto.kyber;

import com.ibm.pross.common.util.serialization.Parse;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Kyber {

    public final static int KYBER_K = 4;
    public final static int KYBER_N = 256;
    public final static int KYBER_Q = 3329;
    final static short zetas[] = new short[]{
            -1044, -758, -359, -1517, 1493, 1422, 287, 202,
            -171, 622, 1577, 182, 962, -1202, -1474, 1468,
            573, -1325, 264, 383, -829, 1458, -1602, -130,
            -681, 1017, 732, 608, -1542, 411, -205, -1571,
            1223, 652, -552, 1015, -1293, 1491, -282, -1544,
            516, -8, -320, -666, -1618, -1162, 126, 1469,
            -853, -90, -271, 830, 107, -1421, -247, -951,
            -398, 961, -1508, -725, 448, -1065, 677, -1275,
            -1103, 430, 555, 843, -1251, 871, 1550, 105,
            422, 587, 177, -235, -291, -460, 1574, 1653,
            -246, 778, 1159, -147, -777, 1483, -602, 1119,
            -1590, 644, -872, 349, 418, 329, -156, -75,
            817, 1097, 603, 610, 1322, -1285, -1465, 384,
            -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
            -1185, -1530, -1278, 794, -1510, -854, -870, 478,
            -108, -308, 996, 991, 958, -1460, 1522, 1628
    };
    public static int KYBER_SYMBYTES = 32; /* size in bytes of hashes, and seeds */
    public static int KYBER_ETA1 = 2;
    public static int KYBER_ETA2 = 2;
    // FIPS 202
    private static int SHAKE128_RATE = 168;
    private static int SHAKE256_RATE = 136;
    private static int SHA3_256_RATE = 136;
    private static int SHA3_512_RATE = 72;
    private static int XOF_BLOCKBYTES = SHAKE128_RATE;
    private static int GEN_MATRIX_NBLOCKS = ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES);
    // NTT
    private static int QINV = -3327;

    private static int rej_uniform(short[] coeff, int polyLength, byte[] buf, int bufLength) {
         int val0, val1;

        int ctr = 0, pos = 0;

        while (ctr < polyLength && pos + 3 <= bufLength) {
            val0 = (short) (((((int)buf[pos + 0] & 0xFF)  >> 0) | (((int)buf[pos + 1] & 0xFF) << 8)) & 0xFFF);
            val1 = (short) (((((int)buf[pos + 1] & 0xFF) >> 4) | (((int)buf[pos + 2] & 0xFF) << 4)) & 0xFFF);
            pos += 3;

            if (val0 < KYBER_Q)
                coeff[ctr++] = (short) val0;
            if (ctr < polyLength && val1 < KYBER_Q)
                coeff[ctr++] = (short) val1;
        }

        return ctr;
    }

    public static Polynomial cbd2(byte[] buf) {
        short[] coeff = new short[KYBER_N];

        int t, d, a, b;
        for (int i = 0; i < KYBER_N / 8; i++) {
            t = java.nio.ByteBuffer.wrap(Arrays.copyOfRange(buf, 4*i, 4*i + 8)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
            d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;

            for (int j = 0; j < 8; j++) {
                a = (d >> (4 * j + 0)) & 0x3;
                b = (d >> (4 * j + 2)) & 0x3;
                coeff[8 * i + j] = Integer.valueOf(a - b).shortValue();
            }
        }

        return new Polynomial(coeff);
    }

    public static Polynomial poly_getnoise_eta1(final byte[] seed, int nonce) {
        byte[] buf = new byte[KYBER_ETA1 * KYBER_N / 4];

        // PRF
        SHAKEDigest xof = new SHAKEDigest(256);
        byte[] extkey = new byte[KYBER_SYMBYTES + 1];
        System.arraycopy(seed, 0, extkey, 0, KYBER_SYMBYTES);
        extkey[KYBER_SYMBYTES] = (byte) nonce;
        xof.update(extkey, 0, extkey.length);
        xof.doFinal(buf, 0, buf.length);

        return cbd2(buf);
    }
    public static Polynomial poly_getnoise_eta2(final byte[] seed, int nonce) {
        byte[] buf = new byte[KYBER_ETA2 * KYBER_N / 4];

        // PRF
        SHAKEDigest xof = new SHAKEDigest(256);
        byte[] extkey = new byte[KYBER_SYMBYTES + 1];
        System.arraycopy(seed, 0, extkey, 0, KYBER_SYMBYTES);
        extkey[KYBER_SYMBYTES] = (byte) nonce;
        xof.update(extkey, 0, extkey.length);
        xof.doFinal(buf, 0, buf.length);

        return cbd2(buf);
    }


    public static void kyber_shake128_absorb(SHAKEDigest xof, byte[] seed, byte a, byte b) {
        byte[] extseed = new byte[KYBER_SYMBYTES + 2];

        System.arraycopy(seed, 0, extseed, 0, KYBER_SYMBYTES);
        extseed[KYBER_SYMBYTES] = a;
        extseed[KYBER_SYMBYTES+1] = b;

        xof.update(extseed, 0, extseed.length);
    }

    // https://github.com/symbolicsoft/kyber-k2so/blob/cae670041c9f25bf5e6808f3662788ea8cfef468/indcpa.go#L103
    public static Matrix gen_matrix(final byte[] seed, final boolean transposed) {
        int ctr, off;
        int bufLen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
        SHAKEDigest xof = new SHAKEDigest(128);
        Matrix A;
        byte[] buf = new byte[(int) bufLen + 2];

        List<List<Polynomial>> matrix = new ArrayList<>();

        for (int i = 0; i < KYBER_K; i++) {
            List<Polynomial> r = new ArrayList<>();

            for (int j = 0; j < KYBER_K; j++) {

                xof.reset();

                if (transposed)
                    kyber_shake128_absorb(xof, seed, (byte) i, (byte) j);
                else
                    kyber_shake128_absorb(xof, seed, (byte) j, (byte) i);

                xof.doFinal(buf, 0, GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES);

                short[] poly = new short[KYBER_N];

                ctr = rej_uniform(poly, KYBER_N, buf, GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES);

                while (ctr < KYBER_N) {
                    off = bufLen % 3;

                    for (int k = 0; k < off; k++) {
                        buf[k] = buf[bufLen - off - k];
                    }

                    xof.update(buf, off, 1);
                    bufLen = off + XOF_BLOCKBYTES;

                    short[] rest = Arrays.copyOfRange(poly, ctr, KYBER_N);
                    int nctr = rej_uniform(rest, KYBER_N - ctr, buf, bufLen);
                    System.arraycopy(rest, 0, poly, ctr, KYBER_N - ctr);

                    ctr += nctr;
                }

                r.add(new Polynomial(poly));
            }
            matrix.add(r);
        }

        return new Matrix(matrix);
    }


    static short montgomery_reduce(int a) {
        short t;

        t = (short) (a * QINV);
        t = (short) ((a - t * KYBER_Q) >> 16);
        return t;
    }

    static int fqmul(int a, int b) {
        return montgomery_reduce(a * b);
    }

    static void ntt(short[] coeff) {

        int j = 0, k = 1, zeta;

        short t = 0;

        for (int len = 128; len >= 2; len >>= 1) {
            for (int start = 0; start < 256; start = j + len) {
                zeta = zetas[k++];
                for (j = start; j < start + len; j++) {
                    t = (short) fqmul(zeta, coeff[j + len]);
                    coeff[j + len] = (short) (coeff[j] - t);
                    coeff[j] = (short) (coeff[j] + t);
                }
            }
        }
    }

    static void invntt(short[] coeff) {

        int j = 0, k = 127, zeta;
        final short f = 1441;
        short t = 0;

        for(int len = 2; len <= 128; len <<= 1) {
            for(int start = 0; start < 256; start = j + len) {
                zeta = zetas[k--];
                for(j = start; j < start + len; j++) {
                    t = coeff[j];
                    coeff[j] = barret_reduce((short) (t + coeff[j + len]));
                    coeff[j + len] = (short) (coeff[j + len] - t);
                    coeff[j + len] = (short) fqmul(zeta, coeff[j + len]);
                }
            }
        }

        for(j = 0; j < 256; j++)
            coeff[j] = (short) fqmul(coeff[j], f);
    }

    static short barret_reduce(short a) {
        short t;
        final short v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

        t = (short) ((v * a + (1 << 25)) >> 26);
        t *= KYBER_Q;
        return (short) (a - t);
    }

    static void poly_reduce(Polynomial p) {
        for (int i = 0; i < KYBER_N; i++) {
            p.poly[i] = barret_reduce(p.poly[i]);
        }
    }

    public static void polyvec_reduce(List<Polynomial> p) {
        for(int i = 0; i < KYBER_K; i++) {
            poly_reduce(p.get(i));
        }
    }

    static void poly_ntt(Polynomial p) {
        ntt(p.poly);
        poly_reduce(p);
    }

    public static void polyvec_ntt(List<Polynomial> pv) {
        for (int i = 0; i < KYBER_K; i++) {
            poly_ntt(pv.get(i));
        }
    }

    static void poly_invntt_tomont(Polynomial p) {
        invntt(p.poly);
    }

    public static void polyvec_invntt_tomont(List<Polynomial> pv) {
        for(int i = 0; i < KYBER_K; i++)
            poly_invntt_tomont(pv.get(i));
    }

    static short[] basemul(short[] a, short[] b, short zeta) {
        short[] r = new short[2];

        r[0] = (short) fqmul(a[1], b[1]);
        r[0] = (short) fqmul(r[0], zeta);
        r[0] += (short) fqmul(a[0], b[0]);
        r[1] = (short) fqmul(a[0], b[1]);
        r[1] += (short) fqmul(a[1], b[0]);

        return r;
    }

    static Polynomial poly_basemul_montgomery(Polynomial a, Polynomial b) {
        short[] r = new short[KYBER_N];
        for (int i = 0; i < KYBER_N / 4; i++) {
            short[] app1 = basemul(Arrays.copyOfRange(a.poly, 4 * i, 4 * i + 2), Arrays.copyOfRange(b.poly, 4 * i, 4 * i + 2), zetas[64 + i]);
            for (int ii = 0; ii < 2; ii++)
                r[4 * i + ii] = app1[ii];
            short[] app2 = basemul(Arrays.copyOfRange(a.poly, 4 * i + 2, 4 * i + 4), Arrays.copyOfRange(b.poly, 4 * i + 2, 4 * i + 4), (short) (-1 * zetas[64 + i]));
            for (int ii = 0; ii < 2; ii++)
                r[4 * i + 2 + ii] = app2[ii];
        }

        return new Polynomial(r);
    }

    public static Polynomial poly_add(Polynomial a, Polynomial b) {
        short[] r = new short[KYBER_N];
        for (int i = 0; i < KYBER_N; i++) {
            r[i] = (short) (a.poly[i] + b.poly[i]);
        }
        return new Polynomial(r);
    }

    static Polynomial poly_sub(Polynomial a, Polynomial b) {
        short[] r = new short[KYBER_N];
        for (int i = 0; i < KYBER_N; i++) {
            r[i] = (short) (a.poly[i] - b.poly[i]);
        }
        return new Polynomial(r);
    }

    public static Polynomial polyvec_basemul_acc_montgomery(List<Polynomial> a, List<Polynomial> b) {
        Polynomial r = poly_basemul_montgomery(a.get(0), b.get(0));
        for (int i = 1; i < KYBER_K; i++) {
            Polynomial t = poly_basemul_montgomery(a.get(i), b.get(i));
            r = poly_add(r, t);
        }

        poly_reduce(r);

        return r;
    }

    public static void poly_tomont(Polynomial r) {
        final long f = ((long) 1 << 32) % KYBER_Q;
        for (int i = 0; i < KYBER_N; i++)
            r.poly[i] = (short) montgomery_reduce((int) (r.poly[i] * f));
    }

    public static List<Polynomial> polyvec_add(final List<Polynomial> a, final List<Polynomial> b) {
        List<Polynomial> r = new ArrayList<>();
        for (int i = 0; i < KYBER_K; i++)
            r.add(poly_add(a.get(i), b.get(i)));

        return r;
    }

    public static List<Polynomial> polyvec_sub(final List<Polynomial> a, final List<Polynomial> b) {
        List<Polynomial> r = new ArrayList<>();
        for (int i = 0; i < KYBER_K; i++)
            r.add(poly_sub(a.get(i), b.get(i)));

        return r;
    }

    static Polynomial poly_frommsg(byte[] m) {
        short[] p = new short[KYBER_N];
        for(int i = 0; i < KYBER_N/8; i++) {
            for(int j = 0; j < 8; j++) {
                short mask = (short) (((m[i] >> j)&1) * -1);
                p[8*i + j] = (short) (mask & ((KYBER_Q+1)/2));
            }
        }

        return new Polynomial(p);
    }

    static byte[] poly_tomsg(Polynomial a) {
        short t;
        byte[] msg = new byte[KYBER_SYMBYTES];

        for(int i = 0; i < KYBER_N/8; i++) {
            msg[i] = 0;
            for(int j = 0; j < 8; j++) {
                t = a.poly[8*i + j];
                t += (t >> 15) & KYBER_Q;
                t = (short) ((((t << 1) + KYBER_Q/2)/KYBER_Q) & 1);
                msg[i] |= t << j;
            }
        }

        return msg;
    }

    public static KyberKeyPair indcpa_keypair() {

        byte[] seed = new byte[Kyber.KYBER_SYMBYTES];

        new SecureRandom().nextBytes(seed);

        final SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
        md.update(seed);

        byte[] hashedSeed = md.digest();

        Kyber.Matrix a = Kyber.gen_matrix(hashedSeed, false);

        List<Polynomial> skpv = new ArrayList<>();
        List<Polynomial> e = new ArrayList<>();

        byte[] noiseSeed = Arrays.copyOfRange(hashedSeed, KYBER_SYMBYTES, hashedSeed.length);
        int nonce = 0;
        for (int i = 0; i < KYBER_K; i++)
            skpv.add(poly_getnoise_eta1(noiseSeed, nonce++));
        for (int i = 0; i < KYBER_K; i++)
            e.add(poly_getnoise_eta1(noiseSeed, nonce++));

        polyvec_ntt(skpv);
        polyvec_ntt(e);

        List<Polynomial> pkpv = new ArrayList<>();
        for (int i = 0; i < KYBER_K; i++) {
            pkpv.add(polyvec_basemul_acc_montgomery(a.matrix.get(i), skpv));
            poly_tomont(pkpv.get(i));
        }

        pkpv = polyvec_add(pkpv, e);
        polyvec_reduce(pkpv);

        return new KyberKeyPair(pkpv, skpv, hashedSeed);
    }

    public static KyberKeyPair indcpa_keypair_from_sk(Matrix a, List<Polynomial> skpv) {

        byte[] seed = new byte[Kyber.KYBER_SYMBYTES];

//        new SecureRandom().nextBytes(seed);

        final SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
        md.update(seed);

        byte[] hashedSeed = md.digest();

//        Kyber.Matrix a = Kyber.gen_matrix(hashedSeed, false);

//        List<Polynomial> skpv = new ArrayList<>();
        List<Polynomial> e = new ArrayList<>();

        byte[] noiseSeed = Arrays.copyOfRange(hashedSeed, KYBER_SYMBYTES, hashedSeed.length);
        int nonce = 0;
//        for (int i = 0; i < KYBER_K; i++)
//            skpv.add(poly_getnoise_eta1(noiseSeed, nonce++));
        for (int i = 0; i < KYBER_K; i++)
            e.add(poly_getnoise_eta1(noiseSeed, nonce++));

//        polyvec_ntt(skpv);
        polyvec_ntt(e);

        List<Polynomial> pkpv = new ArrayList<>();
        for (int i = 0; i < KYBER_K; i++) {
            pkpv.add(polyvec_basemul_acc_montgomery(a.matrix.get(i), skpv));
            poly_tomont(pkpv.get(i));
        }

        pkpv = polyvec_add(pkpv, e);
        polyvec_reduce(pkpv);

        return new KyberKeyPair(pkpv, skpv, hashedSeed);
    }

    /**
     * Generates a public and private key
     *
     * @return asymmetric key pair
     */
    byte[] crypto_kem_keypair() {


        return null;
    }

    public static KyberCiphertext indcpa_enc(byte[] m, List<Polynomial> pkpv, byte[] publicSeed, byte[] coins) {

        Polynomial k = poly_frommsg(m);
        Kyber.Matrix at = gen_matrix(publicSeed, true);

        List<Polynomial> sp = new ArrayList<>();
        List<Polynomial> ep = new ArrayList<>();
        int nonce = 0;

        for(int i = 0; i < KYBER_K; i++)
            sp.add(poly_getnoise_eta1(coins, nonce++));
        for(int i = 0; i < KYBER_K; i++)
            ep.add(poly_getnoise_eta2(coins, nonce++));
        Polynomial epp = poly_getnoise_eta2(coins, nonce++);

        polyvec_ntt(sp);

        // matrix-vector multiplication
        List<Polynomial> b = new ArrayList<>();
        for(int i = 0; i < KYBER_K; i++)
            b.add(polyvec_basemul_acc_montgomery(at.matrix.get(i), sp));

        Polynomial v = polyvec_basemul_acc_montgomery(pkpv, sp);

        polyvec_invntt_tomont(b);
        poly_invntt_tomont(v);

        b = polyvec_add(b, ep);
        v = poly_add(v, epp);
        v = poly_add(v, k);
        polyvec_reduce(b);
        poly_reduce(v);

        return new KyberCiphertext(b, v);
    }

    public static KyberCiphertext indcpa_enc_no_gen_mat(byte[] m, List<Polynomial> pkpv, Matrix at, byte[] coins) {

        Polynomial k = poly_frommsg(m);
//        Kyber.Matrix at = gen_matrix(publicSeed, true);

        List<Polynomial> sp = new ArrayList<>();
        List<Polynomial> ep = new ArrayList<>();
        int nonce = 0;

        for(int i = 0; i < KYBER_K; i++)
            sp.add(poly_getnoise_eta1(coins, nonce++));
        for(int i = 0; i < KYBER_K; i++)
            ep.add(poly_getnoise_eta2(coins, nonce++));
        Polynomial epp = poly_getnoise_eta2(coins, nonce++);

        polyvec_ntt(sp);

        // matrix-vector multiplication
        List<Polynomial> b = new ArrayList<>();
        for(int i = 0; i < KYBER_K; i++)
            b.add(polyvec_basemul_acc_montgomery(at.matrix.get(i), sp));

        Polynomial v = polyvec_basemul_acc_montgomery(pkpv, sp);

        polyvec_invntt_tomont(b);
        poly_invntt_tomont(v);

        b = polyvec_add(b, ep);
        v = poly_add(v, epp);
        v = poly_add(v, k);
        polyvec_reduce(b);
        poly_reduce(v);

        return new KyberCiphertext(b, v);
    }

    /**
     * Encrypts a shared secret (symmetric key)
     *
     * @return encrypted symmetric key
     * @ss: shared secret
     * @pk: public key
     */
    byte[] crypto_kem_enc(final byte[] ss, final byte[] pk) {
        return null;
    }

    public static byte[] indcpa_dec(KyberCiphertext c, List<Kyber.Polynomial> skpv) {

        List<Polynomial> b = c.getC1();
        Polynomial v = c.getC2();

        polyvec_ntt(b);
        Polynomial mp = polyvec_basemul_acc_montgomery(skpv, b);
        poly_invntt_tomont(mp);

        mp = poly_sub(v, mp);
        poly_reduce(mp);

        return poly_tomsg(mp);
    }

    public static Polynomial gen_dec_share(KyberCiphertext c, List<Polynomial> ss, byte[] coins) { // FIXME: add noise
        List<Polynomial> b = c.getC1();
//        Polynomial v = c.getC2();
        polyvec_ntt(b);

        Polynomial decShare =  polyvec_basemul_acc_montgomery(ss, b);

        int nonce = ss.size();
//        List<Polynomial> ep = new ArrayList<>();
//        for(int i = 0; i < KYBER_K; i++)
//            ep.add(poly_getnoise_eta2(coins, nonce++));
        Polynomial ep = poly_getnoise_eta2(coins, nonce++);
//        short[] pol_e = new short[KYBER_N];
//        pol_e[4] = 1;
//        Polynomial ep = new Polynomial(pol_e);


//        poly_ntt(ep);
        poly_invntt_tomont(decShare);

        decShare = poly_add(decShare, ep);
        poly_reduce(decShare);

        return decShare;
    }

//    public static List<Polynomial> gen_dec_shares(KyberCiphertext c, List<List<Polynomial>> skpv) { // FIXME: add noise
//        List<Polynomial> b = c.getC1();
//        polyvec_ntt(b);
//
//        List<Polynomial> tmps = new ArrayList<>();
//        for (List<Polynomial> polynomials : skpv) {
//            tmps.add(polyvec_basemul_acc_montgomery(polynomials, b));
//        }
//
//        return tmps;
//    }

    public static byte[] combine_dec_shares(KyberCiphertext c, List<Polynomial> decShares) {
//        List<Polynomial> b = c.getC1();
        Polynomial v = c.getC2();
//        polyvec_ntt(b);

        Polynomial mp = new Polynomial(new short[KYBER_N]);

        for(int i = 0; i < decShares.size(); i++) {
//            poly_ntt(decShares.get(i));
            mp = poly_add(mp, decShares.get(i));
            poly_reduce(mp);
        }

//        poly_invntt_tomont(mp);
        mp = poly_sub(v, mp);
        poly_reduce(mp);
        poly_reduce(v);

        return poly_tomsg(mp);
    }

    public static byte[] indcpa_dec_n(KyberCiphertext c, List<List<Polynomial>> skpv) {
        List<Polynomial> b = c.getC1();

        polyvec_ntt(b);

        List<Polynomial> tmps = new ArrayList<>();
        for (List<Polynomial> polynomials : skpv) {
            tmps.add(polyvec_basemul_acc_montgomery(polynomials, b));
        }

        Polynomial v = c.getC2();
        Polynomial mp = new Polynomial(new short[KYBER_N]);
        for(int i = 0; i < skpv.size(); i++) {
            mp = poly_add(mp, tmps.get(i));
            poly_reduce(mp);
        }

        poly_invntt_tomont(mp);

        mp = poly_sub(v, mp);
        poly_reduce(mp);

        return poly_tomsg(mp);
    }

//    public static byte[] indcpa_dec_n(KyberCiphertext c, List<List<Polynomial>> skpv) {
//
//        List<Polynomial> b = c.getC1();
//        Polynomial v = c.getC2();
//
//        polyvec_ntt(b);
////        Polynomial mp = polyvec_basemul_acc_montgomery(skpv, b);
//        Polynomial mp = new Polynomial(new short[KYBER_N]);
//
////        List<Polynomial> accuSk = new ArrayList<>();
////        for(int i = 0; i < KYBER_K;i++) {
////            accuSk.add(new Polynomial(new short[KYBER_N]));
////        }
//        for(int i = 0; i < skpv.size(); i++) {
////            accuSk = polyvec_add(accuSk, skpv.get(i));
//            Polynomial tmp = polyvec_basemul_acc_montgomery(skpv.get(i), b);
//            mp = poly_add(mp, tmp);
//            poly_reduce(mp);
//        }
////        accuSk = polyvec_add(skpv.get(0), skpv.get(1));
//
////        for(int i = 0; i < sstmp.size(); i++) {
////            for(int j = 0; j < KYBER_N; j++) {
////                if(sstmp.get(i).poly[j] != accuSk.get(i).poly[j])
////                    System.out.println("Not equal at: " + i + ", " + j + ": " + sstmp.get(i).poly[j] + " --- " + accuSk.get(i).poly[j] + " ( " + skpv.get(0).get(i).poly[j] + " + " + skpv.get(1).get(i).poly[j] + ")");
////            }
//////            if(!Arrays.equals(sstmp.get(i).poly, accuSk.get(i).poly))
//////                System.out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa");
////        }
//
////        mp = polyvec_basemul_acc_montgomery(accuSk, b);
//
//        poly_invntt_tomont(mp);
//
//        mp = poly_sub(v, mp);
//        poly_reduce(mp);
////        poly_reduce(v);
//
//        return poly_tomsg(mp);
//    }

    /**
     * Decrypts encrypted shared secret (symmetric key)
     *
     * @return decrypted symmetric key
     * @css: encrypted shared secret
     * @sk: secret key
     */
    byte[] crypto_kem_dec(final byte[] css, final byte[] sk) {
        return null;
    }

    /**
     * Data types
     */

    // byte[] - seed, hash, ciphertext, ...

    // short[] - polynomial:  coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
    public static class Polynomial {
        public short[] poly;

        public Polynomial(short[] poly) {
            this.poly = poly;
        }
    }

    // Polynomial[] - matrix:
    public static class Matrix {
        public List<List<Polynomial>> matrix;

        public Matrix(List<List<Polynomial>> matrix) {
            this.matrix = matrix;
        }
    }
}
