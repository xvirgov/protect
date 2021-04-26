package com.ibm.pross.common.util.crypto;

import com.ibm.pross.common.util.crypto.kyber.Kyber;
import com.ibm.pross.common.util.crypto.kyber.KyberKeyPair;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import junit.framework.TestCase;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
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
            assertTrue(Arrays.equals(m.matrix.get(i).get(0).poly, mOne.matrix.get(i).get(0).poly));
        }

        // Different seed, should be different
        random.nextBytes(seed);
        Kyber.Matrix mTwo = Kyber.gen_matrix(seed, false);
        for(int i = 0; i < m.matrix.size(); i++) {
            assertFalse(Arrays.equals(m.matrix.get(i).get(0).poly, mTwo.matrix.get(i).get(0).poly));
        }
    }

    @Test
    public void testIndCpaKeyPair() {
        KyberKeyPair keyPair = Kyber.indcpa_keypair();

        assertNotNull(keyPair.getPk());
        assertNotNull(keyPair.getSk());
        assertNotNull(keyPair.getPublicSeed());
    }

}