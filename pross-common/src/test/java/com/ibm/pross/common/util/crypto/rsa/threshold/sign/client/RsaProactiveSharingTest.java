package com.ibm.pross.common.util.crypto.rsa.threshold.sign.client;

import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.shamir.Polynomials;
import junit.framework.TestCase;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import static org.junit.Assert.assertNotEquals;

public class RsaProactiveSharingTest extends TestCase {

    private int numServers = 5;
    private int threshold = 3;
    private BigInteger r = BigInteger.valueOf(2).pow(10);
    private int tau = 80;


    @Test
    public void testRsaProactiveSharingCreation() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        assertEquals(numServers, rsaProactiveSharing.getN());
        assertEquals(threshold, rsaProactiveSharing.getT());
        assertEquals(r, rsaProactiveSharing.getR());
        assertEquals(tau, rsaProactiveSharing.getTau());
        assertEquals(numServers, rsaProactiveSharing.getShares().length);
        assertEquals(numServers, rsaProactiveSharing.getVerificationKeys().length);
        assertNotEquals(rsaProactiveSharing.getV(), BigInteger.ZERO);
    }

    @Test
    public void testPublicExponentProperties() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        // e > n
        assertTrue(rsaProactiveSharing.getPublicKey().getPublicExponent().compareTo(BigInteger.valueOf(rsaProactiveSharing.getN())) > 0);

        // gcd(e, n!) = 1
        assertEquals(BigInteger.ONE, rsaProactiveSharing.getPublicKey().getPublicExponent().gcd(Polynomials.factorial(BigInteger.valueOf(rsaProactiveSharing.getN()))));
    }

    @Test
    public void testAdditiveSharesProperties() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        // d = d_pub + sum_{i=1}^{n} d_i
        BigInteger sum = BigInteger.ZERO;
        for (SecretShare secretShare : rsaProactiveSharing.getAdditiveShares()) {
            sum = sum.add(secretShare.getY());
        }
        assertEquals(rsaProactiveSharing.getPrivateKey().getPrivateExponent(), rsaProactiveSharing.getD_pub().add(sum));
    }
}