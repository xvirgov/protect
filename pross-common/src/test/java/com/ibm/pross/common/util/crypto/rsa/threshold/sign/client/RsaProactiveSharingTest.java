package com.ibm.pross.common.util.crypto.rsa.threshold.sign.client;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.Primes;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.GcdTriplet;
import com.ibm.pross.common.util.shamir.Polynomials;
import junit.framework.TestCase;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertNotEquals;

public class RsaProactiveSharingTest extends TestCase {

    private final int numServers = 5;
    private final int threshold = 3;
    private final BigInteger r = BigInteger.valueOf(2).pow(10);
    private final int tau = 80;


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

        // n = (2p'+1) . (2q'+1)
        BigInteger p = rsaProactiveSharing.getpPrime().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(1));
        BigInteger q = rsaProactiveSharing.getqPrime().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(1));
        assertEquals(rsaProactiveSharing.getPublicKey().getModulus(), p.multiply(q));
    }

    @Test
    public void testRsaKeyProperties() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        // e.d = 1 (mod phi(n))
        BigInteger p = rsaProactiveSharing.getpPrime().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(1));
        BigInteger q = rsaProactiveSharing.getqPrime().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(1));
        BigInteger totient = p.subtract(BigInteger.valueOf(1)).multiply(q.subtract(BigInteger.valueOf(1)));
        assertEquals(BigInteger.ONE, rsaProactiveSharing.getPublicKey().getPublicExponent()
                .multiply(rsaProactiveSharing.getPrivateKey().getPrivateExponent())
                .mod(totient));
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

        // g^{pPrime.qPrime} = 1 (mod n)
        assertNotEquals(BigInteger.ONE, rsaProactiveSharing.getG());
        BigInteger m = rsaProactiveSharing.getpPrime().multiply(rsaProactiveSharing.getqPrime());
        assertEquals(BigInteger.ONE, rsaProactiveSharing.getG().modPow(m, rsaProactiveSharing.getPublicKey().getModulus()));

        List<SecretShare> additiveShares = rsaProactiveSharing.getAdditiveShares();
        List<SecretShare> additiveVerificationKeys = rsaProactiveSharing.getAdditiveVerificationKeys();

        assertEquals(numServers, additiveShares.size());
        assertEquals(numServers, additiveVerificationKeys.size());

        // g^{d_i} = w_i
        for (int i = 0; i < additiveVerificationKeys.size(); i++) {
            BigInteger calculatedVerification = rsaProactiveSharing.getG().modPow(additiveShares.get(i).getY(), rsaProactiveSharing.getPublicKey().getModulus());
            assertEquals(calculatedVerification, additiveVerificationKeys.get(i).getY());
        }
    }

    @Test
    public void testFeldmanSharingReconstruction() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        List<List<SecretShare>> shamirAdditiveShares = rsaProactiveSharing.getShamirAdditiveShares();
        List<List<SecretShare>> feldmanAdditiveVerificationValues = rsaProactiveSharing.getFeldmanAdditiveVerificationValues();

        // Check sizes
        assertEquals(numServers, shamirAdditiveShares.size());
        assertEquals(numServers, feldmanAdditiveVerificationValues.size());

        for (int i = 0; i < numServers; i++) {
            assertEquals(numServers, shamirAdditiveShares.get(0).size());
            assertEquals(threshold, feldmanAdditiveVerificationValues.get(0).size());
        }

        BigInteger L = Polynomials.factorial(BigInteger.valueOf(numServers));

        // Random prime larger than the shared secret -> Ls
        BigInteger randPrime = Primes.generatePrime(rsaProactiveSharing.getBigR().multiply(L).bitLength() + 1);

        // For each additive share...
        List<SecretShare> additiveShares = rsaProactiveSharing.getAdditiveShares();
        for (int i = 0; i < numServers; i++) {
            List<SecretShare> shamirShares = shamirAdditiveShares.get(i);
            Collections.shuffle(shamirShares);

            // Interpolate at different points, secret matches for position 0 only
            for (int j = 0; j < numServers; j++) {
                BigInteger result = Polynomials.interpolateComplete(shamirShares, threshold, j, randPrime);
                if (j == 0) {
                    assertEquals(additiveShares.get(i).getY(), result.divide(L));
                } else {
                    assertNotEquals(additiveShares.get(i).getY(), result.divide(L));
                }
            }
        }
    }

    @Test
    public void testFeldmanSharingVerificationValues() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        List<List<SecretShare>> shamirAdditiveShares = rsaProactiveSharing.getShamirAdditiveShares();
        List<List<SecretShare>> feldmanAdditiveVerificationValues = rsaProactiveSharing.getFeldmanAdditiveVerificationValues();

        // Check sizes
        assertEquals(numServers, shamirAdditiveShares.size());
        assertEquals(numServers, feldmanAdditiveVerificationValues.size());

        for (int i = 0; i < numServers; i++) {
            assertEquals(numServers, shamirAdditiveShares.get(0).size());
            assertEquals(threshold, feldmanAdditiveVerificationValues.get(0).size());
        }

        // For each additive share...
        for (int i = 0; i < numServers; i++) {
            List<SecretShare> feldmanValues = rsaProactiveSharing.getFeldmanAdditiveVerificationValues().get(i);
            List<SecretShare> shamirShares = rsaProactiveSharing.getShamirAdditiveShares().get(i);
            BigInteger generator = rsaProactiveSharing.getG();
            BigInteger modulus = rsaProactiveSharing.getPublicKey().getModulus();

            // For each polynomial share of additive share...
            for (int j = 0; j < numServers; j++) {
                SecretShare share = shamirShares.get(j);

                // expect = g^{s_{i}}
                BigInteger expect = generator.modPow(share.getY(), modulus);

                // result = prod_{k=0}^{t} (b_{k})^{i^{k}}
                BigInteger result = BigInteger.ONE;
                for (int k = 0; k < threshold; k++) {
                    BigInteger part = feldmanValues.get(k).getY().modPow(share.getX().pow(k), modulus);
                    result = result.multiply(part).mod(modulus);
                }

                assertEquals(expect, result);
            }
        }
    }

    @Test
    public void testEncDecProactiveRsa() throws InvalidKeySpecException, NoSuchAlgorithmException, BadArgumentException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        // Enc/Dec parameters
        BigInteger publicExponent = rsaProactiveSharing.getPublicKey().getPublicExponent();
        BigInteger modulus = rsaProactiveSharing.getPublicKey().getModulus();
        BigInteger d_pub = rsaProactiveSharing.getD_pub();
        BigInteger L = Polynomials.factorial(BigInteger.valueOf(numServers));

        // Plaintext
        BigInteger plaintext = BigInteger.valueOf(420);

        // Encryption
        BigInteger ciphertext = plaintext.modPow(publicExponent, modulus);

        // Compute private key shares
        List<BigInteger> privateKeyShares = new ArrayList<>();
        List<List<SecretShare>> shamirAdditiveShares = rsaProactiveSharing.getShamirAdditiveShares();
        for (int i = 0; i < numServers; i++) {
            BigInteger accumulator = BigInteger.ZERO;
            for (int j = 0; j < numServers; j++) {
                accumulator = accumulator.add(shamirAdditiveShares.get(j).get(i).getY());
            }
            privateKeyShares.add(accumulator);

            assertNotEquals(BigInteger.ZERO, accumulator);
        }

        // Compute partial decryption shares
        List<SecretShare> partialDecryptions = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            BigInteger partialDecryption = ciphertext.modPow(L.multiply(privateKeyShares.get(i)), modulus);
            partialDecryptions.add(new SecretShare(BigInteger.valueOf(i + 1), partialDecryption));

            assertNotEquals(BigInteger.ZERO, partialDecryption);
        }

        Collections.shuffle(partialDecryptions);

        // Determine coordinates for decryption
        List<BigInteger> xCoords = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            xCoords.add(partialDecryptions.get(i).getX());
        }

        // Interpolate partial decryptions
        BigInteger preFactor = ciphertext.modPow(L.pow(3).multiply(d_pub), modulus);
        BigInteger gamma = BigInteger.ONE;
        for (int i = 0; i < threshold; i++) {
            final BigInteger decryptionShareCurrentIndex = partialDecryptions.get(i).getX();
            final BigInteger decryptionShareValue = partialDecryptions.get(i).getY();
            final BigInteger lambda_0j = Polynomials.interpolateNoModulus(xCoords, L, BigInteger.ZERO, decryptionShareCurrentIndex);
            gamma = gamma.multiply(decryptionShareValue.modPow(lambda_0j, modulus));
        }
        gamma = preFactor.multiply(gamma).mod(modulus);

        System.out.println("Gamma");
        System.out.println(gamma);
        System.out.println("Check");
        System.out.println(ciphertext.modPow(L.pow(3).multiply(rsaProactiveSharing.getPrivateKey().getPrivateExponent()), modulus));

        // gamma = c^{L^{3}.d}
        assertEquals(ciphertext.modPow(L.pow(3).multiply(rsaProactiveSharing.getPrivateKey().getPrivateExponent()), modulus), gamma);

        // Use EEA to compute plaintext
        final BigInteger lPow = L.pow(3);
        final GcdTriplet gcdTriplet = GcdTriplet.extendedGreatestCommonDivisor(lPow, publicExponent);
        final BigInteger a = gcdTriplet.getX();
        final BigInteger b = gcdTriplet.getY();

        BigInteger recovered = gamma.modPow(a, modulus).multiply(ciphertext.modPow(b, modulus)).mod(modulus);

        // gcd(L^3, e) = 1
        assertEquals(BigInteger.ONE, gcdTriplet.getG());

        // Plaintext is same as recovered plaintext
        assertEquals(plaintext, recovered);
    }

    @Test
    public void testProactiveUpdate() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RsaProactiveSharing rsaProactiveSharing = RsaProactiveSharing.generateSharing(numServers, threshold, r, tau);

        // Original secret
        final BigInteger original_d = rsaProactiveSharing.getPrivateKey().getPrivateExponent();
        final BigInteger original_d_pub = rsaProactiveSharing.getD_pub();
        final List<SecretShare> originalAdditiveShares = rsaProactiveSharing.getAdditiveShares();

        // Constant parameters
        final BigInteger modulus = rsaProactiveSharing.getPublicKey().getModulus();
        final int tau = rsaProactiveSharing.getTau();

        /* Check that the sum of all original additive shares and public remainder equals to the secret exponent */
        BigInteger sum = BigInteger.ZERO;
        for (SecretShare secretShare : originalAdditiveShares) {
            sum = sum.add(secretShare.getY());
        }
        assertEquals(original_d, original_d_pub.add(sum));

        /* Refresh additive shares **/
        BigInteger rPrime = rsaProactiveSharing.getBigR().divide(BigInteger.valueOf(numServers));
        assertEquals(rPrime, (r.add(BigInteger.ONE)).multiply(modulus).multiply(BigInteger.valueOf(2).pow(tau + 1)));

        List<List<SecretShare>> additiveSharesOfAdditiveShares = new ArrayList<>(); // sent privately
        List<SecretShare> publicRemainders = new ArrayList<>(); // broadcasted to everyone

        /* Each agent A_i splits the additive secret share */
        for (int i = 0; i < numServers; i++) {

            List<SecretShare> additiveSharesOfAdditiveShare = new ArrayList<>();
            for (int j = 0; j < numServers; j++) {
                additiveSharesOfAdditiveShare.add(new SecretShare(BigInteger.valueOf(j + 1), RandomNumberGenerator.generateRandomInteger(rPrime.multiply(BigInteger.valueOf(2)))));
            }
            BigInteger d_i_pub = originalAdditiveShares.get(i).getY().subtract(additiveSharesOfAdditiveShare.stream().map(SecretShare::getY).reduce(BigInteger::add).get());

            additiveSharesOfAdditiveShares.add(additiveSharesOfAdditiveShare);
            publicRemainders.add(new SecretShare(BigInteger.valueOf(i + 1), d_i_pub));
        }

        /* Compute new d_pub (same for all agents) */
        BigInteger new_d_pub = original_d_pub.add(publicRemainders.stream().map(SecretShare::getY).reduce(BigInteger::add).get());

        List<SecretShare> newAdditiveShares = new ArrayList<>();
        /* Each agent A_j sums all received additive shares of original additive shares */
        for (int i = 0; i < numServers; i++) {
            BigInteger accumulator = BigInteger.ZERO;
            for (int j = 0; j < numServers; j++) {
                accumulator = accumulator.add(additiveSharesOfAdditiveShares.get(j).get(i).getY());
            }
            newAdditiveShares.add(new SecretShare(BigInteger.valueOf(i + 1), accumulator));
        }

        /* Check that new additive shares are not equal to old additive share (only with negligible probability) */
        assertNotEquals(original_d_pub, new_d_pub);
        for (int i = 0; i < numServers; i++) {
            assertNotEquals(originalAdditiveShares.get(i).getY(), newAdditiveShares.get(i).getY());
        }

        /* Check that the sum of all refreshed additive shares and new public remainder equals to the secret exponent */
        BigInteger new_d = new_d_pub.add(newAdditiveShares.stream().map(SecretShare::getY).reduce(BigInteger::add).get());
        assertEquals(original_d, new_d);
    }
}