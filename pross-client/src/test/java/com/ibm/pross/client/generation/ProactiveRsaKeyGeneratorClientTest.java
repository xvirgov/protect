package com.ibm.pross.client.generation;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.Primes;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import junit.framework.TestCase;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ProactiveRsaKeyGeneratorClientTest extends TestCase {

    public static final int DEFAULT_RSA_KEY_SIZE = 1024;
    public static final int DEFAULT_TAU = 80;
    public static final BigInteger DEFAULT_PARAMETER_R = BigInteger.valueOf(2).pow(10);
    final int ITERATIONS = 10;
    final int[] lengths = new int[]{1024, 2048, 3072, 4096};
    int numServers = 5;
    int threshold = 3;
    int tau = DEFAULT_TAU;
    BigInteger r = DEFAULT_PARAMETER_R;

    @Test
    public void testProactiveRsaSafePrimesPerformance() {

        long timeGen = 0, timeVerify = 0, start, end;

        List<List<BigInteger>> times_all = new ArrayList<>();

        for (int i = 0; i < lengths.length; i++) {

            List<BigInteger> times_current = new ArrayList<>();
            for (int it = 0; it < ITERATIONS; it++) {
                start = System.nanoTime();

                final BigInteger p = Primes.generateSafePrime(lengths[i] / 2);

                end = System.nanoTime();
                times_current.add(BigInteger.valueOf(end - start));
            }

            times_all.add(times_current);
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(new File("safe-primes-res.csv")))) {
            for (int i = 0; i < lengths.length; i++) {
                bw.write(times_all.get(i).stream().map(Object::toString).collect(Collectors.joining(",")));
                bw.write("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testProactiveRsaOverallGenerationPerformance() throws NoSuchAlgorithmException, InvalidKeySpecException {

        long timeGen = 0, timeVerify = 0, start, end;

        List<List<BigInteger>> times_all = new ArrayList<>();

        for (int ii = 0; ii < lengths.length; ii++) {
            int primeLength = lengths[ii] / 2;

            final BigInteger p = Primes.generateSafePrime(primeLength);
            final BigInteger pPrime = Primes.getSophieGermainPrime(p);

            final BigInteger q = Primes.generateSafePrime(primeLength);
            final BigInteger qPrime = Primes.getSophieGermainPrime(q);

            final BigInteger m = pPrime.multiply(qPrime);
            final BigInteger n = p.multiply(q);

            final BigInteger e = BigInteger.valueOf(65537);

            List<BigInteger> times_current = new ArrayList<>();
            for (int it = 0; it < ITERATIONS; it++) {
                start = System.nanoTime();

                final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
                final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

                // Create standard RSA Private key
                final BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                final BigInteger realD = Exponentiation.modInverse(e, totient);
                final RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, realD);
                final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

                // Range parameter R = n.(r+1).N.2^{tau + 1}
                BigInteger R = BigInteger.valueOf(numServers).multiply(r.add(BigInteger.ONE)).multiply(n).multiply(BigInteger.valueOf(2).pow(tau + 1));

                // Generate additive shares
                List<SecretShare> additiveShares = new ArrayList<>();
                for (int i = 0; i < numServers; i++) {
                    additiveShares.add(new SecretShare(BigInteger.valueOf(i + 1), RandomNumberGenerator.generateRandomInteger(R.multiply(BigInteger.valueOf(2)))));
                }
                BigInteger d_pub = realD.subtract(additiveShares.stream().map(SecretShare::getY).reduce(BigInteger::add).get());
                // Generator of verification values for additive shares - random square (of order phi(n)/4)
                final BigInteger sqrtG = RandomNumberGenerator.generateRandomInteger(n);
                final BigInteger g = sqrtG.modPow(BigInteger.valueOf(2), n);

                // Generate additive verification values g^{d_i}
                List<SecretShare> additiveVerificationKeys = new ArrayList<>();
                for (int i = 0; i < additiveShares.size(); i++) {
                    additiveVerificationKeys.add(new SecretShare(BigInteger.valueOf(i + 1), g.modPow(additiveShares.get(i).getY(), n)));
                }

                // L = numServers!
                BigInteger L = Polynomials.factorial(BigInteger.valueOf(numServers));
                // tauHat = tau + 2 + log r
                int tauHat = BigInteger.valueOf(tau).add(BigInteger.valueOf(2)).add(BigInteger.valueOf(r.bitLength())).intValue();
                // coeffR = t.L^{2}.R.2^{tauHat}
                BigInteger coeffR = BigInteger.valueOf(threshold).multiply(L.pow(2)).multiply(R).multiply(BigInteger.valueOf(2).pow(tauHat));

                List<List<SecretShare>> shamirAdditiveShares = new ArrayList<>();
                List<List<SecretShare>> feldmanAdditiveVerificationValues = new ArrayList<>();

                // For each additive share d_i...
                for (int i = 0; i < numServers; i++) {

                    List<BigInteger> coefficients = RandomNumberGenerator.generateRandomArray(BigInteger.valueOf(threshold), coeffR);
                    coefficients.set(0, additiveShares.get(i).getY().multiply(L));

                    // Create shamir shares
                    List<SecretShare> shamirShares = new ArrayList<>();
                    for (int j = 0; j < numServers; j++) {
                        shamirShares.add(Polynomials.evaluatePolynomial(coefficients, BigInteger.valueOf(j + 1), n));
                    }
                    shamirAdditiveShares.add(shamirShares);

                    // Generate verification values
                    feldmanAdditiveVerificationValues.add(Shamir.generateFeldmanValues(coefficients, g, n));
                }

                end = System.nanoTime();
                times_current.add(BigInteger.valueOf(end - start));
            }

            times_all.add(times_current);
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(new File("proactive-rsa-gen-verif.csv")))) {
            for (int i = 0; i < lengths.length; i++) {
                bw.write(times_all.get(i).stream().map(Object::toString).collect(Collectors.joining(",")));
                bw.write("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testProactiveRsaOverallGenerationHeatPerformance() throws NoSuchAlgorithmException, InvalidKeySpecException {

        long timeGen = 0, timeVerify = 0, start, end;

        int minNodes = 3, maxNodes = 15;

        List<List<BigInteger>> times_all = new ArrayList<>();

//        for(int ii = 0; ii < lengths.length; ii++) {
        int primeLength = lengths[0] / 2;

        final BigInteger p = Primes.generateSafePrime(primeLength);
        final BigInteger pPrime = Primes.getSophieGermainPrime(p);

        final BigInteger q = Primes.generateSafePrime(primeLength);
        final BigInteger qPrime = Primes.getSophieGermainPrime(q);

        final BigInteger m = pPrime.multiply(qPrime);
        final BigInteger n = p.multiply(q);

        final BigInteger e = BigInteger.valueOf(65537);

//            for(int it = 0; it < ITERATIONS; it++) {

        for(int ns = minNodes; ns <= maxNodes; ns++) {

            List<BigInteger> times_current = new ArrayList<>();

            for(int tr = minNodes; tr <= ns; tr++) {

                BigInteger accu = BigInteger.ZERO;

                for(int it = 0; it < ITERATIONS; it++) {

                    start = System.nanoTime();

                    final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
                    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

                    // Create standard RSA Private key
                    final BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                    final BigInteger realD = Exponentiation.modInverse(e, totient);
                    final RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, realD);
                    final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

                    // Range parameter R = n.(r+1).N.2^{tau + 1}
                    BigInteger R = BigInteger.valueOf(ns).multiply(r.add(BigInteger.ONE)).multiply(n).multiply(BigInteger.valueOf(2).pow(tau + 1));

                    // Generate additive shares
                    List<SecretShare> additiveShares = new ArrayList<>();
                    for (int i = 0; i < ns; i++) {
                        additiveShares.add(new SecretShare(BigInteger.valueOf(i + 1), RandomNumberGenerator.generateRandomInteger(R.multiply(BigInteger.valueOf(2)))));
                    }
                    BigInteger d_pub = realD.subtract(additiveShares.stream().map(SecretShare::getY).reduce(BigInteger::add).get());
                    // Generator of verification values for additive shares - random square (of order phi(n)/4)
                    final BigInteger sqrtG = RandomNumberGenerator.generateRandomInteger(n);
                    final BigInteger g = sqrtG.modPow(BigInteger.valueOf(2), n);

                    // Generate additive verification values g^{d_i}
                    List<SecretShare> additiveVerificationKeys = new ArrayList<>();
                    for (int i = 0; i < additiveShares.size(); i++) {
                        additiveVerificationKeys.add(new SecretShare(BigInteger.valueOf(i + 1), g.modPow(additiveShares.get(i).getY(), n)));
                    }

                    // L = numServers!
                    BigInteger L = Polynomials.factorial(BigInteger.valueOf(ns));
                    // tauHat = tau + 2 + log r
                    int tauHat = BigInteger.valueOf(tau).add(BigInteger.valueOf(2)).add(BigInteger.valueOf(r.bitLength())).intValue();
                    // coeffR = t.L^{2}.R.2^{tauHat}
                    BigInteger coeffR = BigInteger.valueOf(tr).multiply(L.pow(2)).multiply(R).multiply(BigInteger.valueOf(2).pow(tauHat));

                    List<List<SecretShare>> shamirAdditiveShares = new ArrayList<>();
                    List<List<SecretShare>> feldmanAdditiveVerificationValues = new ArrayList<>();

                    // For each additive share d_i...
                    for (int i = 0; i < ns; i++) {

                        List<BigInteger> coefficients = RandomNumberGenerator.generateRandomArray(BigInteger.valueOf(tr), coeffR);
                        coefficients.set(0, additiveShares.get(i).getY().multiply(L));

                        // Create shamir shares
                        List<SecretShare> shamirShares = new ArrayList<>();
                        for (int j = 0; j < ns; j++) {
                            shamirShares.add(Polynomials.evaluatePolynomial(coefficients, BigInteger.valueOf(j + 1), n));
                        }
                        shamirAdditiveShares.add(shamirShares);

                        // Generate verification values
                        feldmanAdditiveVerificationValues.add(Shamir.generateFeldmanValues(coefficients, g, n));
                    }

                    end = System.nanoTime();


                    accu = accu.add(BigInteger.valueOf(end).subtract(BigInteger.valueOf(start)));
                }
                times_current.add(accu.divide(BigInteger.valueOf(ITERATIONS)).divide(BigInteger.valueOf(1000000)));
            }

            for(int fill = ns; fill < maxNodes; fill++) {
                times_current.add(BigInteger.ZERO);
            }

            times_all.add(times_current);
        }
//            }

//        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(new File("heat-rsa-gen.csv")))) {
            for (int i = 0; i < 13; i++) {
                bw.write(times_all.get(i).stream().map(Object::toString).collect(Collectors.joining(",")));
                bw.write("\n");
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }

    }


}