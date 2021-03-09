package com.ibm.pross.common.util.crypto.rsa.threshold.proactive;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.Primes;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaProactiveSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.GcdTriplet;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

public class ProactiveRsaGenerator {

    private static final Logger logger = LogManager.getLogger(ProactiveRsaGenerator.class);

    // Default values
    public static final int DEFAULT_RSA_KEY_SIZE = 1024;
    public static final int DEFAULT_TAU = 80;
    public static final BigInteger DEFAULT_PARAMETER_R = BigInteger.valueOf(2).pow(10);

    public static List<ProactiveRsaShareholder> generateProactiveRsa(final int numServers, final int threshold)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return generateProactiveRsa(numServers, threshold, DEFAULT_RSA_KEY_SIZE, DEFAULT_PARAMETER_R, DEFAULT_TAU);
    }

    public static List<ProactiveRsaShareholder> generateProactiveRsa(final int numServers, final int threshold,
                                                                     final int keyBitSize, final BigInteger r,
                                                                     final int tau)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.info("Generating Proactive-RSA keys with max bit size: " + keyBitSize);
        final int primeLength = (keyBitSize / 2);

        logger.info("Generating p...");
        final BigInteger p = Primes.generateSafePrime(primeLength);
        final BigInteger pPrime = Primes.getSophieGermainPrime(p);
        logger.info("[DONE]");

        logger.info("Generating q...");
        final BigInteger q = Primes.generateSafePrime(primeLength);
        final BigInteger qPrime = Primes.getSophieGermainPrime(q);
        logger.info("[DONE]");

        logger.info("Computing moduli...");
        final BigInteger m = pPrime.multiply(qPrime);
        final BigInteger n = p.multiply(q);
        logger.info("[DONE]");

        // Public exponent (e must be greater than numServers)
        final BigInteger e = BigInteger.valueOf(65537);
        if (e.longValue() <= numServers) {
            throw new IllegalArgumentException("e must be greater than the number of servers!");
        }

        // Create standard RSA Public key pair
        logger.info("Creating RSA keypair...");
        final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

        // Create standard RSA Private key
        final BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        final BigInteger realD = Exponentiation.modInverse(e, totient);
        final RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, realD);
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        logger.info("[DONE]");

        // Range parameter R = n.(r+1).N.2^{tau + 1}
        BigInteger R = BigInteger.valueOf(numServers).multiply(r.add(BigInteger.ONE)).multiply(n).multiply(BigInteger.valueOf(2).pow(tau + 1));

        // Generate additive shares
        logger.info("Generating additive shares of private exponent...");
        List<SecretShare> additiveShares = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            additiveShares.add(new SecretShare(BigInteger.valueOf(i + 1), RandomNumberGenerator.generateRandomInteger(R.multiply(BigInteger.valueOf(2)))));
        }
        BigInteger d_pub = realD.subtract(additiveShares.stream().map(SecretShare::getY).reduce(BigInteger::add).get());
        logger.info("[DONE]");

        // Generator of verification values for additive shares - random square (of order phi(n)/4)
        final BigInteger sqrtG = RandomNumberGenerator.generateRandomInteger(n);
        final BigInteger g = sqrtG.modPow(BigInteger.valueOf(2), n);

        // Generate additive verification values g^{d_i}
        logger.info("Computing verification values for additive shares...");
        List<SecretShare> additiveVerificationKeys = new ArrayList<>();
        for (int i = 0; i < additiveShares.size(); i++) {
            additiveVerificationKeys.add(new SecretShare(BigInteger.valueOf(i + 1), g.modPow(additiveShares.get(i).getY(), n)));
        }
        logger.info("[DONE]");

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

            logger.info("Generating shamir shares and verification keys for additive share d_" + (i+1) );
            List<BigInteger> coefficients = RandomNumberGenerator.generateRandomArray(BigInteger.valueOf(threshold), coeffR);
            coefficients.set(0, additiveShares.get(i).getY().multiply(L));

            // Create shamir shares
            List<SecretShare> shamirShares = new ArrayList<>();
            for(int j = 0; j < numServers; j++) {
                shamirShares.add(Polynomials.evaluatePolynomial(coefficients, BigInteger.valueOf(j + 1), n));
            }
            shamirAdditiveShares.add(shamirShares);

            // Generate verification values
            feldmanAdditiveVerificationValues.add(Shamir.generateFeldmanValues(coefficients, g, n));

            logger.info("[DONE]");
        }

        // Pre-computed values

        logger.info("Summing shamir share for additive shares...");
        List<SecretShare> shamirAdditiveSharesSummed = new ArrayList<>();
        for(int i = 0; i < numServers; i++) {
            BigInteger accumulator = BigInteger.ZERO;
            for(int j = 0; j < numServers; j++) {
                accumulator = accumulator.add(shamirAdditiveShares.get(j).get(i).getY());
            }
            shamirAdditiveSharesSummed.add(new SecretShare(BigInteger.valueOf(i+1), accumulator));
        }
        logger.info("[DONE]");

        logger.info("Computing EEA values of gcd(L^3, e)...");
        final BigInteger lPow = L.pow(3);
        final GcdTriplet gcdTriplet = GcdTriplet.extendedGreatestCommonDivisor(lPow, e);
        final BigInteger aGcd = gcdTriplet.getX();
        final BigInteger bGcd = gcdTriplet.getY();
        logger.info("[DONE]");

        logger.info("Computing multiplied and exponentiated feldman verification values...");
        // Compute feldman verification values
        List<BigInteger> multipliedFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            BigInteger accumulator = BigInteger.ONE;
            for (int j = 0; j < numServers; j++) {
                accumulator = accumulator.multiply(feldmanAdditiveVerificationValues.get(j).get(i).getY());
            }
            multipliedFeldmanVerificationValues.add(accumulator);
        }

        List<SecretShare> agentsFeldmanVerificationValues = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            BigInteger result = BigInteger.ONE;
            for (int j = 0; j < threshold; j++) {
                result = result.multiply(multipliedFeldmanVerificationValues.get(j).modPow(BigInteger.valueOf(i + 1).pow(j), n)).mod(n);
            }
            agentsFeldmanVerificationValues.add(new SecretShare(BigInteger.valueOf(i+1), result));
        }
        logger.info("[DONE]");

        logger.info("Creating shareholders...");

        ProactiveRsaPublicParameters proactiveRsaPublicParameters = new ProactiveRsaPublicParameters.ProactiveRsaPublicParametersBuilder()
                .setPublicKey(publicKey)
                .setbAgent(agentsFeldmanVerificationValues)
                .setBigR(R)
                .setCoeffR(coeffR)
                .setD_pub(d_pub)
                .setB(feldmanAdditiveVerificationValues)
                .setG(g)
                .setL(L)
                .setNumServers(numServers)
                .setTau(tau)
                .setTauHat(tauHat)
                .setThreshold(threshold)
                .setW(additiveVerificationKeys)
                .setR(r)
                .setaGcd(aGcd)
                .setbGcd(bGcd)
                .setEpoch(0)
                .build();

        List<ProactiveRsaShareholder> proactiveRsaShareholders = new ArrayList<>();
        for(int i = 0; i < numServers; i++) {
            ProactiveRsaShareholder proactiveRsaShareholder = new ProactiveRsaShareholder.ProactiveRsaShareholderBuilder()
                    .setProactiveRsaPublicParameters(proactiveRsaPublicParameters)
                    .setD_i(additiveShares.get(i).getY())
                    .setS_i(shamirAdditiveSharesSummed.get(i).getY())
                    .setS(shamirAdditiveShares.get(i))
                    .build();

            proactiveRsaShareholders.add(proactiveRsaShareholder);
        }

        logger.info("[DONE]");

        return proactiveRsaShareholders;
    }

}
