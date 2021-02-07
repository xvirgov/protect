package com.ibm.pross.common.util.crypto.rsa.threshold.sign.client;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.Primes;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaSharing {

	private static final Logger logger = LogManager.getLogger(RsaSharing.class);

	public static final int DEFAULT_RSA_KEY_SIZE = 1024;
	
	// Threshold config
	private final int n;
	private final int t;
	
	// The generated key
	private final RSAPublicKey publicKey;
	private final RSAPrivateKey privateKey;
	
	// The shamir shares of d mod totient
	private final ShamirShare[] shares;
	
	// The generator for created the verification keys
	private final BigInteger v;
	
	// V^share mod N for each shareholder
	private final BigInteger[] verificationKeys;

	public static RsaSharing generateSharing(final int n, final int t) throws InvalidKeySpecException, NoSuchAlgorithmException {
		return generateSharing(DEFAULT_RSA_KEY_SIZE, n, t);
	}
	
	public static RsaSharing generateSharing(final int keySizeBits, final int numServers, final int threshold) throws InvalidKeySpecException, NoSuchAlgorithmException {
		logger.info("Generating RSA keys with max bit size: " + keySizeBits);
		final int primeLength = (keySizeBits / 2);
		
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

		// Create secret shares of "d"
		logger.info("Generating secret shares...");
		final BigInteger d = Exponentiation.modInverse(e, m);

		// Generate random polynomial coefficients for secret sharing of d
		final BigInteger[] coefficients = RandomNumberGenerator.generateRandomArray(threshold, m);

		// Set the secret as the first coefficient
		coefficients[0] = d;

		// Evaluate the polynomial from 1 to numSevers (must not evaluate at zero!)
		final ShamirShare[] shares = new ShamirShare[numServers];
		for (int i = 0; i < numServers; i++) {
			BigInteger xCoord = BigInteger.valueOf(i + 1);
			shares[i] = Polynomials.evaluatePolynomial(coefficients, xCoord, m);
		}
		logger.info("[DONE]");

		// Generate public and private verification keys
		logger.info("Creating public and private verification keys...");

		// Generate public verification key v as a random square modulo n
		final BigInteger sqrtV = RandomNumberGenerator.generateRandomInteger(n);
		final BigInteger v = sqrtV.modPow(ThresholdSignatures.TWO, n);

		// Generate private verification keys as v^share mod n
		final BigInteger[] verificationKeys = new BigInteger[shares.length];
		for (int i = 0; i < shares.length; i++) {
			verificationKeys[i] = v.modPow(shares[i].getY(), n);
		}
		logger.info("[DONE]");

		return new RsaSharing(numServers, threshold, publicKey, privateKey, shares, v, verificationKeys);
	}
	
	public RsaSharing(int n, int t, RSAPublicKey publicKey, RSAPrivateKey privateKey, ShamirShare[] shares,
			BigInteger v, BigInteger[] verificationKeys) {
		super();
		this.n = n;
		this.t = t;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.shares = shares;
		this.v = v;
		this.verificationKeys = verificationKeys;
	}

	public int getN() {
		return n;
	}

	public int getT() {
		return t;
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	public ShamirShare[] getShares() {
		return shares;
	}

	public BigInteger getV() {
		return v;
	}

	public BigInteger[] getVerificationKeys() {
		return verificationKeys;
	}
	
	public KeyPair getKeyPair() {
		return new KeyPair(this.publicKey, this.privateKey);
	}

	@Override
	public String toString() {
		return "RsaSharing [n=" + n + ", t=" + t + ", publicKey=" + publicKey + ", privateKey=" + privateKey
				+ ", shares=" + Arrays.toString(shares) + ", v=" + v + ", verificationKeys="
				+ Arrays.toString(verificationKeys) + "]";
	}
	
	
}
