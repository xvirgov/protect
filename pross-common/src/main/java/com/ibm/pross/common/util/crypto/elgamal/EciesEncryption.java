/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.elgamal;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.kdf.EntropyExtractor;
import com.ibm.pross.common.util.crypto.kdf.HmacKeyDerivationFunction;
import com.ibm.pross.common.util.serialization.Parse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Implements public key cryptography based on elliptic curves
 * 
 * Implements the "ECIES" algorithm:
 * https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
 * 
 * Which is based loosely on ElGamal encryption. It uses AES-GCM for encryption
 * and HMAC-SHA256 for message authentication.
 */
public class EciesEncryption {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static EcPoint G = CommonConfiguration.g;

	final public static String ALGORITHM = "ECIES";
	final public static byte[] ECIES = ALGORITHM.getBytes(StandardCharsets.UTF_8);

	final public static String HMAC_ALG = "HMACSHA256";
	final public static byte[] HMAC = HMAC_ALG.getBytes(StandardCharsets.UTF_8);
	final public static int HMAC_KEY_LEN = 32;

	private static final Logger logger = LogManager.getLogger(EciesEncryption.class);

	public static byte[] encrypt(final byte[] plaintext, final EcPoint recipientPublicKey) {
		long start, end;

		// Generate r (we save this as it is needed for rebuttals
		start = System.nanoTime();
		final BigInteger r = generateR();
		end = System.nanoTime();
		logger.info("PerfMeas:EciesEncGenRand:" + (end - start));

		// Encrypt the content
		byte[] encryptedBytes = encrypt(plaintext, r, recipientPublicKey);

		return encryptedBytes;
	}
	
	public static byte[] encrypt(final byte[] plaintext, final PublicKey recipientPublicKey) {

		// Generate r (we save this as it is needed for rebuttals
		final BigInteger r = generateR();

		// Encrypt the content
		byte[] encryptedBytes = encrypt(plaintext, r, recipientPublicKey);

		return encryptedBytes;
	}

	public static byte[] decryptPayload(final byte[] ciphertext, final PrivateKey recipientPrivateKey)
			throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException {

		// Decrypt the content
		final byte[] plaintext = decrypt(ciphertext, recipientPrivateKey);

		return plaintext;
	}



	public static BigInteger generateR() {
		return RandomNumberGenerator.generateRandomPositiveInteger(curve.getR());
	}

	protected static byte[] encrypt(final byte[] message, final BigInteger r, final PublicKey publicKey) {
		if (publicKey instanceof ECPublicKey) {
			final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
			final ECPoint javaPoint = ecPublicKey.getW();
			final EcPoint point = new EcPoint(javaPoint.getAffineX(), javaPoint.getAffineY());
			return encrypt(message, r, point);
		} else {
			throw new IllegalArgumentException("Key type must be ECPublicKey!");
		}
	}

	protected static byte[] decrypt(final byte[] ciphertext, final PrivateKey privateKey)
			throws BadPaddingException, IllegalBlockSizeException {
		if (privateKey instanceof ECPrivateKey) {
			final ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
			final BigInteger privateKeyInt = ecPrivateKey.getS();
			return decrypt(ciphertext, privateKeyInt);
		} else {
			throw new IllegalArgumentException("Key type must be ECPublicKey!");
		}
	}

	protected static byte[] decrypt(final byte[] ciphertext, final BigInteger r, PublicKey publicKey)
			throws BadPaddingException, IllegalBlockSizeException {
		if (publicKey instanceof ECPublicKey) {
			final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
			final ECPoint javaPoint = ecPublicKey.getW();
			final EcPoint point = new EcPoint(javaPoint.getAffineX(), javaPoint.getAffineY());
			return decrypt(ciphertext, r, point);
		} else {
			throw new IllegalArgumentException("Key type must be ECPublicKey!");
		}
	}

	protected static byte[] encrypt(final byte[] message, final BigInteger r, final EcPoint publicKey) {

		long start, end;
		try {

			start = System.nanoTime();
			// Calculate R (our DH public value)
			final EcPoint R = curve.multiply(G, r);
			end = System.nanoTime();
			logger.info("PerfMeas:EciesEncPubCompute:" + (end - start));

			start = System.nanoTime();
			// Calculate shared secret
			final EcPoint sharedSecret = curve.multiply(publicKey, r);
			end = System.nanoTime();
			logger.info("PerfMeas:EciesEncSharedSecretCompute:" + (end - start));
			
			// Setup key generator
			start = System.nanoTime();
			final HmacKeyDerivationFunction kdf = EntropyExtractor.getKeyGenerator(ECIES, sharedSecret);

			// Get cipher
			final Cipher aesGcmCipher = EntropyExtractor.getCipher(kdf, Cipher.ENCRYPT_MODE);

			// Get hmac
			final byte[] hmacKey = kdf.createKey(HMAC, HMAC_KEY_LEN);
			final Mac hmac = Mac.getInstance(HMAC_ALG);
			hmac.init(new SecretKeySpec(hmacKey, HMAC_ALG));
			end = System.nanoTime();
			logger.info("PerfMeas:EciesEncKdf:" + (end - start));

			// We have all the keys, perform encryption and mac the cipher text
			start = System.nanoTime();
			final byte[] messageCiphertext = aesGcmCipher.doFinal(message);
			end = System.nanoTime();
			logger.info("PerfMeas:EciesEncSymmCompute:" + (end - start));

			start = System.nanoTime();
			final byte[] mac = hmac.doFinal(messageCiphertext);
			end = System.nanoTime();
			logger.info("PerfMeas:EciesEncMacCompute:" + (end - start));

			// Serialize the public value
			byte[] publicValue = Parse.concatenate(R.getX(), R.getY());

			// Combine all the parts and return
			return Parse.concatenate(publicValue, messageCiphertext, mac);

		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Extract the public value from the ciphertext
	 * 
	 * @param ciphertext
	 * @return
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static EcPoint getPublicValue(final byte[] ciphertext) throws BadPaddingException {

		// Deserialize components of the ciphertext
		final byte[][] combined = Parse.splitArrays(ciphertext);
		if (combined.length != 3) {
			throw new BadPaddingException("Invalid ciphertext");
		}
		final byte[] publicValue = combined[0];
		final byte[][] coordinates = Parse.splitArrays(publicValue);
		if (coordinates.length != 2) {
			throw new BadPaddingException("Invalid public value");
		}
		final BigInteger xCoord = new BigInteger(coordinates[0]);
		final BigInteger yCoord = new BigInteger(coordinates[1]);

		// Recover R (the sender's DH public value)
		final EcPoint R = new EcPoint(xCoord, yCoord);

		return R;
	}

	public static byte[] decrypt(final byte[] ciphertext, final BigInteger privateKey)
			throws BadPaddingException, IllegalBlockSizeException {

		// Deserialize components of the ciphertext
		final byte[][] combined = Parse.splitArrays(ciphertext);
		if (combined.length != 3) {
			throw new BadPaddingException("Invalid ciphertext");
		}
		final byte[] publicValue = combined[0];
		final byte[][] coordinates = Parse.splitArrays(publicValue);
		if (coordinates.length != 2) {
			throw new BadPaddingException("Invalid public value");
		}
		final BigInteger xCoord = new BigInteger(coordinates[0]);
		final BigInteger yCoord = new BigInteger(coordinates[1]);

		// Recover R (the sender's DH public value)
		final EcPoint R = new EcPoint(xCoord, yCoord);

		// Calculate shared secret
		final EcPoint sharedSecret = curve.multiply(R, privateKey);

		return decrypt(ciphertext, sharedSecret);
	}

	public static byte[] decrypt(final byte[] ciphertext, final EcPoint sharedSecret)
			throws BadPaddingException, IllegalBlockSizeException {
		long start, end;

		// Deserialize components of the ciphertext
		final byte[][] combined = Parse.splitArrays(ciphertext);
		if (combined.length != 3) {
			throw new BadPaddingException("Invalid ciphertext");
		}
		final byte[] messageCiphertext = combined[1];
		final byte[] macValue = combined[2];

		// Setup key generator
		start = System.nanoTime();
		final HmacKeyDerivationFunction kdf = EntropyExtractor.getKeyGenerator(ECIES, sharedSecret);

		// Get cipher
		final Cipher aesGcmCipher = EntropyExtractor.getCipher(kdf, Cipher.DECRYPT_MODE);

		// Get hmac
		final byte[] hmacKey = kdf.createKey(HMAC, HMAC_KEY_LEN);
		end = System.nanoTime();

		logger.info("PerfMeas:EciesDecCombineKdf:" + (end - start));

		start = System.nanoTime();
		try {
			final Mac hmac = Mac.getInstance(HMAC_ALG);
			hmac.init(new SecretKeySpec(hmacKey, HMAC_ALG));

			// Verify the hmac value before proceeding
			final byte[] mac = hmac.doFinal(messageCiphertext);
			if (!MessageDigest.isEqual(macValue, mac)) {
				throw new BadPaddingException("Invalid HMAC!");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
		end = System.nanoTime();
		logger.info("PerfMeas:EciesDecCombineMac:" + (end - start));

		// Pperform decryption
		start = System.nanoTime();
		byte[] plain = aesGcmCipher.doFinal(messageCiphertext);
		end = System.nanoTime();
		logger.info("PerfMeas:EciesDecCombineDecrypt:" + (end - start));
		return plain;
	}

	protected static byte[] decrypt(final byte[] ciphertext, final BigInteger r, final EcPoint publicKey)
			throws BadPaddingException, IllegalBlockSizeException {

		// Deserialize components of the ciphertext
		final byte[][] combined = Parse.splitArrays(ciphertext);
		if (combined.length != 3) {
			throw new BadPaddingException("Invalid ciphertext");
		}
		final byte[] publicValue = combined[0];
		final byte[] messageCiphertext = combined[1];
		final byte[] macValue = combined[2];
		final byte[][] coordinates = Parse.splitArrays(publicValue);
		if (coordinates.length != 2) {
			throw new BadPaddingException("Invalid public value");
		}
		final BigInteger xCoord = new BigInteger(coordinates[0]);
		final BigInteger yCoord = new BigInteger(coordinates[1]);

		// Recover R (the sender's DH public value)
		final EcPoint R = new EcPoint(xCoord, yCoord);

		// Begin performing checks

		// Ensure that the provided public value is correct for the given r
		final EcPoint recomputedR = curve.multiply(G, r);
		if (!R.equals(recomputedR)) {
			throw new IllegalArgumentException("R value is incorrect");
		}

		// Calculate shared secret based on the private r value
		final EcPoint sharedSecret = curve.multiply(publicKey, r);

		// Setup key generator
		final HmacKeyDerivationFunction kdf = EntropyExtractor.getKeyGenerator(ECIES, sharedSecret);

		// Get cipher
		final Cipher aesGcmCipher = EntropyExtractor.getCipher(kdf, Cipher.DECRYPT_MODE);

		// Get hmac
		final byte[] hmacKey = kdf.createKey(HMAC, HMAC_KEY_LEN);
		try {
			final Mac hmac = Mac.getInstance(HMAC_ALG);
			hmac.init(new SecretKeySpec(hmacKey, HMAC_ALG));

			// Verify the hmac value before proceeding
			final byte[] mac = hmac.doFinal(messageCiphertext);
			if (!MessageDigest.isEqual(macValue, mac)) {
				throw new BadPaddingException("Invalid HMAC!");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}

		// Pperform decryption
		return aesGcmCipher.doFinal(messageCiphertext);
	}

}
