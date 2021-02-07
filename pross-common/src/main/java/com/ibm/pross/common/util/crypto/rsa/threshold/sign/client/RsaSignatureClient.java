package com.ibm.pross.common.util.crypto.rsa.threshold.sign.client;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.rsa.RsaUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.SecretRecoveryException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.UserNotFoundException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaSignatureServer;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Recovers an RSA signature via interaction with at least a threshold number of
 * well-behaved servers.
 * 
 * Improperly behaving servers are detected through a verification process and
 * are excluded from the operation. This recovery operation can be used to
 * reliably store small amounts of data that is highly sensitive and highly
 * valuable, necessitating strong confidentiality and long-term availability
 * properties.
 */
public class RsaSignatureClient {

	private static final Logger logger = LogManager.getLogger(RsaSignatureClient.class);

	private final RsaSignatureServer[] servers;
	private final int threshold;

	public RsaSignatureClient(RsaSignatureServer[] servers, int threshold) {
		this.servers = servers;
		this.threshold = threshold;
	}

	public BigInteger recoverSignature(final String keyName, final byte[] toBeSigned) throws BelowThresholdException, BadArgumentException, SecretRecoveryException, NoSuchAlgorithmException {

		// Use a quorum to establish the consistent configuration across servers
		final ServerPublicConfiguration mostCommonConfig = RsaSignatureClient.getConsistentConfiguration(keyName, this.servers,
				this.threshold);

		// Generate blinded version of the password
		logger.info("  Computing a blinded password...");
		BigInteger n = mostCommonConfig.getN();
		BigInteger e = mostCommonConfig.getE();
		BigInteger r = RandomNumberGenerator.generateRandomInteger(n);
		BigInteger b = r.modPow(e, n);
		
		// Process to message to be signed by hashing
		final byte[] hashed = MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM).digest(toBeSigned);
		BigInteger numToBeSigned = (new BigInteger(1, hashed)).mod(n);
		
		// Blind the input to be signed
		BigInteger blindedToBeSigned = numToBeSigned.multiply(b).mod(n);
		logger.info(" done.");

		// Send signing request to the servers
		logger.info("  Requesting signature shares of blinded password...");
		Set<SignatureResponse> signatureTriplets = new HashSet<>();
		int serverIndex = 0;
		for (RsaSignatureServer server : servers) {
			serverIndex++;
			try {
				signatureTriplets.add(server.computeSignatureShare(keyName, blindedToBeSigned));
			} catch (BadArgumentException | UserNotFoundException e1) {
				logger.error("    Failed to get result from server[" + serverIndex + "], error = " + e1.getMessage());
			}
		}
		logger.info(" done. Collected " + signatureTriplets.size() + " unique signature shares");

		logger.info("  Verifying signature shares...");
		
		// Validate each share and remove it if it doesn't pass verification
		List<SignatureResponse> validatedSignatureTriplets = new ArrayList<>();
		for (SignatureResponse signatureTriplet : signatureTriplets) {

			BigInteger index = signatureTriplet.getServerIndex();

			try {
				if (ThresholdSignatures.validateSignatureResponse(blindedToBeSigned, signatureTriplet, mostCommonConfig)) {
					validatedSignatureTriplets.add(signatureTriplet);
				} else {
					logger.info(
							"    Signture share at index " + index + " failed validation, excluding from operation");
				}
			} catch (BadArgumentException e1) {
				logger.info(
						"    Signture share at index " + index + " failed validation, excluding from operation, error = " + e1.getMessage());
			}
		}

		logger.info("  Recovered " + validatedSignatureTriplets.size() + " verified signature shares");

		if (validatedSignatureTriplets.size() < this.threshold) {
			throw new BelowThresholdException("Insufficient valid signature shares to recover (below threshold)");
		}

		// Combine shares
		logger.info("  Recovering signature from shares...");
		BigInteger blindedSignature = ThresholdSignatures.recoverSignature(blindedToBeSigned, validatedSignatureTriplets,
				mostCommonConfig);
		logger.info(" done.");

		// Verify signature is correct for what was passed
		logger.info("  Verifying signature...");
		BigInteger signed = RsaUtil.rsaVerify(blindedSignature, e, n);
		if (!signed.equals(blindedToBeSigned)) {
			throw new SecretRecoveryException("Signature was improperly computed");
		}
		logger.info(" done.");

		// Unblind the signature
		logger.info("  Unblinding signature...");
		BigInteger unblindingFactor = Exponentiation.modInverse(r, n);
		BigInteger signatureOfPassword = blindedSignature.multiply(unblindingFactor).mod(n);
		logger.info(" done.");

		return signatureOfPassword;
	}

	public static ServerPublicConfiguration getConsistentConfiguration(final String username, final RsaSignatureServer[] servers,
			int threshold) throws BelowThresholdException {

		logger.info("  Accessing configuration information from servers...");
		// Begin with by requesting configuration from all servers
		final Map<ServerPublicConfiguration, Integer> serverConfigs = new HashMap<>();
		for (RsaSignatureServer server : servers) {
			try {
				ServerPublicConfiguration config = server.getPublicConfiguration(username);
				if (!serverConfigs.containsKey(config)) {
					serverConfigs.put(config, 1);
				} else {
					Integer currentCount = serverConfigs.get(config);
					serverConfigs.put(config, new Integer(currentCount + 1));
				}
			} catch (Exception e) {
				logger.info("  Failed to recover from one server..");
			}
		}
		logger.info(" done.");

		// Determine which view is the most consistent
		ServerPublicConfiguration mostCommonConfig = null;
		int maxConsistencies = 0;
		for (Entry<ServerPublicConfiguration, Integer> entry : serverConfigs.entrySet()) {
			if (entry.getValue() > maxConsistencies) {
				maxConsistencies = entry.getValue();
				mostCommonConfig = entry.getKey();
			}
		}
		logger.info("  Found configuration shared by " + maxConsistencies + " servers");

		if (maxConsistencies < threshold) {
			throw new BelowThresholdException("Insufficient consistency to permit recovery (below threshold)");
		}

		return mostCommonConfig;
	}

}
