package com.ibm.pross.server.app.http.handlers;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.kyber.Kyber;
import com.ibm.pross.common.util.crypto.kyber.KyberCiphertext;
import com.ibm.pross.common.util.crypto.kyber.KyberShareholder;
import com.ibm.pross.common.util.crypto.kyber.KyberUtils;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaProactiveSharing;
import com.ibm.pross.common.util.shamir.Polynomials;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaShareConfiguration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.avpss.ApvssShareholder.SharingType;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;
import org.json.simple.parser.JSONParser;

/**
 * This handler performs an exponentiation using a share of a secret. Client's
 * must have a specific authorization to be able to invoke this method. If the
 * secret is not found a 404 is returned. If the client is not authorized a 403
 * is returned.
 */
@SuppressWarnings("restriction")
public class SignHandler extends AuthenticatedClientRequestHandler {

	private static final Logger logger = LogManager.getLogger(SignHandler.class);

	public static final Permissions REQUEST_PERMISSION = Permissions.SIGN;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String MESSAGE_FIELD = "message";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public SignHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException {

		logger.debug("Performing partial signature/decryption...");

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
		final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
		if (secretName == null) {
			throw new BadRequestException();
		}

		// Perform authentication
		accessEnforcement.enforceAccess(username, secretName, REQUEST_PERMISSION);

		// Ensure shareholder exists
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}
		// Make sure secret is not disabled
		if (!shareholder.isEnabled()) {
			throw new ResourceUnavailableException();
		}

		// Ensure the secret is of the supported type
		if (!SharingType.RSA_STORED.equals(shareholder.getSharingType()) && !SharingType.RSA_PROACTIVE_STORED.equals(shareholder.getSharingType()) && !SharingType.KYBER_STORED.equals(shareholder.getSharingType())) {
			throw new BadRequestException();
		}

		String response;
		if(shareholder.getSharingType().equals(SharingType.RSA_STORED)) {

			// Extract message from request
			final String message = HttpRequestProcessor.getParameterValue(params, MESSAGE_FIELD);
			if (message == null) {
				throw new BadRequestException();
			}


			final BigInteger m = new BigInteger(message);
			response = createRsaResponse(shareholder, m);
		}
		else if (shareholder.getSharingType().equals(SharingType.RSA_PROACTIVE_STORED)){

			// Extract message from request
			final String message = HttpRequestProcessor.getParameterValue(params, MESSAGE_FIELD);
			if (message == null) {
				throw new BadRequestException();
			}


			final BigInteger m = new BigInteger(message);
			response = createProactiveRsaResponse(shareholder, m);
		}
		else if (shareholder.getSharingType().equals(SharingType.KYBER_STORED)){
//			response = createProactiveRsaResponse(shareholder, m);
//			KyberCiphertext kyberCiphertext = KyberCiphertext.getCiphertext(KyberUtils.base64ToBytes(message));

			// get body of message
			JSONObject jsonParameters;
			try (InputStream inputStream = exchange.getRequestBody();
				 InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
				 BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
				JSONParser parser = new JSONParser();
				String requestBody = bufferedReader.readLine();
//				logger.info("REQUEST:::" + requestBody);
				jsonParameters = (JSONObject) parser.parse(requestBody);
//				logger.info("PASSED HERE");
//				logger.info("GOT:::" + jsonParameters.get("message"));
			} catch (Exception ex) {
				logger.error(ex);
				throw new RuntimeException(ex);
			}
//			logger.info("HERE1");
			KyberCiphertext kyberCiphertext = KyberCiphertext.getCiphertext(KyberUtils.base64ToBytes(jsonParameters.get("message").toString()));
//			logger.info("HERE2");
			response = createKyberResponse(shareholder, kyberCiphertext);
//			logger.info("HERE3");
		}
		else {
			throw new BadRequestException();
		}
//		// Get RSA parameters
//		final RsaSharing rsaSharing = shareholder.getRsaSharing();
//
//		// Do processing
//		final long startTime = System.nanoTime();
//		final SignatureResponse signatureResponse = doSigning(shareholder, m, rsaSharing);
//		final long endTime = System.nanoTime();
//
//		// Compute processing time
//		final long processingTimeUs = (endTime - startTime) / 1_000;
//
//		// Create response
//		final int serverIndex = shareholder.getIndex();
//		final long epoch = shareholder.getEpoch();
//
//		// Return the result in json
//		final JSONObject obj = new JSONObject();
//		obj.put("responder", new Integer(serverIndex));
//		obj.put("epoch", new Long(epoch));
//
//		obj.put("share", signatureResponse.getSignatureShare().toString());
//
//		JSONArray shareProof = new JSONArray();
//		shareProof.add(signatureResponse.getSignatureShareProof().getC().toString());
//		shareProof.add(signatureResponse.getSignatureShareProof().getZ().toString());
//		obj.put("share_proof", shareProof);
//
//		// public exponenet e
//		obj.put("e", rsaSharing.getPublicKey().getPublicExponent().toString());
//
//		// modulus
//		obj.put("n", rsaSharing.getPublicKey().getModulus().toString());
//
//		// V
//		obj.put("v", rsaSharing.getV().toString());
//
//		// Verification keys
//		JSONArray verificationKeys = new JSONArray();
//		for (final BigInteger vi : rsaSharing.getVerificationKeys()) {
//			verificationKeys.add(vi.toString());
//		}
//		obj.put("verification_keys", verificationKeys);
//
//		obj.put("compute_time_us", new Long(processingTimeUs));

//		String response = obj.toJSONString() + "\n";


		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	private SignatureResponse doSigning(final ApvssShareholder shareholder, final BigInteger m,
			final RsaSharing rsaSharing) throws NotFoundException {
		final ShamirShare share = shareholder.getShare1();
		if ((shareholder.getSecretPublicKey() == null) || (share == null)) {
			throw new NotFoundException();
		} else {
			logger.info("Signing with: " + shareholder.getShare1());
			ServerPublicConfiguration publicConfig = new ServerPublicConfiguration(shareholder.getN(),
					shareholder.getK(), rsaSharing.getPublicKey().getModulus(),
					rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getV(), rsaSharing.getVerificationKeys());
			RsaShareConfiguration config = new RsaShareConfiguration(publicConfig, shareholder.getShare1());
			return ThresholdSignatures.produceSignatureResponse(m, config);
		}
	}

	private String createRsaResponse(ApvssShareholder shareholder, BigInteger m) throws NotFoundException {
		// Get RSA parameters
		final RsaSharing rsaSharing = shareholder.getRsaSharing();

		// Do processing
		final long startTime = System.nanoTime();
		final SignatureResponse signatureResponse = doSigning(shareholder, m, rsaSharing);
		final long endTime = System.nanoTime();

		// Compute processing time
		final long processingTimeUs = (endTime - startTime) / 1_000;

		// Create response
		final int serverIndex = shareholder.getIndex();
		final long epoch = shareholder.getEpoch();

		// Return the result in json
		final JSONObject obj = new JSONObject();
		obj.put("responder", new Integer(serverIndex));
		obj.put("epoch", new Long(epoch));

		obj.put("share", signatureResponse.getSignatureShare().toString());

		JSONArray shareProof = new JSONArray();
		shareProof.add(signatureResponse.getSignatureShareProof().getC().toString());
		shareProof.add(signatureResponse.getSignatureShareProof().getZ().toString());
		obj.put("share_proof", shareProof);

		// public exponenet e
		obj.put("e", rsaSharing.getPublicKey().getPublicExponent().toString());

		// modulus
		obj.put("n", rsaSharing.getPublicKey().getModulus().toString());

		// V
		obj.put("v", rsaSharing.getV().toString());

		// Verification keys
		JSONArray verificationKeys = new JSONArray();
		for (final BigInteger vi : rsaSharing.getVerificationKeys()) {
			verificationKeys.add(vi.toString());
		}
		obj.put("verification_keys", verificationKeys);

		obj.put("compute_time_us", new Long(processingTimeUs));

		return obj.toJSONString() + "\n";
	}

	private String createProactiveRsaResponse(ApvssShareholder shareholder, BigInteger m) throws NotFoundException {
		// Get RSA parameters
		final ProactiveRsaShareholder proactiveRsaShareholder = shareholder.getProactiveRsaShareholder();

		logger.info("Creating partial decryption for proactive rsa");

		// Do processing
		final long startTime = System.nanoTime();
		final SignatureResponse signatureResponse = ThresholdSignatures.produceProactiveSignatureResponse(m, proactiveRsaShareholder, BigInteger.valueOf(shareholder.getIndex()));
		final long endTime = System.nanoTime();

		// Compute processing time
		logger.info("PerfMeas:RsaDecShareTotal:" + (endTime - startTime));
		final long processingTimeUs = (endTime - startTime) / 1_000;

		// Create response
		final int serverIndex = shareholder.getIndex();
		final long epoch = shareholder.getEpoch();

		// Return the result in json
		final JSONObject obj = new JSONObject();
		obj.put("compute_time_us", Long.toString(processingTimeUs));
		obj.put("epoch", Integer.toString(proactiveRsaShareholder.getProactiveRsaPublicParameters().getEpoch()));
		obj.put("signatureResponse", signatureResponse.getJson());

		return obj.toJSONString() + "\n";
	}

	private String createKyberResponse(ApvssShareholder shareholder, KyberCiphertext ciphertext) throws NotFoundException {
		final KyberShareholder kyberShareholder = shareholder.getKyberShareholder();

		logger.debug("Creating partial decryption for kyber");

		// Do processing
		final long startTime = System.nanoTime();
		final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
		md2.update(new byte[]{1, 2, 3});
		byte[] coins1 = md2.digest();
		Kyber.Polynomial decryptionShare = Kyber.gen_dec_share(ciphertext, kyberShareholder.getSecretShare(), coins1);
//		final SignatureResponse signatureResponse = ThresholdSignatures.produceProactiveSignatureResponse(m, proactiveRsaShareholder, BigInteger.valueOf(shareholder.getIndex()));
		final long endTime = System.nanoTime();
		logger.info("PerfMeas:KyberDecShareTotal:" + (endTime - startTime));

		// Compute processing time
		final long processingTimeUs = (endTime - startTime) / 1_000;

		// Create response
//		final int serverIndex = shareholder.getIndex();
//		final long epoch = shareholder.getEpoch();

		// Return the result in json
		final JSONObject obj = new JSONObject();
		obj.put("compute_time_us", Long.toString(processingTimeUs));
//		obj.put("epoch", Integer.toString(proactiveRsaShareholder.getProactiveRsaPublicParameters().getEpoch()));
		obj.put("signatureResponse", KyberUtils.bytesToBase64(KyberUtils.shortsToBytes(decryptionShare.poly)));

		logger.debug("Partial decryption for KYBER generated!!");

		return obj.toJSONString() + "\n";
	}

}