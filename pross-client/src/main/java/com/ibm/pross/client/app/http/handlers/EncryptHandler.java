package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.app.http.db.SharesDB;
import com.ibm.pross.server.app.http.db.StoreHandlerDB;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaShareConfiguration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;

/**
 * This handler performs an exponentiation using a share of a secret. Client's
 * must have a specific authorization to be able to invoke this method. If the
 * secret is not found a 404 is returned. If the client is not authorized a 403
 * is returned.
 */
@SuppressWarnings("restriction")
public class SignHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.SIGN;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String MESSAGE_FIELD = "message";
	public static final String NAME_FIELD = "name";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;
	private ServerPublicConfiguration publicConfig;

	public SignHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
		this.publicConfig = null;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException {

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();

		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
		final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
		if (secretName == null || !secretName.equals("rsa-secret")) {
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

		// Extract message from request
		final String message = HttpRequestProcessor.getParameterValue(params, MESSAGE_FIELD);
		if (message == null) {
			throw new BadRequestException();
		}
		final String name = HttpRequestProcessor.getParameterValue(params, NAME_FIELD);
		final BigInteger m = new BigInteger(message);
		// Ensure the secret is of the supported type
		//if (!SharingType.RSA_STORED.equals(shareholder.getSharingType())) {
		//	throw new BadRequestException();
		//}

		// Get RSA parameters
		//final RsaSharing rsaSharing = shareholder.getRsaSharing();

		// Do processing
		final long startTime = System.nanoTime();
		final SignatureResponse signatureResponse = doSigning(shareholder, m, name);
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
		obj.put("e", publicConfig.getE().toString());

		// modulus
		obj.put("n", publicConfig.getN().toString());

		// V
		obj.put("v", publicConfig.getV().toString());

		// Verification keys
		JSONArray verificationKeys = new JSONArray();
		for (final BigInteger vi : publicConfig.getVerificationKeys()) {
			verificationKeys.add(vi.toString());
		}
		obj.put("verification_keys", verificationKeys);

		obj.put("compute_time_us", new Long(processingTimeUs));


		String response = obj.toJSONString() + "\n";

		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
		//TODO here write!
	}

	private SignatureResponse doSigning(final ApvssShareholder shareholder, final BigInteger m, String name) throws BadRequestException, IOException {
		//Load database
		StoreHandlerDB storeHandlerDB = new StoreHandlerDB("/jsonDB_".concat(String.valueOf(shareholder.getIndex())));
		storeHandlerDB.prepareDB();
		SharesDB sharesDB = storeHandlerDB.queryById(name);
		//If name does not exist, throw 400
		if (sharesDB == null)
		{
			throw new BadRequestException();
		}
		if (sharesDB.getStatus().equals("false"))
		{
			throw new BadRequestException();
		}
		//convert into required format
		BigInteger[] verificationKeys = new BigInteger[sharesDB.getVerificationKeys().length];
		for (int i = 0; i <  verificationKeys.length; i ++){
			verificationKeys[i] = new BigInteger(sharesDB.getVerificationKeys()[i]);
		}

		publicConfig = new ServerPublicConfiguration(sharesDB.getN(),
					sharesDB.getK(), new BigInteger(sharesDB.getModulus()), new BigInteger(sharesDB.getPublicExponent()), new BigInteger(sharesDB.getV()),verificationKeys);

		final ShamirShare share = new ShamirShare(BigInteger.valueOf(shareholder.getIndex()), new BigInteger(sharesDB.getShare()));

		RsaShareConfiguration config = new RsaShareConfiguration(publicConfig, share);

		return ThresholdSignatures.produceSignatureResponse(m, config);


	}

}