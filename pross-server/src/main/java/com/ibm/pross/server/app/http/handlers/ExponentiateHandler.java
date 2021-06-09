package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.server.app.avpss.SharingState;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
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
public class ExponentiateHandler extends AuthenticatedClientRequestHandler {

	private static final Logger logger = LogManager.getLogger(ExponentiateHandler.class);

	public static final Permissions REQUEST_PERMISSION = Permissions.EXPONENTIATE;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String BASE_X_COORD = "x";
	public static final String BASE_Y_COORD = "y";
	public static final String OUTPUT_FORMAT_FIELD = "json";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public ExponentiateHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException {

		logger.info("Decryption request has been received");

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
		final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
		if (secretName == null) {
			throw new BadRequestException();
		}
		final Boolean outputJson = Boolean
				.parseBoolean(HttpRequestProcessor.getParameterValue(params, OUTPUT_FORMAT_FIELD));

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

		// Extract X-Coordinate from request
		final List<String> xCoords = params.get(BASE_X_COORD);
		if ((xCoords == null) || (xCoords.size() != 1) || (xCoords.get(0) == null)) {
			throw new BadRequestException();
		}
		final BigInteger xCoord = new BigInteger(xCoords.get(0));

		// Extract Y-Coordinate from request or compute it.
		final BigInteger yCoord;
		final List<String> yCoords = params.get(BASE_Y_COORD);
		if ((yCoords != null) && (yCoords.size() == 1) && (yCoords.get(0) != null)) {
			yCoord = new BigInteger(yCoords.get(0));
		} else {
			// Compute yCoordinate from xCoordinate
			final BigInteger ySquared = CommonConfiguration.CURVE.computeYSquared(xCoord);
			yCoord = CommonConfiguration.CURVE.getPointHasher().squareRoot(ySquared);
		}

		// Form an elliptic curve point
		final EcPoint basePoint = new EcPoint(xCoord, yCoord);

		// Ensure the resulting point exists on the curve
		if (!CommonConfiguration.CURVE.isPointOnCurve(basePoint)) {
			throw new BadRequestException();
		}

		SharingState sharingState = shareholder.getSharing(shareholder.getEpoch());

//		logger.info("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
//		logger.info(sharingState.getSharePublicKeys());
//		logger.info(sharingState.getVerifications());
//		logger.info("verif key:" + sharingState.getVerifications().get(shareholder.getIndex()));
//		logger.info("recomputed verif key:" + CommonConfiguration.CURVE.multiply(CommonConfiguration.CURVE.getG(), sharingState.getShare1().getY()));
//		logger.info("index: " + shareholder.getIndex());
//		logger.info("s: " + sharingState.getShare1().getY());
//		logger.info("G: " + CommonConfiguration.CURVE.getG());
//		logger.info("sG: " + CommonConfiguration.CURVE.multiply(CommonConfiguration.g, sharingState.getShare1().getY()));
//		logger.info("verif: " +  sharingState.getVerifications().get(shareholder.getIndex()));
//		logger.info("all keys: " +  sharingState.getVerifications());
//		logger.info("number of verif keys: " + sharingState.getVerifications().size());
//		logger.info("number of verif keys: " + sharingState.getVerifications().get(0).getX());
//		logger.info("number of verif keys: " + sharingState.getVerifications().get(0).getY());
//		for(int i = 0; i < sharingState.getVerifications().size(); i++) {
//			System.out.println(sharingState.getVerifications().get(i).getX() + " : " + sharingState.getVerifications().get(i).getY());
//		}

//		EcCurve curve = CommonConfiguration.CURVE;
//
//		System.out.println("Index: " + shareholder.getIndex());
//		System.out.println("verif: " + curve.multiply(curve.getG(), sharingState.getShare1().getY()));

		// Do processing
		final long startTime = System.nanoTime();
		final EcPoint result = doExponentiation(shareholder, basePoint);
		final long endTime = System.nanoTime();

		// Create proof c = H(G, R, s_i.G, s_i.R, r.G, rR)

		EcPoint G = CommonConfiguration.g;
		EcPoint R = basePoint;
		BigInteger r = RandomNumberGenerator.generateRandomInteger(CommonConfiguration.CURVE.getR());
		BigInteger si = sharingState.getShare1().getY();

		EcPoint siG = CommonConfiguration.CURVE.multiply(G, si);
		EcPoint siR = CommonConfiguration.CURVE.multiply(R, si);
		EcPoint rG = CommonConfiguration.CURVE.multiply(G, r);
		EcPoint rR = CommonConfiguration.CURVE.multiply(R, r);

		byte[] cBytes = Parse.concatenate(G, R, siG, siR, rG, rR);

		BigInteger c = ThresholdSignatures.hashToInteger(cBytes, ThresholdSignatures.HASH_MOD);
		BigInteger z = si.multiply(c).add(r);

		SignatureShareProof decryptionProof = new SignatureShareProof(c, z);


		// Compute processing time
		final long processingTimeUs = (endTime - startTime) / 1_000;

		// Create response
		final int serverIndex = shareholder.getIndex();
		final long epoch = shareholder.getEpoch();
		final String response;
		if (outputJson) {

			// Return the result in json
			final JSONObject obj = new JSONObject();
			obj.put("responder", new Integer(serverIndex));
			obj.put("epoch", new Long(epoch));

			JSONArray inputPoint = new JSONArray();
			inputPoint.add(basePoint.getX().toString());
			inputPoint.add(basePoint.getY().toString());
			obj.put("base_point", inputPoint);

			JSONArray outputPoint = new JSONArray();
			outputPoint.add(result.getX().toString());
			outputPoint.add(result.getY().toString());
			obj.put("result_point", outputPoint);
			obj.put("dec_proof", decryptionProof.getJson());

			obj.put("compute_time_us", new Long(processingTimeUs));

			response = obj.toJSONString() + "\n";

		} else {
			response = basePoint + "^{s_" + serverIndex + "} = \n" + result + "\n\n" + "Result computed in "
					+ processingTimeUs + " microseconds using share #" + serverIndex + " of secret '" + secretName
					+ "' from epoch " + epoch + "\n";
		}
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		logger.info("Sending results of exponentiation and proof...");

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	private EcPoint doExponentiation(final ApvssShareholder shareholder, EcPoint basePoint) throws NotFoundException {
		final ShamirShare share = shareholder.getShare1();
		if ((shareholder.getSecretPublicKey() == null) || (share == null)) {
			throw new NotFoundException();
		} else {
			// Compute exponentiation using share
			return CommonConfiguration.CURVE.multiply(basePoint, share.getY());
		}

	}

}