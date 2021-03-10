package com.ibm.pross.server.app.http.handlers;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.ConflictException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.InternalServerException;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaProactiveSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;

/**
 * This handler pre-stores a share of the secret Client's must have a specific
 * authorization to be able to invoke this method. The client must invoke this
 * method on each of the shareholders providing each with a unique share of the
 * secret before performing a generate in order to guarantee correct storage of
 * the secret.
 * <p>
 * If the secret is not found a 404 is returned. If the client is not authorized
 * a 403 is returned.
 */
@SuppressWarnings("restriction")
public class StoreHandler extends AuthenticatedClientRequestHandler {

    public static final Permissions REQUEST_PERMISSION = Permissions.STORE;
    // Required parameters
    public static final String SECRET_NAME_FIELD = "secretName";
    public static final String SHARE_VALUE = "share";
    // RSA query parameters
    public static final String MODULUS_VALUE = "n";
    public static final String PUBLIC_EXPONENT_VALUE = "e";
    public static final String SHARING_TYPE_VALUE = "sharingType";
    public static final String SHARING_TYPE_VALUE_PROACTIVE_RSA = "proactive-rsa";
    public static final String VERIFICATION_BASE = "v";
    public static final String VERIFICATION_KEYS = "v_";
    private static final Logger logger = LogManager.getLogger(StoreHandler.class);
    // Fields
    private final AccessEnforcement accessEnforcement;
    private final ConcurrentMap<String, ApvssShareholder> shareholders;

    public StoreHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
                        final ConcurrentMap<String, ApvssShareholder> shareholders) {
        super(clientKeys);
        this.shareholders = shareholders;
        this.accessEnforcement = accessEnforcement;
    }

    @Override
    public void authenticatedClientHandle(final HttpExchange exchange, final String username)
            throws IOException, UnauthorizedException, NotFoundException, BadRequestException,
            ResourceUnavailableException, ConflictException, InternalServerException { // TODO-now refactor

        logger.info("Starting store operation");

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
        // If DKG already started, it is too late, but we allow RSA keys to be updated
        if ((shareholder.getSharingType() != null)) {
            throw new ConflictException();
        }

        // Parse values from RSA storage operation
        final String nStr = HttpRequestProcessor.getParameterValue(params, MODULUS_VALUE);
        final BigInteger n = (nStr == null) ? null : new BigInteger(nStr);

        final String eStr = HttpRequestProcessor.getParameterValue(params, PUBLIC_EXPONENT_VALUE);
        final BigInteger e = (eStr == null) ? null : new BigInteger(eStr);

        final String sharingType = HttpRequestProcessor.getParameterValue(params, SHARING_TYPE_VALUE);
//		logger.info(receivedBody);

        // Receive store request message
        JSONObject jsonParameters;
        try (InputStream inputStream = exchange.getRequestBody();
             InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
             BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
            JSONParser parser = new JSONParser();
            String requestBody = bufferedReader.readLine();
            jsonParameters = (JSONObject) parser.parse(requestBody);
        } catch (Exception ex) {
            logger.error(ex);
            throw new RuntimeException(ex);
        }

//        logger.info("JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ");
//        if (jsonParameters != null)
//            logger.info(jsonParameters.toString());

        // Prepare to formulate response
        final int serverIndex = shareholder.getIndex();
        final String response;

        // Extract share from the request
        final List<String> shareValues = params.get(SHARE_VALUE);
        if (((shareValues == null) || (shareValues.size() != 1) || (shareValues.get(0) == null)) && sharingType == null) {
            // Unset the stored value
            shareholder.setStoredShareOfSecret(null);
            response = "s_" + serverIndex + " has been unset, DKG will use a random value for '" + secretName + "'.";
        } else {
            BigInteger shareValue = BigInteger.ZERO;
            if (((e != null) && (n != null))) { // TODO-now specify in store request
                shareValue = new BigInteger(shareValues.get(0));
                // Store RSA share, e and exponent n
                RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
                KeyFactory keyFactory;

                try {
                    keyFactory = KeyFactory.getInstance("RSA");


                    final String vStr = HttpRequestProcessor.getParameterValue(params, VERIFICATION_BASE);
                    final BigInteger v = (vStr == null) ? null : new BigInteger(vStr);

                    final BigInteger[] verificationKeys = new BigInteger[shareholder.getN()];
                    for (int i = 1; i <= shareholder.getN(); i++) {
                        final String vStrI = HttpRequestProcessor.getParameterValue(params, VERIFICATION_KEYS + i);
                        verificationKeys[i - 1] = (vStrI == null) ? null : new BigInteger(vStrI);
                    }

                    final RsaSharing rsaSharing = new RsaSharing(shareholder.getN(), shareholder.getK(), (RSAPublicKey) keyFactory.generatePublic(spec), null, null, v, verificationKeys);
                    shareholder.setRsaSecret(shareValue, rsaSharing);
                    response = "RSA share have been stored.";

                } catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
                    throw new InternalServerException();
                }
            } else if (sharingType != null && sharingType.equals(SHARING_TYPE_VALUE_PROACTIVE_RSA)) {
                try {
                    final ProactiveRsaShareholder proactiveRsaShareholder = ProactiveRsaShareholder.getParams(jsonParameters);

                    shareholder.setProactiveRsaShareholder(proactiveRsaShareholder);

                    // Start proactive RSA process

                    boolean started = shareholder.refreshRsaSharing(0);

                    if (started) {
//                        shareholder.waitForEpochIncrease(shareholder.getEpoch()); // wait until epoch number is increased
                    }
                    else {
                        logger.error("Secret was already established");
                        throw new ConflictException();
                    }

                    response = "proactive RSA share have been stored.";
                } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
                    logger.error(exception);
                    throw new InternalServerException();
                }
            } else {
                shareholder.setStoredShareOfSecret(shareValue);
                response = "s_" + serverIndex + " has been stored, DKG will use it for representing '" + secretName
                        + "' in the DKG.";
            }
        }

        logger.info(response);

        // Create response
        final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

        // Write headers
        exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

        // Write response
        try (final OutputStream os = exchange.getResponseBody();) {
            os.write(binaryResponse);
        }
    }

    private RsaProactiveSharing createProactiveRsaSharingFromParameters(JSONObject proactiveRsaParameters,
                                                                        ApvssShareholder shareholder,
                                                                        KeyFactory keyFactory, RSAPublicKeySpec rsaPublicKeySpec,
                                                                        BigInteger v, BigInteger[] verificationKeys) throws InvalidKeySpecException {

//        logger.info("Starin parsing...........");
        // Parse the json parameters
        BigInteger d_pub = new BigInteger(String.valueOf(proactiveRsaParameters.get("d_pub")));
        BigInteger d_i = new BigInteger(String.valueOf(proactiveRsaParameters.get("additiveSecretKey")));
        BigInteger g = new BigInteger(String.valueOf(proactiveRsaParameters.get("g")));

        List<List<SecretShare>> feldmanAdditiveVerificationValues = new ArrayList<>();
        List<SecretShare> agentShamirShares = new ArrayList<>();
        List<SecretShare> additiveVerificationKeys = new ArrayList<>();
        try {
            JSONArray agentShamirSharesArray = (JSONArray) proactiveRsaParameters.get("agentsShamirShares");
            for (int i = 0; i < shareholder.getN(); i++) {
                agentShamirShares.add(new SecretShare(BigInteger.valueOf(i + 1), new BigInteger((String) agentShamirSharesArray.get(i))));
            }

            for (int i = 0; i < shareholder.getN(); i++) {
                JSONArray feldmanAdditiveVerificationValuesArray = (JSONArray) proactiveRsaParameters.get("b_" + (i + 1));
                List<SecretShare> collector = new ArrayList<>();
                for (int j = 0; j < shareholder.getK(); j++) {
                    collector.add(new SecretShare(BigInteger.valueOf(j + 1), new BigInteger((String) feldmanAdditiveVerificationValuesArray.get(j))));
                }
                feldmanAdditiveVerificationValues.add(collector);
            }

            JSONArray additiveVerificationKeysArray = (JSONArray) proactiveRsaParameters.get("additiveVerificationKeys");
            for (int i = 0; i < shareholder.getN(); i++) {
                additiveVerificationKeys.add(new SecretShare(BigInteger.valueOf(i + 1), new BigInteger((String) additiveVerificationKeysArray.get(i))));
            }
        } catch (Exception ex) {
            logger.error(ex);
            throw new RuntimeException();
        }

        List<BigInteger> multipliedFeldmanVerificationValues = new ArrayList<>(); // TODO-now have this directly precomputed
        for (int i = 0; i < shareholder.getK(); i++) {
            BigInteger accumulator = BigInteger.ONE;
            for (int j = 0; j < shareholder.getN(); j++) {
                accumulator = accumulator.multiply(feldmanAdditiveVerificationValues.get(j).get(i).getY());
            }
            multipliedFeldmanVerificationValues.add(accumulator);
        }

        BigInteger summedPrivateKeysShares = agentShamirShares.stream().map(SecretShare::getY).reduce(BigInteger::add).get();

        BigInteger modulus = rsaPublicKeySpec.getModulus();

        List<BigInteger> agentsFeldmanVerificationValues = new ArrayList<>();  // TODO-now have this directly precomputed
        for (int i = 0; i < shareholder.getN(); i++) {
            BigInteger result = BigInteger.ONE;
            for (int j = 0; j < shareholder.getK(); j++) {
                result = result.multiply(multipliedFeldmanVerificationValues.get(j).modPow(BigInteger.valueOf(i + 1).pow(j), modulus)).mod(modulus);
            }
            agentsFeldmanVerificationValues.add(result);
        }


        RsaProactiveSharing rsaProactiveSharing = new RsaProactiveSharing(null, null, shareholder.getN(),
                shareholder.getK(), null, 0, 0, null, null, (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec),
                null, null, null, d_pub, g, null, null,
                feldmanAdditiveVerificationValues, additiveVerificationKeys, null, null); // TODO-now: json->agent object

        rsaProactiveSharing.setShamirAdditiveSharesOfAgent(agentShamirShares);
        rsaProactiveSharing.setAdditiveShareOfAgent(d_i);
        rsaProactiveSharing.setSummedAgentsShamirKeyShares(summedPrivateKeysShares);
        rsaProactiveSharing.setAgentsFeldmanVerificationValues(agentsFeldmanVerificationValues);
        return rsaProactiveSharing;
    }

}