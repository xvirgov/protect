package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import com.ibm.pross.common.util.SecretShare;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.avpss.SharingState;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;

/**
 * This handler returns information about a secret. Client's must have a
 * specific authorization to be able to invoke this method. If the secret is not
 * found a 404 is returned. If the client is not authorized a 403 is returned.
 *
 * <pre>
 * Information about the secret includes:
 * - The name of the secret
 * - The public key of the secret
 * - The current epoch id of the secret (first is zero)
 * - The shareholder public verification keys of the secret
 * - The Feldman co-efficients of the secret
 * - The time the secret was first generated/stored by this server
 * - The id of the client who performed the creation or generation of the secret
 * - The time the secret was last proactively refreshed by this server
 * - The next scheduled time for this server to begin a proactive refresh
 * - The number of shares and the reconstruction threshold of the secret
 * - The prime field of the shamir sharing of the secret
 * - The elliptic curve group for exponentiation operations
 * </pre>
 */
@SuppressWarnings("restriction")
public class InfoHandler extends AuthenticatedClientRequestHandler {

    public static final Permissions REQUEST_PERMISSION = Permissions.INFO;
    // Query name
    public static final String CIPHER_FIELD = "cipher";
    public static final String SECRET_NAME_FIELD = "secretName";
    public static final String EPOCH_NUMBER_FIELD = "epochNumber";
    public static final String OUTPUT_FORMAT_FIELD = "json";
    // Query value
    public static final String CIPHER_FIELD_RSA = "rsa";
    public static final String CIPHER_FIELD_PROACTIVE_RSA = "proactive-rsa";
    public static final String CIPHER_FIELD_EC = "ec";
    private static final Logger logger = LogManager.getLogger(InfoHandler.class);
    // Fields
    private final AccessEnforcement accessEnforcement;
    private final ServerConfiguration serverConfig;
    private final ConcurrentMap<String, ApvssShareholder> shareholders;

    public InfoHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
                       final ServerConfiguration serverConfig, final ConcurrentMap<String, ApvssShareholder> shareholders) {
        super(clientKeys);
        this.shareholders = shareholders;
        this.serverConfig = serverConfig;
        this.accessEnforcement = accessEnforcement;
    }

    private static String getRSAPublicInfo(final ApvssShareholder shareholder, final String secretName,
                                           final Long epochNumber, final ServerConfiguration serverConfig, final boolean outputJson) throws BadRequestException {

        // Prevent invalid epochs from being accessed // TODO-thesis move this before getting the secrets
//		if ((epochNumber < 0) || (epochNumber > shareholder.getEpoch())) {
//			throw new BadRequestException();
//		}

        logger.debug("Retrieving local public RSA sharing information for secret " + secretName);
//        logger.debug("Sharing type: " + shareholder.getSharingType().toString());

        final int serverIndex = shareholder.getIndex();

        if (outputJson) {
            // Just return the epoch, and public key

            // Return the result in json
            final JSONObject obj = new JSONObject();
            obj.put("responder", Integer.valueOf(serverIndex).toString());
            obj.put("epoch", Long.valueOf(shareholder.getEpoch()).toString());

//			final JSONArray publicKeyPoint = new JSONArray();
//			publicKeyPoint.add(shareholder.getSecretPublicKey().getX().toString());
//			publicKeyPoint.add(shareholder.getSecretPublicKey().getY().toString());
//			obj.put("public_key", publicKeyPoint);
//
//			for (int i = 1; i <= shareholder.getN(); i++) {
//				final JSONArray verificationPoint = new JSONArray();
//				verificationPoint.add(shareholder.getSharePublicKey(i).getX().toString());
//				verificationPoint.add(shareholder.getSharePublicKey(i).getY().toString());
//				obj.put("share_verification_key_" + i, verificationPoint);
//			}

            obj.put("public_key", shareholder.getRsaSharing().getPublicKey().getPublicExponent().toString());
            obj.put("public_modulus", shareholder.getRsaSharing().getPublicKey().getModulus().toString());

//            logger.info(shareholder.getRsaSharing());
            obj.put("v", shareholder.getRsaSharing().getV().toString());
//			obj.put("public_exponent", shareholder.getRsaSharing().getVerificationKeys().
//			);

//            logger.info("---------------------------------------------------------------------------------");
//            logger.info(shareholder.getRsaSharing().getVerificationKeys());
//            logger.info("---------------------------------------------------------------------------------");

            List<String> verificationKeys = Arrays.stream(shareholder.getRsaSharing().getVerificationKeys())
                    .map(BigInteger::toString).collect(Collectors.toList());

            for (int i = 1; i <= shareholder.getN(); i++) {
//                final JSONArray verificationPoint = new JSONArray();
//                verificationPoint.add(verificationKeys.get(i - 1));
                obj.put("share_verification_key_" + i, verificationKeys.get(i - 1));
            }


            return obj.toJSONString() + "\n";
        }

        return null; // TODO-thesis add support to show RSA secrets on the website
    }

    private static String getProactiveRSAPublicInfo(final ApvssShareholder shareholder, final String secretName,
                                           final Long epochNumber, final ServerConfiguration serverConfig, final boolean outputJson) throws BadRequestException {

        // Prevent invalid epochs from being accessed // TODO-thesis move this before getting the secrets
//		if ((epochNumber < 0) || (epochNumber > shareholder.getEpoch())) {
//			throw new BadRequestException();
//		}

        logger.info("Retrieving local public RSA sharing information for secret " + secretName);
//        logger.debug("Sharing type: " + shareholder.getSharingType().toString());

        final int serverIndex = shareholder.getIndex();

        if (outputJson) {
            // Just return the epoch, and public key

            // Return the result in json
            final JSONObject obj = new JSONObject();
            obj.put("responder", Integer.valueOf(serverIndex).toString());
            obj.put("epoch", Long.valueOf(shareholder.getEpoch()).toString());

//			final JSONArray publicKeyPoint = new JSONArray();
//			publicKeyPoint.add(shareholder.getSecretPublicKey().getX().toString());
//			publicKeyPoint.add(shareholder.getSecretPublicKey().getY().toString());
//			obj.put("public_key", publicKeyPoint);
//
//			for (int i = 1; i <= shareholder.getN(); i++) {
//				final JSONArray verificationPoint = new JSONArray();
//				verificationPoint.add(shareholder.getSharePublicKey(i).getX().toString());
//				verificationPoint.add(shareholder.getSharePublicKey(i).getY().toString());
//				obj.put("share_verification_key_" + i, verificationPoint);
//			}

            obj.put("public_key", shareholder.getRsaProactiveSharing().getPublicKey().getPublicExponent().toString());
            obj.put("public_modulus", shareholder.getRsaProactiveSharing().getPublicKey().getModulus().toString());


            obj.put("d_pub", shareholder.getRsaProactiveSharing().getD_pub().toString());
            obj.put("g", shareholder.getRsaProactiveSharing().getG().toString());

            List<SecretShare> additiveVerificationKeys = shareholder.getRsaProactiveSharing().getAdditiveVerificationKeys();
            JSONArray additiveVerificationKeysArray = new JSONArray();
            additiveVerificationKeysArray.addAll(additiveVerificationKeys.stream().map(SecretShare::getY).map(BigInteger::toString).collect(Collectors.toList()));
            obj.put("additiveVerificationKeys", additiveVerificationKeysArray);

            List<List<SecretShare>> feldmanVerificationValues = shareholder.getRsaProactiveSharing().getFeldmanAdditiveVerificationValues();
            for(int i = 0; i < shareholder.getN(); i++) {
                JSONArray agentsFeldmanVerificationValuesArray = new JSONArray();

                agentsFeldmanVerificationValuesArray.addAll(feldmanVerificationValues.get(i).stream().map(SecretShare::getY).map(BigInteger::toString).collect(Collectors.toList()));
                obj.put("b_" + (i+1), agentsFeldmanVerificationValuesArray);
            }

            logger.info("{DONE}");

//            logger.info(shareholder.getRsaSharing());
//            obj.put("v", shareholder.getRsaSharing().getV().toString());
//			obj.put("public_exponent", shareholder.getRsaSharing().getVerificationKeys().
//			);

//            logger.info("---------------------------------------------------------------------------------");
//            logger.info(shareholder.getRsaSharing().getVerificationKeys());
//            logger.info("---------------------------------------------------------------------------------");

//            List<String> verificationKeys = Arrays.stream(shareholder.getRsaSharing().getVerificationKeys())
//                    .map(BigInteger::toString).collect(Collectors.toList());
//
//            logger.info("HERE");
//            for (int i = 1; i <= shareholder.getN(); i++) {
////                final JSONArray verificationPoint = new JSONArray();
////                verificationPoint.add(verificationKeys.get(i - 1));
//                obj.put("share_verification_key_" + i, verificationKeys.get(i - 1));
//            }


            return obj.toJSONString() + "\n";
        }

        return null; // TODO-thesis add support to show RSA secrets on the website
    }

    @SuppressWarnings("unchecked")
    private static String getSecretInfo(final ApvssShareholder shareholder, final String secretName,
                                        final Long epochNumber, final ServerConfiguration serverConfig, final boolean outputJson) throws BadRequestException {

        // Prevent invalid epochs from being accessed
        if ((epochNumber < 0) || (epochNumber > shareholder.getEpoch())) {
            throw new BadRequestException();
        }

        final int serverIndex = shareholder.getIndex();

        if (outputJson) {
            // Just return the epoch, and public key

            // Return the result in json
            final JSONObject obj = new JSONObject();
            obj.put("responder", Integer.valueOf(serverIndex));
            obj.put("epoch", Long.valueOf(shareholder.getEpoch()));

            final JSONArray publicKeyPoint = new JSONArray();
            publicKeyPoint.add(shareholder.getSecretPublicKey().getX().toString());
            publicKeyPoint.add(shareholder.getSecretPublicKey().getY().toString());
            obj.put("public_key", publicKeyPoint);

            for (int i = 1; i <= shareholder.getN(); i++) {
                final JSONArray verificationPoint = new JSONArray();
                verificationPoint.add(shareholder.getSharePublicKey(i).getX().toString());
                verificationPoint.add(shareholder.getSharePublicKey(i).getY().toString());
                obj.put("share_verification_key_" + i, verificationPoint);
            }

            return obj.toJSONString() + "\n";
        }

        // This server
        final InetSocketAddress thisServerAddress = serverConfig.getServerAddresses().get(serverIndex - 1);
        final String ourIp = thisServerAddress.getAddress().getHostAddress();
        final int ourPort = CommonConfiguration.BASE_HTTP_PORT + serverIndex;

        // Create response
        final StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("<html>\n");
        stringBuilder.append("<head>\n");
        if (epochNumber == shareholder.getEpoch()) {
            // Refresh only if looking at the latest
            final String linkUrl = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName;
            stringBuilder.append("<meta http-equiv=\"refresh\" content=\"10;URL='" + linkUrl + "'\">\n");
        }
        stringBuilder.append("</head>\n");
        stringBuilder.append("<body>\n");
        stringBuilder.append("<pre>\n");

        // Shareholder information
        stringBuilder.append("This is <a href=\"/\">shareholder #" + serverIndex + "</a>"
                + " running <a href=\"https://github.com/jasonkresch/protect\">PROTECT</a>,"
                + " a <b>P</b>latform for <b>Ro</b>bust <b>T</b>hr<b>e</b>shold <b>C</b>ryp<b>t</b>ography.\n");
        stringBuilder.append("<p/>");

        // Secret Info
        stringBuilder.append("<b>Information for \"" + secretName + "\":</b>\n");
        final int n = shareholder.getN();
        final int k = shareholder.getK();
        if (shareholder.getSecretPublicKey() == null) {
            // final String linkUrl = "https://" + ourIp + ":" + ourPort +
            // "/generate?secretName=" + secretName;
            stringBuilder.append("<p>Secret not yet established.\n\n");

            /// "(<a href=\"" + linkUrl + "\">Perform DKG</a>)\n");

            stringBuilder.append("<form action=\"/store\" method=\"get\">");
            stringBuilder.append("<b>Prepare Share for DKG (optional):</b> ");
            stringBuilder.append(
                    "<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
            stringBuilder.append("s_" + serverIndex
                    + ": <input type=\"text\" name=\"share\"> <input type=\"submit\" value=\"Store Share\"> </form>\n");

            stringBuilder.append("<form action=\"/generate\" method=\"get\">");
            stringBuilder.append("<b>Create Shared Secret:</b> ");
            stringBuilder.append(
                    "<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
            stringBuilder.append("<input type=\"submit\" value=\"Initiate DKG\"></form>\n");
            stringBuilder.append("<p/>");

            // stringBuilder.append("<b>Set RSA Share and Modulus:</b>\n");
            // stringBuilder.append("<form action=\"/store\" method=\"get\">");
            // stringBuilder.append(
            // "<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" +
            // secretName + "\">");
            // stringBuilder.append("s_" + serverIndex
            // + ": <input type=\"text\" name=\"share\"> modulus: <input type=\"text\"
            // name=\"modulus\"> <input type=\"submit\" value=\"Store RSA Share\">
            // </form>\n");
            // stringBuilder.append("<p/>");

            stringBuilder.append("<p/>");
        } else {
            stringBuilder.append("sharing_type      =  " + shareholder.getSharingType() + "\n");
            stringBuilder.append("g^{s}             =  " + shareholder.getSecretPublicKey() + "\n");
            stringBuilder.append("number_of_shares  =  " + shareholder.getN() + "\n");
            stringBuilder.append("threshold         =  " + shareholder.getK() + "\n");
            stringBuilder.append("creation_time     =  " + shareholder.getCreationTime() + "\n");
            stringBuilder.append("last_refresh      =  " + shareholder.getLastRefreshTime() + "\n");
            stringBuilder.append("refresh_frequency =  " + shareholder.getRefreshFrequency() + " seconds\n");
            stringBuilder.append("<p/>");

            // Print Field Information
            stringBuilder.append("<b>Field Information:</b>\n");
            stringBuilder.append("prime_modulus     =  " + CommonConfiguration.CURVE.getR() + "\n");
            stringBuilder.append("curve_oid         =  " + CommonConfiguration.CURVE.getOid() + " ("
                    + CommonConfiguration.CURVE.getName() + ")\n");
            stringBuilder.append("generator         =  " + CommonConfiguration.g + "\n");
            stringBuilder.append("<p/>");

            // Print Epoch information
            final SharingState sharingState = shareholder.getSharing(epochNumber);
            stringBuilder.append("<b>Epoch:</b>\n");
            final long firstEpoch = 0;
            final long previousEpoch = epochNumber - 1;
            final long nextEpoch = epochNumber + 1;
            final long latestEpoch = shareholder.getEpoch();
            final String infoFirstEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
                    + "&epochNumber=" + firstEpoch;
            final String infoPreviousEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
                    + "&epochNumber=" + previousEpoch;
            final String infoNextEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
                    + "&epochNumber=" + nextEpoch;
            final String infoLastEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
                    + "&epochNumber=" + latestEpoch;
            stringBuilder.append("epoch_number      =  ");
            stringBuilder.append("<a href=\"" + infoFirstEpoch + "\"><<</a> ");
            stringBuilder.append("<a href=\"" + infoPreviousEpoch + "\"><</a> ");
            stringBuilder.append(epochNumber);
            stringBuilder.append(" <a href=\"" + infoNextEpoch + "\">></a> ");
            stringBuilder.append("<a href=\"" + infoLastEpoch + "\">>></a>\n");
            stringBuilder.append("completion_time   =  " + sharingState.getCreationTime() + "\n");

            stringBuilder.append("<p/>");

            // Print share verification keys
            stringBuilder.append("<b>Share Verification Keys:</b>\n");
            for (int i = 1; i <= n; i++) {
                stringBuilder.append("g^{s_" + i + "} =  " + sharingState.getSharePublicKeys()[i] + "\n");
            }
            stringBuilder.append("<p/>");

            // Print Feldman Coefficients
            stringBuilder.append("<b>Feldman Coefficients:</b>\n");
            for (int i = 0; i < k; i++) {
                stringBuilder.append("g^{a_" + i + "} =  " + sharingState.getFeldmanValues()[i] + "\n");
            }
            stringBuilder.append("<p/>");

            // Print Share Information
            final String readLink = "https://" + ourIp + ":" + ourPort + "/read?secretName=" + secretName;
            final String enableLink = "https://" + ourIp + ":" + ourPort + "/enable?secretName=" + secretName;
            final String disableLink = "https://" + ourIp + ":" + ourPort + "/disable?secretName=" + secretName;
            final String deleteLink = "https://" + ourIp + ":" + ourPort + "/delete?secretName=" + secretName;
            final String recoverLink = "https://" + ourIp + ":" + ourPort + "/recover?secretName=" + secretName;
            stringBuilder.append("<b>Share Information:</b>\n");
            stringBuilder.append(CommonConfiguration.HASH_ALGORITHM + "(s_" + serverIndex + ")  =  "
                    + sharingState.getShare1Hash() + "\n");
            if (sharingState.getShare1() != null) {
                stringBuilder.append("exists        =  TRUE     (<a href=\"" + readLink + "\">Read Share</a>)  (<a href=\"" + deleteLink + "\">Delete Share</a>) \n");
            } else {
                stringBuilder.append("exists        =  FALSE    (<a href=\"" + readLink + "\">Read Share</a>)  (<a href=\"" + recoverLink + "\">Recover Share</a>) \n");
            }
            if (shareholder.isEnabled()) {
                stringBuilder.append("status        =  ENABLED  (<a href=\"" + disableLink + "\">Disable Share</a>) \n");
            } else {
                stringBuilder.append("status        =  DISABLED (<a href=\"" + enableLink + "\">Enable Share</a>) \n");
            }
            stringBuilder.append("<p/>");

            // TODO: Consider: only showing this if the share exists?
            stringBuilder.append("<b>Use Share:</b>\n");
            stringBuilder.append("<form action=\"/exponentiate\" method=\"get\">");
            stringBuilder.append(
                    "<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
            stringBuilder.append(
                    "x: <input type=\"text\" name=\"x\"> y: <input type=\"text\" name=\"y\"> <input type=\"submit\" value=\"Exponentiate\"> \n");
            stringBuilder.append("<p/>");

        }

        // Peers
        stringBuilder.append("<b>Peers:</b>\n");

        int serverId = 0;
        for (final InetSocketAddress serverAddress : serverConfig.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?secretName=" + secretName;
            stringBuilder
                    .append("server." + serverId + " = " + "<a href=\"" + linkUrl + "\">" + serverAddress + "</a>\n");
        }
        stringBuilder.append("<p/>\n");

        stringBuilder.append("</pre>\n");
        stringBuilder.append("</body>\n");
        stringBuilder.append("</html>\n");

        return stringBuilder.toString();
    }

    // TODO-thesis: add option to just return public values for majority voting - secret keys shouldn't be uselessly transported
    @Override
    public void authenticatedClientHandle(final HttpExchange exchange, final String username)
            throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

        logger.info("Server info request is being processed..");

        // Extract secret name from request
        final String queryString = exchange.getRequestURI().getQuery();
        final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);

        final String cipher = HttpRequestProcessor.getParameterValue(params, CIPHER_FIELD);
//        if (cipher == null) {
//            throw new BadRequestException();
//        }

        final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
        if (secretName == null) {
            throw new BadRequestException();
        }

        final Boolean outputJson = Boolean
                .parseBoolean(HttpRequestProcessor.getParameterValue(params, OUTPUT_FORMAT_FIELD));

//        logger.info("Providing info about secret " + secretName + " of cipher suite " + cipher);

        // Perform authentication
        accessEnforcement.enforceAccess(username, secretName, REQUEST_PERMISSION);

        // Do processing
        final ApvssShareholder shareholder = this.shareholders.get(secretName);
        if (shareholder == null) {
            throw new NotFoundException();
        }

        // Get epoch number from request
        final Long epochNumber;
        final List<String> epochNumbers = params.get(EPOCH_NUMBER_FIELD);
        if ((epochNumbers != null) && (epochNumbers.size() == 1)) {
            epochNumber = Long.parseLong(epochNumbers.get(0));
        } else {
            epochNumber = shareholder.getEpoch();
        }

//        logger.debug("Epoch number: " + epochNumber);

        // Check epoch
        if ((epochNumber < 0) || (epochNumber > shareholder.getEpoch())) {
            logger.error("Epoch is not correct");
            throw new BadRequestException();
        }

        // Create response
        String response = null;
        if (cipher != null && cipher.equalsIgnoreCase(CIPHER_FIELD_RSA)) {
            response = getRSAPublicInfo(shareholder, secretName, epochNumber, serverConfig, outputJson);
        }
        else if (cipher != null && cipher.equalsIgnoreCase(CIPHER_FIELD_PROACTIVE_RSA)) {
            logger.info("Getting proactive RSA public info...");
            response = getProactiveRSAPublicInfo(shareholder, secretName, epochNumber, serverConfig, outputJson);
        }
        else {
            response = getSecretInfo(shareholder, secretName, epochNumber, serverConfig, outputJson);
        }

//        else if (cipher.equalsIgnoreCase(CIPHER_FIELD_EC)) { // TODO-thesis: for now, the default is to return ecc params - change that
//            response = getSecretInfo(shareholder, secretName, epochNumber, serverConfig, outputJson);
//        }

//        logger.debug("Response created");

        if (response == null) {
            throw new BadRequestException();
        }

//		logger.debug("Response:");
//		logger.debug(response);
        final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

        // Write headers
        // exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300;
        // includeSubdomains");
        exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

        // Write response
        try (final OutputStream os = exchange.getResponseBody();) {
            os.write(binaryResponse);
        }
    }

}