//package com.ibm.pross.client.app.http.handlers;
//
//import java.io.*;
//import java.net.URL;
//import java.nio.charset.StandardCharsets;
//import java.security.cert.X509Certificate;
//import java.util.List;
//import java.util.Map;
//import java.util.concurrent.ConcurrentMap;
//
//import com.ibm.pross.client.app.http.HttpRequestProcessor;
//import com.ibm.pross.common.config.CommonConfiguration;
//import com.ibm.pross.common.config.KeyLoader;
//import com.ibm.pross.common.config.ServerConfiguration;
//import com.ibm.pross.common.exceptions.http.BadRequestException;
//import com.ibm.pross.common.exceptions.http.ConflictException;
//import com.ibm.pross.common.exceptions.http.HttpStatusCode;
//import com.ibm.pross.common.exceptions.http.NotFoundException;
//import com.ibm.pross.common.exceptions.http.UnauthorizedException;
////import com.ibm.pross.server.app.avpss.ApvssShareholder;
////import com.ibm.pross.server.app.http.HttpRequestProcessor;
////import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
////import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
//import com.sun.net.httpserver.HttpExchange;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//
//import javax.net.ssl.HttpsURLConnection;
//
///**
// * This handler initiates a Distributed Key Generation for a secret. Client's
// * must have a specific authorization to be able to invoke this method. If the
// * secret is not found a 404 is returned. If the client is not authorized a 401
// * is returned. If the secret has already been stored or generated with this
// * name the request will fail with 409 conflict. Replacing an existing secret
// * requires an explicit deletion first.
// *
// * The client may specify whether the generation is to be of a Pedersen or
// * Feldman form. The Pedersen offers some security advantages but is slower.
// *
// * <pre>
// * Parameters of the DKG include:
// * - The name of the secret
// * - Whether to use a Pedersen- or Feldman-style generation
// * - The elliptic curve over which to perform the DKG
// * - The frequency for which a proactive refresh ought to be performed (in seconds)
// * </pre>
// */
//@SuppressWarnings("restriction")
//public class GenerateHandler extends AuthenticatedClientRequestHandler {
//
//    private static final Logger logger = LogManager.getLogger(GenerateHandler.class);
//
////    public static final Permissions REQUEST_PERMISSION = Permissions.GENERATE;
//
//    // Query name
//    public static final String SECRET_NAME_FIELD = "secretName";
//
//    // Fields
////    private final AccessEnforcement accessEnforcement;
////    private final ConcurrentMap<String, ApvssShareholder> shareholders;
//    private final List<X509Certificate> caCerts;
//    private final ServerConfiguration serverConfiguration;
//
//    public GenerateHandler(final KeyLoader clientKeys, final List<X509Certificate> caCerts,
//                           final ServerConfiguration serverConfiguration) {
//        super(clientKeys);
//        this.caCerts = caCerts;
//        this.serverConfiguration = serverConfiguration;
//    }
//
//    @Override
//    public void authenticatedClientHandle(final HttpExchange exchange, final String username)
//            throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException {
//
//        String url_link = "https://" + serverConfiguration.getServerAddresses().get(0).getAddress().getHostAddress() + ":" + ((int) CommonConfiguration.BASE_HTTP_PORT + 1) + "/id";
//        logger.debug(url_link);
//
//        final URL url = new URL(url_link);
//        final HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
//        this.configureHttps(httpsURLConnection, 1);
//
//        httpsURLConnection.setRequestMethod("GET");
//        httpsURLConnection.setConnectTimeout(10_000);
//        httpsURLConnection.setReadTimeout(10_000);
//
//        httpsURLConnection.connect();
//
//        try (final InputStream inputStream = httpsURLConnection.getInputStream();
//             final InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
//             final BufferedReader bufferedReader = new BufferedReader(inputStreamReader);) {
////            logger.debug(bufferedReader.readLine());
//            while (true) {
//                String line = bufferedReader.readLine();
//                logger.debug(line);
//                if(line==null)
//                    break;
//            }
//        }
//
//
//    }
//
//        // Extract secret name from request
//        // final String secretName =
//        // exchange.getRequestHeaders().getFirst(SECRET_NAME_FIELD);
////        final String queryString = exchange.getRequestURI().getQuery();
////        final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
////        final List<String> secretNames = params.get(SECRET_NAME_FIELD);
////        if (secretNames == null || secretNames.size() != 1) {
////            throw new BadRequestException();
////        }
////        final String secretName = secretNames.get(0);
////
////        // Perform authentication
////        accessEnforcement.enforceAccess(username, secretName, REQUEST_PERMISSION);
////
////        // Do processing
////        final long startTime = System.nanoTime();
////        doDistribuedKeyGeneration(secretName);
////        final long endTime = System.nanoTime();
////
////        // Compute processing time
////        final long processingTimeMs = (endTime - startTime) / 1_000_000;
////
////        // Create response
////        final String response = "The secret '" + secretName + "' has been generated in " + processingTimeMs + " ms.\n";
////        final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
////
////        // Write headers
////        exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);
////
////        // Write response
////        try (final OutputStream os = exchange.getResponseBody();) {
////            os.write(binaryResponse);
////        }
////    }
//
////    private void doDistribuedKeyGeneration(final String secretName) throws ConflictException {
////
////        // Get Shareholder
////        final ApvssShareholder shareholder = this.shareholders.get(secretName);
////
////        // Initiate the DKG
////        boolean started = shareholder.broadcastPublicSharing(0);
////
////        if (started) {
////            // Wait for share to be established
////            shareholder.waitForQual();
////
////            // Wait for completion
////            shareholder.waitForPublicKeys();
////        } else {
////            // The secret was already established
////            throw new ConflictException();
////        }
////    }
////
//}