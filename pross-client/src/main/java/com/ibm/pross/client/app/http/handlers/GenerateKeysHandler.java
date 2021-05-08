package com.ibm.pross.client.app.http.handlers;

import com.ibm.pross.client.app.http.HttpRequestProcessor;
import com.ibm.pross.client.app.permissions.AppPermissions;
import com.ibm.pross.client.generation.KyberKeyGenerationClient;
import com.ibm.pross.client.generation.ProactiveRsaKeyGeneratorClient;
import com.ibm.pross.client.generation.RsaKeyGeneratorClient;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.*;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@SuppressWarnings("restriction")
public class GenerateKeysHandler extends AuthenticatedClientRequestHandler {
    public static final AppPermissions.Permissions REQUEST_PERMISSION = AppPermissions.Permissions.DELETE;
    // Query names
    public static final String KEY_GENERATION_TYPE = "type";
    public static final String CIPHER = "cipher";
    public static final String SECRET_NAME_FIELD = "secretName";
    public static final String PROACTIVE = "proactive";
    // Query values
    public static final String CIPHER_RSA = "rsa";
    public static final String CIPHER_PROACTIVE_RSA = "proactive-rsa";
    public static final String CIPHER_KYBER = "kyber";
    private static final Logger logger = LogManager.getLogger(GenerateKeysHandler.class);
    //Path names
    public static String CLIENT_DIRECTORY = "client";
    public static String CLIENT_KEYS_DIRECTORY = "client/keys";
    public static String CERTS_DIRECTORY = "certs";


    // Fields
    private final ServerConfiguration serverConfiguration;
    private final List<X509Certificate> caCertificates;
    private final KeyLoader serverKeys;
    private final X509Certificate clientCertificate;
    private final PrivateKey clientTlsKey;


    public GenerateKeysHandler(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
                               final KeyLoader serverKeys, final X509Certificate clientCertificate,
                               PrivateKey clientTlsKey) {
        super(serverKeys);

        this.serverConfiguration = serverConfiguration;
        this.caCertificates = caCertificates;
        this.serverKeys = serverKeys;
        this.clientCertificate = clientCertificate;
        this.clientTlsKey = clientTlsKey;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void authenticatedClientHandle(final HttpExchange exchange, final String user) throws IOException {
        final URI requestUri = exchange.getRequestURI();

        if (requestUri == null)
            return;

        final String requestParameters = requestUri.getQuery();

        String response;

        final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(requestParameters);
        final String cipher = Objects.requireNonNull(HttpRequestProcessor.getParameterValue(params, CIPHER)).toLowerCase();
        final String secretName = Objects.requireNonNull(HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD)).toLowerCase();

        logger.info(cipher + "-key generation requested for secret : " + secretName);

        boolean generationStatus = false;
        try {
            if (cipher.equals(CIPHER_RSA)) {
                RsaKeyGeneratorClient rsaKeyGeneratorClient = new RsaKeyGeneratorClient(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey, secretName);
                generationStatus = rsaKeyGeneratorClient.generateRsaKeys();
            } else if (cipher.equals(CIPHER_PROACTIVE_RSA)) {
                ProactiveRsaKeyGeneratorClient rsaKeyGeneratorClient = new ProactiveRsaKeyGeneratorClient(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey, secretName);
                generationStatus = rsaKeyGeneratorClient.generateRsaKeys();
            } else if (cipher.equals(CIPHER_KYBER)) {
                KyberKeyGenerationClient kyberKeyGenerationClient = new KyberKeyGenerationClient(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey, secretName);
                generationStatus = kyberKeyGenerationClient.generateKyberKeys();
            }
        } catch (Exception ex) {
            logger.error(ex);
        }

        response = (generationStatus) ? "Key generation process was SUCCESSFUL" : "Key generation process FAILED";

        logger.info(response);

        final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

        exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

        // Write headers
        exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300; includeSubdomains");
        exchange.sendResponseHeaders((generationStatus) ? HttpStatusCode.SUCCESS : HttpStatusCode.SERVER_ERROR, binaryResponse.length);

        // Write response
        try (final OutputStream os = exchange.getResponseBody();) {
            os.write(binaryResponse);
        }
    }
}

