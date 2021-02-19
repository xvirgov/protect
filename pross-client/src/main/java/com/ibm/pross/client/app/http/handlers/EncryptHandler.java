package com.ibm.pross.client.app.http.handlers;

import com.ibm.pross.client.app.http.HttpRequestProcessor;
import com.ibm.pross.client.app.permissions.AppPermissions;
import com.ibm.pross.client.encryption.EciesEncryptionClient;
import com.ibm.pross.client.encryption.RsaEncryptionClient;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.*;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@SuppressWarnings("restriction")
public class EncryptHandler extends AuthenticatedClientRequestHandler {
    public static final AppPermissions.Permissions REQUEST_PERMISSION = AppPermissions.Permissions.DELETE;
    // Query names
    public static final String CIPHER_FIELD = "cipher";
    public static final String OPERATION_FIELD = "operation";
    public static final String SECRET_NAME_FIELD = "secretName";
    public static final String USER_FIELD = "userName";
    // Query values
    public static final String RSA_CIPHER = "rsa";
    public static final String ECIES_CIPHER = "ecies";
    private static final Logger logger = LogManager.getLogger(EncryptHandler.class);
    //Path names
    public static String CLIENT_DIRECTORY = "client";
    public static String CLIENT_KEYS_DIRECTORY = "client/keys";
    public static String CERTS_DIRECTORY = "certs";


    // Fields
    private final ServerConfiguration serverConfiguration;
    private final List<X509Certificate> caCertificates;
    private final KeyLoader serverKeys;
    private final X509Certificate clientCertificate;
    private PrivateKey clientTlsKey;
//	private final List<X509Certificate> caCerts;
//	private final KeyLoader serverKeys;

    public EncryptHandler(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
                          final KeyLoader serverKeys, final X509Certificate clientCertificate,
                          PrivateKey clientTlsKey) {
        super(serverKeys);
//		this.caCerts = caCerts;
//		this.serverKeys = serverKeys;
        this.serverConfiguration = serverConfiguration;
        this.caCertificates = caCertificates;
        this.serverKeys = serverKeys;
        this.clientCertificate = clientCertificate;
        this.clientTlsKey = clientTlsKey;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void authenticatedClientHandle(final HttpExchange exchange, final String user) throws IOException,
            UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException, InternalServerException {

//        logger.info("Started encryption operation");

        // Extract secret name from request
        final URI requestUri = exchange.getRequestURI();

        if (requestUri == null)
            return;

        final String requestParameters = requestUri.getQuery();

        String response = requestParameters;

        final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(requestParameters);
        final String cipher = Objects.requireNonNull(HttpRequestProcessor.getParameterValue(params, CIPHER_FIELD)).toLowerCase();
        final String secretName = Objects.requireNonNull(HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD)).toLowerCase();

        // TODO check if operation is encryption or decryption
        // TODO check if secret exists
//        logger.debug("ECIES operation \"" + cipher + "\" requested using a secret \"" + secretName + "\"");
        logger.info(cipher + "-encryption operation requested with secret " + secretName);

//		InputStream inputStream = new InputStreamReader(exchange.getRequestBody());

//		try (InputStreamReader inputStreamReader = new InputStreamReader(exchange.getRequestBody());
//			 BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
//			int character;
//			while ((character = bufferedReader.read()) != EOF) {
//
//			}
//		}

        // Print the binary data
//		int count = 0;
//		InputStream inputStream = exchange.getRequestBody();
//		int character;
//		while ((character = inputStream.read()) != -1) {
//			System.out.printf("%02x : %c \n",character, character);
//			count++;
//		}
//		logger.info("Number of bytes: " + count);

        if (cipher.equals(ECIES_CIPHER)) {
			EciesEncryptionClient eciesEncryptionClient = new EciesEncryptionClient(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey, secretName, exchange.getRequestBody());

			try (final OutputStream os = exchange.getResponseBody();) {
				final byte[] binaryResponse = eciesEncryptionClient.encryptStream();
				exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);
				os.write(binaryResponse);
			} catch (Exception ex) {
				logger.error(ex);
			}
		}
        else if (cipher.equals(RSA_CIPHER)) {
			RsaEncryptionClient rsaEncryptionClient = new RsaEncryptionClient(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

			try (final OutputStream os = exchange.getResponseBody();) {
				final byte[] binaryResponse = rsaEncryptionClient.encryptStream(secretName, exchange.getRequestBody());
				exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);
				os.write(binaryResponse);
			} catch (Exception ex) {
				logger.error(ex);
			}
		}
        // Write headers
        // exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300;
        // includeSubdomains");
//		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);
//
//		// Write response
//		try (final OutputStream os = exchange.getResponseBody();) {
//			os.write(binaryResponse);
//		}

//
//		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
//		final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
//		if (secretName == null || !secretName.equals("rsa-secret")) {
//			throw new BadRequestException();
//		}
//		final String userName = HttpRequestProcessor.getParameterValue(params, USER_FIELD);
//
//		// Perform authentication
//		accessEnforcement.enforceAccess(userName, secretName, REQUEST_PERMISSION);
//
//		// Load client certificate
//		X509Certificate clientCertificate;
//		final File clientDirectory = new File(baseDirectory, CLIENT_DIRECTORY);
//		final File certDirectory = new File(clientDirectory, CERTS_DIRECTORY);
//		final File clientCertificateFile = new File(certDirectory, "cert-" + userName);
//		try {
//			clientCertificate = Pem.loadCertificateFromFile(clientCertificateFile);
//		} catch (CertificateException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (InvalidKeySpecException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		}
//
//		// Load client key
//		PrivateKey clientPrivateKey;
//		final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
//		final File clientKeysFile = new File(clientKeysDirectory, "private-" + userName);
//		try {
//			clientPrivateKey = (PrivateKey) Pem.loadKeyFromFile(clientKeysFile);
//		} catch (CertificateException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (InvalidKeySpecException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		}


//		final String name = HttpRequestProcessor.getParameterValue(params, NAME_FIELD);

//		String response = "Encrypt handle olololololor";
//		String response = exchange.getRequestURI().getQuery();
//		String response = exchange.getRequestBody().toString();

        // tested with: sudo curl -k -F "data=@/home/xvirgov/tmp"   --cacert ca-key-clients --cert client/certs/cert-administrator --key client/keys/private-administrator https://localhost:8080/encrypt?oooooooooooooooooooooooooo=aa --output tmp


//		StringBuilder stringBuilder = new StringBuilder(4096);
//		try(InputStreamReader inputStreamReader = new InputStreamReader(exchange.getRequestBody());
//			BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
//			String line;
//			while ((line = bufferedReader.readLine()) != null) {
//				stringBuilder.append(line + "\n");
//			}
//		}
//		String response = stringBuilder.toString();


//		doStoring()
//		try {
//			success = doStoring(secretName,name,clientCertificate,clientPrivateKey);
//			if (success) {
//				response = "RSA shares deleted. \n";
//				logger.info("Deletion complete");
//			} else {
//				response = "RSA not deleted";
//			}
//		} catch (GeneralSecurityException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (BelowThresholdException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (BadArgumentException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		} catch (ClassNotFoundException e) {
//			e.printStackTrace();
//			throw new UnauthorizedException();
//		}

        // Create response

//		new EciesEncryptionClient()
//
//		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
//
//		// Write headers
//		// exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300;
//		// includeSubdomains");
//		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);
//
//		// Write response
//		try (final OutputStream os = exchange.getResponseBody();) {
//			os.write(binaryResponse);
//		}
    }

//	private EcPoint doExponentiation(final ApvssShareholder shareholder, EcPoint basePoint) throws NotFoundException {
//		final ShamirShare share = shareholder.getShare1();
//		if ((shareholder.getSecretPublicKey() == null) || (share == null)) {
//			throw new NotFoundException();
//		} else {
//			// Compute exponentiation using share
//			return CommonConfiguration.CURVE.multiply(basePoint, share.getY());
//		}
//
//	}

    private Boolean doStoring(String secretName, String name, X509Certificate clientCertificate, PrivateKey clientPrivateKey) throws ResourceUnavailableException, GeneralSecurityException, BelowThresholdException, IOException, BadArgumentException, ClassNotFoundException {
//		RsaCertificateAuthorityClient client = new RsaCertificateAuthorityClient(serverConfiguration,caCerts,serverKeys,clientCertificate,clientPrivateKey, secretName, name);
//		Boolean response = client.workOnShares(false,false);
//		return response;
        return false;
    }

}

