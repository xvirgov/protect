package com.ibm.pross.client.app.http.handlers;

import com.ibm.pross.client.app.http.HttpRequestProcessor;
import com.ibm.pross.client.app.permissions.AccessEnforcement;
import com.ibm.pross.client.app.permissions.AppPermissions;
import com.ibm.pross.client.signing.RsaCertificateAuthorityClient;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.*;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.serialization.Pem;
import com.sun.net.httpserver.HttpExchange;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;

@SuppressWarnings("restriction")
public class EncryptHandler extends AuthenticatedClientRequestHandler {
	public static final AppPermissions.Permissions REQUEST_PERMISSION = AppPermissions.Permissions.DELETE;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String NAME_FIELD = "name";
	public static final String USER_FIELD = "userName";

	//Path names
	public static String CLIENT_DIRECTORY = "client";
	public static String CLIENT_KEYS_DIRECTORY = "client/keys";
	public static String CERTS_DIRECTORY = "certs";


	// Fields
	private final List<X509Certificate> caCerts;
	private final KeyLoader serverKeys;

	public EncryptHandler(final KeyLoader clientKeys, final List<X509Certificate> caCerts,
						 final KeyLoader serverKeys) {
		super(clientKeys);
		this.caCerts = caCerts;
		this.serverKeys = serverKeys;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String user) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException, InternalServerException {

		// Extract secret name from request
//		final String queryString = exchange.getRequestURI().getQuery();
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

		String response = "Encrypt handle olololololor";
		doStoring()
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

	private Boolean doStoring(String secretName, String name, X509Certificate clientCertificate, PrivateKey clientPrivateKey) throws ResourceUnavailableException, GeneralSecurityException, BelowThresholdException, IOException, BadArgumentException, ClassNotFoundException {
//		RsaCertificateAuthorityClient client = new RsaCertificateAuthorityClient(serverConfiguration,caCerts,serverKeys,clientCertificate,clientPrivateKey, secretName, name);
//		Boolean response = client.workOnShares(false,false);
//		return response;
		return false;
	}

}

