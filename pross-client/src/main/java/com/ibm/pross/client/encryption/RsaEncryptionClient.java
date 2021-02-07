package com.ibm.pross.client.encryption;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.client.util.RsaPublicParameters;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.RsaUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSignatureClient;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.shamir.Polynomials;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class RsaEncryptionClient extends BaseClient {

    private final String secretName;
    private final InputStream inputStream;

    private static final Logger logger = LogManager.getLogger(RsaEncryptionClient.class);

    public RsaEncryptionClient(final ServerConfiguration serverConfiguration,
                               final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
                               final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
                               InputStream inputStream) {

        super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

        this.secretName = secretName;
        this.inputStream = inputStream;
    }

    public byte[] encryptStream() throws BelowThresholdException, ResourceUnavailableException, IOException {
        logger.info("Starting RSA encryption with secret " + secretName);

        RsaPublicParameters rsaPublicParameters = this.getRsaPublicParams(secretName);

        logger.info(rsaPublicParameters);

        final byte[] plaintextData = IOUtils.toByteArray(inputStream);

//        logger.info("Encrypting message: " + Arrays.toString(plaintextData));
        BigInteger plaintext = new BigInteger(plaintextData);
        logger.info("Encrypting message: " + plaintext);

        final byte[] ciphertext = RsaUtil.rsaVerify(plaintext, rsaPublicParameters.getExponent(), rsaPublicParameters.getModulus()).toByteArray();

        logger.info("Ciphertext: " + Arrays.toString(ciphertext));

//        final byte[] ciphertext = (new String("aaa").getBytes());

//        // Ensure shareholder exists
//        final ApvssShareholder shareholder = this.shareholders.get(secretName);
//        if (shareholder == null) {
//            throw new NotFoundException();
//        }
//        // Make sure secret is not disabled
//        if (!shareholder.isEnabled()) {
//            throw new ResourceUnavailableException();
//        }
        return ciphertext;
    }

    public byte[] decryptionStream() throws IOException, BelowThresholdException, ResourceUnavailableException {
        logger.info("Starting RSA decryption with secret " + secretName);

        final byte[] ciphertextData = IOUtils.toByteArray(inputStream);
        BigInteger ciphertext = new BigInteger(ciphertextData);

        logger.info("Decrypting message: " + ciphertext);

        RsaPublicParameters rsaPublicParameters = this.getRsaPublicParams(secretName);

        final BigInteger decryptionResult = decryptThresholdRsa(ciphertext, rsaPublicParameters.getEpoch());

        return null;
    }

    private BigInteger decryptThresholdRsa(final BigInteger message, final long expectedEpoch) throws ResourceUnavailableException {
        logger.info("Performing threshold RSA decryption");

        // Server configuration
        final int numShareholders = this.serverConfiguration.getNumServers();
        final int reconstructionThreshold = this.serverConfiguration.getReconstructionThreshold();

        // We create a thread pool with a thread for each task and remote server
        final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

        // The countdown latch tracks progress towards reaching a threshold
        final CountDownLatch latch = new CountDownLatch(reconstructionThreshold);
        final AtomicInteger failureCounter = new AtomicInteger(0);
        final int maximumFailures = (numShareholders - reconstructionThreshold);

        // Each task deposits its result into this map after verifying it is correct and
        // consistent
        // TODO: Add verification via proofs
        final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
//            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/exponentiate?secretName="
//                    + this.secretName + "&x=" + inputPoint.getX() + "&y=" + inputPoint.getY() + "&json=true";
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/sign?secretName=" + this.secretName
                    + "&message=" + message.toString();

//			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/id";
//			logger.info("Performing id on server " + serverId);
//			try {
//				final URL url = new URL(linkUrl);
//				final HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
//				this.configureHttps(httpsURLConnection, serverId);
//
//				httpsURLConnection.setRequestMethod("GET");
//				httpsURLConnection.setConnectTimeout(10_000);
//				httpsURLConnection.setReadTimeout(10_000);
//
//				httpsURLConnection.connect();
//
//				try (final InputStream inputStream = httpsURLConnection.getInputStream();
//					 final InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
//					 final BufferedReader bufferedReader = new BufferedReader(inputStreamReader);) {
////            logger.debug(bufferedReader.readLine());
//					while (true) {
//						String line = bufferedReader.readLine();
//						logger.debug(line);
//						if (line == null)
//							break;
//					}
//				}
//			} catch( Exception ex){
//				logger.error(ex);
//			}

            logger.info("Requesting exponentiation of public value from server " + serverId);

            final int thisServerId = serverId;

            // Create new task to get the partial exponentiation result from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, verifiedResults, latch, failureCounter,
                    maximumFailures) {
                @Override
                protected void parseJsonResult(final String json) throws Exception {

                    // Parse JSON
                    final JSONParser parser = new JSONParser();
                    final Object obj = parser.parse(json);
                    final JSONObject jsonObject = (JSONObject) obj;
//                    final Long responder = (Long) jsonObject.get("responder");
//                    final long epoch = (Long) jsonObject.get("epoch");
//                    final JSONArray resultPoint = (JSONArray) jsonObject.get("result_point");
//                    final BigInteger x = new BigInteger((String) resultPoint.get(0));
//                    final BigInteger y = new BigInteger((String) resultPoint.get(1));

                    logger.info(json);

                    // Verify result
                    // TODO: Separate results by their epoch, wait for enough results of the same
                    // epoch
                    // TOOD: Implement retry if epoch mismatch and below threshold
//                    if ((responder == thisServerId) && (epoch == expectedEpoch)) {
//
//                        // FIXME: Do verification of the results (using proofs)
//                        final EcPoint partialResult = new EcPoint(x, y);
//
//                        // Store result for later processing
//                        verifiedResults.add(new DerivationResult(BigInteger.valueOf(responder), partialResult));
//
//                        // Everything checked out, increment successes
//                        latch.countDown();
//                    } else {
//                        throw new Exception(
//                                "Server " + thisServerId + " sent inconsistent results (likely during epoch change)");
//                    }

                }
            });
        }

        try {
            // Once we have K successful responses we can interpolate our share
            latch.await();

            // Check that we have enough results to interpolate the share
            if (failureCounter.get() <= maximumFailures) {

//                List<DerivationResult> results = verifiedResults.stream().map(obj -> createDerivationResult(obj))
//                        .collect(Collectors.toList());
//
//                // When complete, interpolate the result at zero (where the secret lies)
//                final EcPoint interpolatedResult = Polynomials.interpolateExponents(results, reconstructionThreshold,
//                        0);
                executor.shutdown();
                return null;
//                return interpolatedResult;
            } else {
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

}
