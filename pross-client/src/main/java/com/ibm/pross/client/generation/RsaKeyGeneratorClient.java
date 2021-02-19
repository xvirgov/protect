package com.ibm.pross.client.generation;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Performs generation and storage of RSA private key shares
 */
public class RsaKeyGeneratorClient extends BaseClient {

    private static final Logger logger = LogManager.getLogger(RsaKeyGeneratorClient.class);

    // Default paths
    public static String CONFIG_FILENAME = "server/common.config";
    public static String SERVER_KEYS_DIRECTORY = "server/keys";
    public static String CLIENT_DIRECTORY = "client";
    public static String CLIENT_KEYS_DIRECTORY = "client/keys";
    public static String CA_DIRECTORY = "ca";
    public static String CERTS_DIRECTORY = "certs";

    //    // Parameters of operation
    private final String secretName;
//    private final File caFile;
//
//    // Unique parameters for generating
//    private final String issuerDn;
//
//    // Unique parameters for issuing
//    private final File publicKeyFile;
//    private final File certificateOutputFile;
//    private final String subjectDn;

    public RsaKeyGeneratorClient(final ServerConfiguration serverConfiguration,
                                 final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
                                 final X509Certificate clientCertificate, final PrivateKey clientTlsKey, final String secretName) {

        super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

        this.secretName = secretName;
    }

    /**
     * @brief Generates RSA key shares and stores them at the servers
     */
    public boolean generateRsaKeys() throws InvalidKeySpecException, NoSuchAlgorithmException, BelowThresholdException, ResourceUnavailableException {
        // Get n and t
        final int numServers = serverConfiguration.getNumServers();
        final int threshold = serverConfiguration.getReconstructionThreshold();

//        logger.info("Generating threshold RSA keys with parameters: [number of private key shares : " + numServers + ", threshold: " + threshold + "]");
        final RsaSharing rsaSharing = RsaSharing.generateSharing(numServers, threshold);
        logger.info("RSA key generation complete");

        logger.info("Storing RSA private key");
        return this.storeRsaSharing(rsaSharing);
    }

    /**
     * Interacts with the servers to store an RSA sharing to a given secret
     *
     * @param rsaSharing
     * @return
     * @throws ResourceUnavailableException
     * @throws BelowThresholdException
     */
    private Boolean storeRsaSharing(final RsaSharing rsaSharing)
            throws ResourceUnavailableException, BelowThresholdException {

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
        final List<Object> successfulResults = Collections.synchronizedList(new ArrayList<>());

        // Collect pulic data to register with servers

        // Send the public exponenet to the server
        final BigInteger exponent = rsaSharing.getPublicKey().getPublicExponent();

        // Send the modulus to the server
        final BigInteger modulus = rsaSharing.getPublicKey().getModulus();

        // Send the generator to the server
        final BigInteger v = rsaSharing.getV();

        StringBuilder allVerificationKeys = new StringBuilder();
        for (int i = 1; i <= this.serverConfiguration.getNumServers(); i++) {
            allVerificationKeys.append("&v_" + i + "=" + rsaSharing.getVerificationKeys()[i - 1]);
        }

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

            // Send share to the server
            final BigInteger share = rsaSharing.getShares()[serverId - 1].getY();

            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/store?secretName=" + this.secretName
                    + "&e=" + exponent + "&n=" + modulus + "&v=" + v + allVerificationKeys.toString() + "&share="
                    + share;

            logger.info("Share: " + share);

            // Create new task to get the partial exponentiation result from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, successfulResults, latch, failureCounter,
                    maximumFailures) {
                @Override
                protected void parseJsonResult(final String json) throws Exception {

                    // Store result for later processing
                    successfulResults.add(Boolean.TRUE);

                    // Everything checked out, increment successes
                    latch.countDown();

                }
            });
        }

        try {
            // Once we have K successful responses we can interpolate our share
            latch.await();

            // Check that we have enough results to interpolate the share
            if (failureCounter.get() <= maximumFailures) {

                // When complete, interpolate the result at zero (where the secret lies)
                final Boolean wereSuccessful = (Boolean) getConsistentConfiguration(successfulResults,
                        reconstructionThreshold);
                executor.shutdown();

                return wereSuccessful;
            } else {
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

}
