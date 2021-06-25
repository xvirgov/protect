package com.ibm.pross.client.generation;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaPublicParameters;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaProactiveSharing;
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
import java.util.stream.Collectors;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;


/**
 * Performs generation and storage of RSA private key shares
 */
public class ProactiveRsaKeyGeneratorClient extends BaseClient {

    private static final Logger logger = LogManager.getLogger(ProactiveRsaKeyGeneratorClient.class);

    // Default paths
    public static String CONFIG_FILENAME = "server/common.config";
    public static String SERVER_KEYS_DIRECTORY = "server/keys";
    public static String CLIENT_DIRECTORY = "client";
    public static String CLIENT_KEYS_DIRECTORY = "client/keys";
    public static String CA_DIRECTORY = "ca";
    public static String CERTS_DIRECTORY = "certs";

        // Parameters of operation
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

    public ProactiveRsaKeyGeneratorClient(final ServerConfiguration serverConfiguration,
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

        long start, end;
        long start_total, end_total;


        start = System.nanoTime();
        start_total = System.nanoTime();
        final List<ProactiveRsaShareholder> proactiveRsaShareholders = ProactiveRsaGenerator.generateProactiveRsa(numServers, threshold);
        end = System.nanoTime();
        logger.info("PerfMeas:RsaGenEnd:" + (end - start));
        logger.info("RSA key generation complete");

        logger.info("Storing RSA private key");
        start = System.nanoTime();
        boolean stored = this.storeProactiveRsaSharing(proactiveRsaShareholders);
        end = System.nanoTime();
        end_total = System.nanoTime();
        logger.info("PerfMeas:RsaStoreEnd:" + (end - start));
        logger.info("PerfMeas:RsaGenTotal:" + (end_total - start_total));

        // Calculate overall size



        return stored;
    }

    public boolean generateRsaKeysNoRefresh() throws InvalidKeySpecException, NoSuchAlgorithmException, BelowThresholdException, ResourceUnavailableException {
        // Get n and t
        final int numServers = serverConfiguration.getNumServers();
        final int threshold = serverConfiguration.getReconstructionThreshold();

        long start, end;
        long start_total, end_total;


        start = System.nanoTime();
        start_total = System.nanoTime();
        final List<ProactiveRsaShareholder> proactiveRsaShareholders = ProactiveRsaGenerator.generateProactiveRsa(numServers, threshold);
        end = System.nanoTime();
        logger.info("PerfMeas:RsaGenEnd:" + (end - start));
        logger.info("RSA key generation complete");

        logger.info("Storing RSA private key");
        start = System.nanoTime();
        boolean stored = this.storeRsaSharing(proactiveRsaShareholders);
        end = System.nanoTime();
        end_total = System.nanoTime();
        logger.info("PerfMeas:RsaStoreEnd:" + (end - start));
        logger.info("PerfMeas:RsaGenTotal:" + (end_total - start_total));

        return stored;
    }

    private Boolean storeRsaSharing(final List<ProactiveRsaShareholder> proactiveRsaShareholders)
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
        final List<Object> successfulResults = Collections.synchronizedList(new ArrayList<>());

        // Send the generator to the server
        final BigInteger v = null;

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) { // TODO-now agent->json
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

            final JSONObject message = proactiveRsaShareholders.get(serverId-1).getJson();

            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/store" + // TODO-now move all to json body
                    "?secretName=" + this.secretName
                    + "&sharingType=rsa";

            // Create new task to get the partial exponentiation result from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, message.toJSONString() + "\n", "POST", successfulResults, latch, failureCounter,
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

    private Boolean storeProactiveRsaSharing(final List<ProactiveRsaShareholder> proactiveRsaShareholders)
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
        final List<Object> successfulResults = Collections.synchronizedList(new ArrayList<>());

        // Send the generator to the server
        final BigInteger v = null;

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) { // TODO-now agent->json
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

            final JSONObject message = proactiveRsaShareholders.get(serverId-1).getJson();

            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/store" + // TODO-now move all to json body
                    "?secretName=" + this.secretName
                    + "&sharingType=proactive-rsa";

            // Create new task to get the partial exponentiation result from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, message.toJSONString() + "\n", "POST", successfulResults, latch, failureCounter,
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
