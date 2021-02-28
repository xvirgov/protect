package com.ibm.pross.client.util;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.ibm.pross.common.util.SecretShare;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class BaseClient {

    private static final Logger logger = LogManager.getLogger(BaseClient.class);
    // Default paths
    public static String CONFIG_FILENAME = "server/common.config";
    public static String SERVER_KEYS_DIRECTORY = "server/keys";
    public static String CLIENT_DIRECTORY = "client";
    public static String CLIENT_KEYS_DIRECTORY = "client/keys";
    public static String CA_DIRECTORY = "ca";
    public static String CERTS_DIRECTORY = "certs";

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new EdDSASecurityProvider());
    }

    // For connecting to servers
    protected final ServerConfiguration serverConfiguration;

    // For authenticating the servers
    protected final List<X509Certificate> caCertificates;
    protected final KeyLoader serverKeys;

    // For loading our own private key and certificate
    protected final X509Certificate clientCertificate;
    protected final PrivateKey clientTlsKey;

    /**
     * Constructor for base clients. This requires the minimum configuration
     * information for a client to connect to the servers, authenticate them, and
     * authenticate to them using client credentials.
     *
     * @param serverConfiguration
     * @param caCertificates
     * @param serverKeys
     * @param clientCertificate
     * @param clientTlsKey
     */
    public BaseClient(ServerConfiguration serverConfiguration, List<X509Certificate> caCertificates,
                      KeyLoader serverKeys, X509Certificate clientCertificate, PrivateKey clientTlsKey) {
        super();
        this.serverConfiguration = serverConfiguration;
        this.caCertificates = caCertificates;
        this.serverKeys = serverKeys;
        this.clientCertificate = clientCertificate;
        this.clientTlsKey = clientTlsKey;
    }

    protected void configureHttps(final HttpsURLConnection httpsConnection, final int remoteServerId)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException, KeyManagementException {

        // Configure SSL context
        final SSLContext sslContext = SSLContext.getInstance(CommonConfiguration.TLS_VERSION);

        // Create in-memory key store
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        final char[] password = "password".toCharArray();
        keyStore.load(null, password);

        // Add the CA certificate for the server
        keyStore.setCertificateEntry("ca-" + remoteServerId, this.caCertificates.get(remoteServerId - 1));

        // Add certificate and private key for the server
        // Note: Client CA cert is last after all the servers
        final X509Certificate ourCaCert = this.caCertificates.get(this.serverConfiguration.getNumServers());
        keyStore.setKeyEntry("host", this.clientTlsKey, password,
                new X509Certificate[]{clientCertificate, ourCaCert});

        // Make Key Manager Factory
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, password);

        // Setup the trust manager factory
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        // Initialize the context
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Get the socket factory from the context
        httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
    }

    protected Object getConsistentConfiguration(final Collection<Object> configurationData, int threshold)
            throws BelowThresholdException {

        // Count up the number of consistencies among the configurations
        final Map<Object, Integer> voteTracker = new HashMap<>();

        synchronized (configurationData) {
            for (final Object object : configurationData) {
                if (!voteTracker.containsKey(object)) {
                    voteTracker.put(object, 1);
                } else {
                    Integer currentCount = voteTracker.get(object);
                    voteTracker.put(object, Integer.valueOf(currentCount + 1));
                }
            }
        }

        // Determine which view is the most consistent
        Object mostCommonConfig = null;
        int maxConsistencies = 0;
        for (Entry<Object, Integer> entry : voteTracker.entrySet()) {
            if (entry.getValue() > maxConsistencies) {
                maxConsistencies = entry.getValue();
                mostCommonConfig = entry.getKey();
            }
        }

        // Ensure there is at least a threshold agreement
        if (maxConsistencies < threshold) {
            ;
            for (Object o : configurationData) {
                logger.info(" --- " + o);
            }
            throw new BelowThresholdException("Insufficient consistency to permit recovery (below threshold)");
        }

        return mostCommonConfig;
    }

    /**
     * Interacts with the servers to determine the public key of the secret (by
     * majority vote)
     *
     * @param inputPoint
     * @return
     * @throws ResourceUnavailableException
     * @throws BelowThresholdException
     */
    @SuppressWarnings("unchecked")
    protected SimpleEntry<List<EcPoint>, Long> getServerVerificationKeys(final String secretName)
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
        final List<Object> collectedResults = Collections.synchronizedList(new ArrayList<>());

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?secretName=" + secretName
                    + "&json=true";

            final int thisServerId = serverId;

            // Create new task to get the secret info from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, collectedResults, latch, failureCounter,
                    maximumFailures) {
                @Override
                protected void parseJsonResult(final String json) throws Exception {

                    // Parse JSON
                    final JSONParser parser = new JSONParser();
                    final Object obj = parser.parse(json);
                    final JSONObject jsonObject = (JSONObject) obj;
                    final Long responder = (Long) jsonObject.get("responder");
                    final long epoch = (Long) jsonObject.get("epoch");
                    final List<EcPoint> verificationKeys = new ArrayList<>();

                    final JSONArray publicKeyPoint = (JSONArray) jsonObject.get("public_key");
                    final BigInteger x = new BigInteger((String) publicKeyPoint.get(0));
                    final BigInteger y = new BigInteger((String) publicKeyPoint.get(1));
                    verificationKeys.add(new EcPoint(x, y));
                    for (int i = 1; i <= numShareholders; i++) {
                        final JSONArray verificationKey = (JSONArray) jsonObject.get("share_verification_key_" + i);
                        final BigInteger x2 = new BigInteger((String) verificationKey.get(0));
                        final BigInteger y2 = new BigInteger((String) verificationKey.get(1));
                        verificationKeys.add(new EcPoint(x2, y2));
                    }

                    // Store parsed result
                    if ((responder == thisServerId)) {

                        // Store result for later processing
                        collectedResults.add(new SimpleEntry<List<EcPoint>, Long>(verificationKeys, epoch));

                        // Everything checked out, increment successes
                        latch.countDown();
                    } else {
                        throw new Exception("Server " + thisServerId + " sent inconsistent results");
                    }

                }
            });
        }

        try {
            // Once we have K successful responses we attempt to find a consistent
            // configuration
            // FIXME: There is a better way of doing this, map result to a counter, wait for
            // counter to reach majority (or fail)
            // if not enough remaining responses permit getting a majority
            latch.await();

            // Check that we have enough results to interpolate the share
            if (failureCounter.get() <= maximumFailures) {

                executor.shutdown();

                return (SimpleEntry<List<EcPoint>, Long>) getConsistentConfiguration(collectedResults,
                        reconstructionThreshold);
            } else {
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Interacts with the servers to determine the public key of the secret (by
     * majority vote)
     *
     * @param inputPoint
     * @return
     * @throws ResourceUnavailableException
     * @throws BelowThresholdException
     */
    @SuppressWarnings("unchecked")
    protected RsaPublicParameters getRsaPublicParams(final String secretName)
            throws ResourceUnavailableException, BelowThresholdException {

        logger.debug("Starting retrieval of the RSA Public params from secret " + secretName);

        // Server configuration
        final int numShareholders = this.serverConfiguration.getNumServers();
        final int reconstructionThreshold = this.serverConfiguration.getReconstructionThreshold();

        // We create a thread pool with a thread for each task and remote server
        final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

        // The countdown latch tracks progress towards reaching a threshold
        final CountDownLatch latch = new CountDownLatch(reconstructionThreshold);

        logger.debug("Wait until at least " + reconstructionThreshold + " servers respond");

        final AtomicInteger failureCounter = new AtomicInteger(0);
        final int maximumFailures = (numShareholders - reconstructionThreshold);

        // Each task deposits its result into this map after verifying it is correct and
        // consistent

        final Map<RsaPublicParameters, Integer> rsaPublicParametersCount = Collections.synchronizedMap(new HashMap<>());

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?cipher=rsa&secretName=" + secretName + "&json=true";

            final int thisServerId = serverId;

            // Create new task to get the secret info from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, rsaPublicParametersCount, latch, failureCounter,
                    maximumFailures) {
                @Override
                protected void parseJsonResult(final String json) throws Exception {
                    final JSONParser parser = new JSONParser();
                    final Object obj = parser.parse(json);
                    final JSONObject jsonObject = (JSONObject) obj;


                    final Long responder = Long.parseLong(jsonObject.get("responder").toString());
                    final long epoch = Long.parseLong(jsonObject.get("epoch").toString());
                    final BigInteger publicExponent = new BigInteger((String) jsonObject.get("public_key"));
                    final BigInteger publicModulus = new BigInteger((String) jsonObject.get("public_modulus"));
                    final BigInteger verificationKey = new BigInteger((String) jsonObject.get("v"));

                    List<BigInteger> shareVerificationKeys = new ArrayList<>();

                    for (int i = 1; i <= numShareholders; i++) {
                        shareVerificationKeys.add(new BigInteger((String) jsonObject.get("share_verification_key_" + i)));
                    }

                    if ((responder == thisServerId)) {

                        RsaPublicParameters rsaPublicParameters = new RsaPublicParameters(publicExponent, publicModulus, verificationKey, shareVerificationKeys, epoch);

                        // Add parameters to the hashmap
                        if (!rsaPublicParametersCount.containsKey(rsaPublicParameters)) {
                            rsaPublicParametersCount.put(rsaPublicParameters, 1);
                        } else {
                            rsaPublicParametersCount.put(rsaPublicParameters, rsaPublicParametersCount.get(rsaPublicParameters) + 1);
                        }

                        // Everything checked out, increment successes
                        latch.countDown();
                    } else {
                        throw new Exception("Server " + thisServerId + " sent inconsistent results");
                    }

                }
            });
        }

        try {
            latch.await();

            // Check that we have enough results to interpolate the share
            if (failureCounter.get() <= maximumFailures) {

                executor.shutdown();
                // Use the config which was returned by more than threshold number of servers

                int maxWait = 10;
                while (rsaPublicParametersCount.values().stream().reduce(0, Integer::sum) < this.serverConfiguration.getNumServers() && maxWait-- > 0) {
                    for (Map.Entry<RsaPublicParameters, Integer> params : rsaPublicParametersCount.entrySet()) {
                        if (params.getValue() >= reconstructionThreshold) {
                            logger.info("Consistency level reached.");
                            return params.getKey();
                        }
                    }
                    logger.info("Waiting for more servers to send config...");
                    Thread.sleep(2000);
                }

                throw new BelowThresholdException("Timeout: insufficient consistency to permit recovery (below threshold)");
            } else {
                logger.error("Number of failures exceeded the threshold");
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Interacts with the servers to determine the public key of the secret (by
     * majority vote)
     *
     * @param inputPoint
     * @return
     * @throws ResourceUnavailableException
     * @throws BelowThresholdException
     */
    @SuppressWarnings("unchecked")
    protected ProactiveRsaPublicParameters getProactiveRsaPublicParams(final String secretName)
            throws ResourceUnavailableException, BelowThresholdException {

        logger.info("Starting retrieval of the proactive RSA Public params from secret " + secretName);

        // Server configuration
        final int numShareholders = this.serverConfiguration.getNumServers();
        final int reconstructionThreshold = this.serverConfiguration.getReconstructionThreshold();

        // We create a thread pool with a thread for each task and remote server
        final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

        // The countdown latch tracks progress towards reaching a threshold
        final CountDownLatch latch = new CountDownLatch(reconstructionThreshold);

        logger.info("Wait until at least " + reconstructionThreshold + " servers respond");

        final AtomicInteger failureCounter = new AtomicInteger(0);
        final int maximumFailures = (numShareholders - reconstructionThreshold);

        // Each task deposits its result into this map after verifying it is correct and
        // consistent

        final Map<ProactiveRsaPublicParameters, Integer> rsaPublicParametersCount = Collections.synchronizedMap(new HashMap<>());

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?cipher=proactive-rsa&secretName=" + secretName + "&json=true";

            logger.info(linkUrl);

            final int thisServerId = serverId;

            // Create new task to get the secret info from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, rsaPublicParametersCount, latch, failureCounter,
                    maximumFailures, 1) {
                @Override
                protected void parseJsonResult(final String json) throws Exception {
                    logger.info("Parsing response...");
                    final JSONParser parser = new JSONParser();
                    final Object obj = parser.parse(json);
                    final JSONObject jsonObject = (JSONObject) obj;


                    final Long responder = Long.parseLong(jsonObject.get("responder").toString()); // TODO-now json->publicRsaParams
                    final long epoch = Long.parseLong(jsonObject.get("epoch").toString());
                    final BigInteger publicExponent = new BigInteger((String) jsonObject.get("public_key"));
                    final BigInteger publicModulus = new BigInteger((String) jsonObject.get("public_modulus"));
                    final BigInteger g = new BigInteger((String) jsonObject.get("g"));
                    final BigInteger d_pub = new BigInteger((String) jsonObject.get("d_pub"));

                    List<List<SecretShare>> feldmanAdditiveVerificationValues = new ArrayList<>();
                    List<SecretShare> additiveVerificationKeys = new ArrayList<>();

                    for (int i = 0; i < numShareholders; i++) {
                        JSONArray feldmanAdditiveVerificationValuesArray = (JSONArray) jsonObject.get("b_" + (i + 1));
                        List<SecretShare> collector = new ArrayList<>();
                        for (int j = 0; j < reconstructionThreshold; j++) {
                            collector.add(new SecretShare(BigInteger.valueOf(j + 1), new BigInteger((String) feldmanAdditiveVerificationValuesArray.get(j))));
                        }
                        feldmanAdditiveVerificationValues.add(collector);
                    }

                    JSONArray additiveVerificationKeysArray = (JSONArray) jsonObject.get("additiveVerificationKeys");
                    for (int i = 0; i < numShareholders; i++) {
                        additiveVerificationKeys.add(new SecretShare(BigInteger.valueOf(i + 1), new BigInteger((String) additiveVerificationKeysArray.get(i))));
                    }

                    if ((responder == thisServerId)) {

                        ProactiveRsaPublicParameters proactiveRsaPublicParameters = new ProactiveRsaPublicParameters(publicExponent, publicModulus, g, d_pub, feldmanAdditiveVerificationValues, additiveVerificationKeys, epoch);

                        // Add parameters to the hashmap
                        if (!rsaPublicParametersCount.containsKey(proactiveRsaPublicParameters)) {
                            rsaPublicParametersCount.put(proactiveRsaPublicParameters, 1);
                        } else {
                            rsaPublicParametersCount.put(proactiveRsaPublicParameters, rsaPublicParametersCount.get(proactiveRsaPublicParameters) + 1);
                        }

                        // Everything checked out, increment successes
                        latch.countDown();
                    } else {
                        throw new Exception("Server " + thisServerId + " sent inconsistent results");
                    }

                }
            });
        }

        try {
            latch.await();

            // Check that we have enough results to interpolate the share
            if (failureCounter.get() <= maximumFailures) {

                executor.shutdown();
                // Use the config which was returned by more than threshold number of servers

                int maxWait = 10;
                while (rsaPublicParametersCount.values().stream().reduce(0, Integer::sum) < this.serverConfiguration.getNumServers() && maxWait-- > 0) {
                    for (Map.Entry<ProactiveRsaPublicParameters, Integer> params : rsaPublicParametersCount.entrySet()) {
                        if (params.getValue() >= reconstructionThreshold) {
                            logger.info("Consistency level reached.");
                            return params.getKey();
                        }
                    }
                    logger.info("Waiting for more servers to send config...");
                    Thread.sleep(2000);
                }

                throw new BelowThresholdException("Timeout: insufficient consistency to permit recovery (below threshold)");
            } else {
                logger.error("Number of failures exceeded the threshold");
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
