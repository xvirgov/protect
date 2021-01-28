package com.ibm.pross.client.app;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.client.app.http.HttpRequestProcessor;
import com.ibm.pross.client.app.permissions.AccessEnforcement;
import com.ibm.pross.client.app.permissions.AppPermissionLoader;
import com.ibm.pross.client.encryption.EciesEncryptionClient;
import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.util.serialization.Pem;
//import com.ibm.pross.server.app.avpss.ApvssShareholder;
//import com.ibm.pross.server.app.http.HttpRequestProcessor;
//import com.ibm.pross.server.communication.MessageDeliveryManager;
//import com.ibm.pross.server.communication.handlers.ChainBuildingMessageHandler;
//import com.ibm.pross.server.communication.pointtopoint.MessageReceiver;
//import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
//import com.ibm.pross.server.configuration.permissions.ClientPermissionLoader;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class ClientApplication extends BaseClient {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new EdDSASecurityProvider());
    }

//    public static String CONFIG_FILENAME = "common.config";
//    public static String SERVER_KEYS_DIRECTORY = "keys";
//    public static String CERTS_DIRECTORY = "certs";
//    public static String SAVE_DIRECTORY = "state";
//    public static String CLIENT_KEYS_DIRECTORY = "../client/keys";
//    public static String AUTH_DIRECTORY = "../client/clients.config";
//    public static String CA_DIRECTORY = "../ca";

    private static final Logger logger = LogManager.getLogger(EciesEncryptionClient.class);

    public ClientApplication(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
                             final KeyLoader serverKeys, final X509Certificate clientCertificate,
                             PrivateKey clientTlsKey, final X509Certificate caCertHost)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
            CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, ResourceUnavailableException, BelowThresholdException {

        super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

        final HttpRequestProcessor requestProcessor = new HttpRequestProcessor(serverConfiguration, caCertificates,
                serverKeys, clientCertificate, clientTlsKey, caCertHost);
        requestProcessor.start();
    }

    public static void main(final String[] args)
         throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
         CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException,
            ResourceUnavailableException, BelowThresholdException{
        if (args.length < 2) {
            logger.error("USAGE: config-dir client-role");
            System.exit(-1);
        }
        final File baseDirectory = new File(args[0]);
        final String clientRole = args[1];

        // Load server configuration (learn n and k)
        final File configFile = new File(baseDirectory, CONFIG_FILENAME);
        final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
        logger.info(configuration);

        // Load server keys
        final File keysDirectory = new File(baseDirectory, SERVER_KEYS_DIRECTORY);
        final KeyLoader serverKeys = new KeyLoader(keysDirectory, configuration.getNumServers(), null);

        // Load client certificate
        final File clientDirectory = new File(baseDirectory, CLIENT_DIRECTORY);
        final File certDirectory = new File(clientDirectory, CERTS_DIRECTORY);
        final File clientCertificateFile = new File(certDirectory, "cert-" + clientRole);
        final X509Certificate clientCertificate = Pem.loadCertificateFromFile(clientCertificateFile);

        // Load client key
        final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
        final File clientKeysFile = new File(clientKeysDirectory, "private-" + clientRole);
        final PrivateKey clientPrivateKey = (PrivateKey) Pem.loadKeyFromFile(clientKeysFile);

        // Load CA certificates
        final File caDirectory = new File(baseDirectory, CA_DIRECTORY);
        final List<X509Certificate> caCerts = new ArrayList<>();
        for (int i = 1; i <= configuration.getNumServers(); i++) {
            final File caCertificateFile = new File(caDirectory, "ca-cert-server-" + i + ".pem");
            caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
        }
        final File caCertificateFile = new File(caDirectory, "ca-cert-clients.pem");
        caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
        final X509Certificate caCertHost = Pem.loadCertificateFromFile(caCertificateFile);

        new ClientApplication(configuration, caCerts, serverKeys, clientCertificate, clientPrivateKey, caCertHost);
    }

//    public ClientApplication(final File baseDirectory, final int serverIndex)
//            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
//            CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
//
//        // Load configuration
//        final File configFile = new File(baseDirectory, CONFIG_FILENAME);
//        final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
//        logger.info(configuration);
//
//        // Load server keys
//        final File keysDirectory = new File(baseDirectory, SERVER_KEYS_DIRECTORY);
//        final KeyLoader serverKeys = new KeyLoader(keysDirectory, configuration.getNumServers(), serverIndex);
//        logger.info("Loaded encryption and verification keys");
//
//        // Load Client Access Controls
//        final AccessEnforcement accessEnforcement = AppPermissionLoader.loadIniFile(new File(baseDirectory, AUTH_DIRECTORY));
//
//        // Setup persistent state for message broadcast and processing
//        final List<InetSocketAddress> serverAddresses = configuration.getServerAddresses();
//        final File saveDir = new File(baseDirectory, SAVE_DIRECTORY);
//        final File serverSaveDir = new File(saveDir, "server-" + serverIndex);
//        serverSaveDir.mkdirs();
//
//        final File appKeyFile = new File(CLIENT_KEYS_DIRECTORY, "private-" + serverIndex);
//        byte[] privKeyByteArray = Files.readAllBytes(appKeyFile.toPath());
//        String privaKeyString = new String(privKeyByteArray);
//
//        if (privaKeyString.contains("BEGIN EC") || !privaKeyString.contains("BEGIN")){
//            logger.info("Provided format of key not supported, convert to PKCS8");
//            System.exit(-1);
//        }
//        privaKeyString = privaKeyString.replace("-----BEGIN PRIVATE KEY-----","");
//        privaKeyString = privaKeyString.replace("-----END PRIVATE KEY-----", "");
//        privaKeyString = privaKeyString.replaceAll("[\\r\\n]+", "").replace("\r","");
//        privKeyByteArray = Base64.getDecoder().decode(privaKeyString);
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
//        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
//        PrivateKey appPrivateKey = keyFactory.generatePrivate(keySpec);
//
////        // Wait for messages and begin processing them as they arrive
////        final int myPort = configuration.getServerAddresses().get(serverIndex - 1).getPort();
////        final MessageReceiver messageReceiver = new MessageReceiver(myPort);
////        messageReceiver.start();
////        logger.info("Listening on port: " + myPort);
////
////        // Perform basic benchmark before starting up
////        logger.info("Benchmarking Algorithms: ");
////        BenchmarkCli.runAllBenchmarks();
////
////        // Create message handler for the Certified Chain
////        final int optQuorum = (configuration.getNumServers() - configuration.getMaxLivenessFaults());
////        final ChainBuildingMessageHandler chainBuilder = new ChainBuildingMessageHandler(serverIndex, optQuorum,
////                serverKeys, serverSaveDir);
////
////        // Create message manager to manage messages received over point to point links;
////        final MessageDeliveryManager messageManager = new MessageDeliveryManager(serverAddresses, serverIndex,
////                serverKeys, serverSaveDir, chainBuilder, messageReceiver);
////        chainBuilder.setMessageManager(messageManager);
//
//        // Create Shareholder for each secret to be maintained
////        final ConcurrentMap<String, ApvssShareholder> shareholders = new ConcurrentHashMap<>();
////        final int n = configuration.getNumServers();
////        final int k = configuration.getReconstructionThreshold();
////        for (final String secretName : accessEnforcement.getKnownSecrets()) {
////            // Create Shareholder
////            logger.info("Starting APVSS Shareholder for secret: " + secretName);
////            final ApvssShareholder shareholder = new ApvssShareholder(secretName, serverKeys, chainBuilder, serverIndex,
////                    n, k);
////            shareholder.start(false); // Start the message processing thread but don't start the DKG
////            shareholders.put(secretName, shareholder);
////        }
//
//        // Wait for BFT to setup
////        while (!chainBuilder.isBftReady()) {
////            Thread.sleep(100);
////        }
////        logger.info("BFT ready.");
//
//        // Load certificates to support TLS
//        final File caDirectory = new File(baseDirectory, CA_DIRECTORY);
//        final File certDirectory = new File(baseDirectory, CERTS_DIRECTORY);
//        final File hostCertificateFile = new File(certDirectory, "cert-" + serverIndex);
//        final List<X509Certificate> caCerts = new ArrayList<>();
//        for (int i = 1; i <= configuration.getNumServers(); i++) {
//            final File caCertificateFile = new File(caDirectory, "ca-cert-server-" + i + ".pem");
//            caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
//        }
//        final File caCertificateFile = new File(caDirectory, "ca-cert-clients.pem");
//        caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
//        final X509Certificate hostCert = Pem.loadCertificateFromFile(hostCertificateFile);
//
//        // Load client authentication keys
//        final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
//        final KeyLoader clientKeys = new KeyLoader(clientKeysDirectory, accessEnforcement.getKnownUsers());
//        logger.info("Loaded client keys");
//
//        //Load Alice's cert
//        final File aliceCertDirectory = new File(baseDirectory, CERTS_DIRECTORY);
//        final File aliceCertFile = new File(aliceCertDirectory, "car-owner-cert");
//        final X509Certificate aliceCert = Pem.loadCertificateFromFile(aliceCertFile);
//        final BigInteger publicModulus = ((RSAPublicKey) aliceCert.getPublicKey()).getModulus();
//
//        // Start server to process client requests
//        final HttpRequestProcessor requestProcessor = new HttpRequestProcessor(serverIndex, configuration,
//                accessEnforcement, caCerts, hostCert, appPrivateKey, clientKeys, serverKeys, serverKeys.getTlsKey(), caCerts.get(0), null, baseDirectory);
//
////        final HttpRequestProcessor requestProcessor = new HttpRequestProcessor(serverIndex, configuration,
////                accessEnforcement, appPrivateKey, caCerts, hostCert, serverKeys.getTlsKey(), clientKeys, serverKeys);
//        requestProcessor.start();
//    }

//    public static void main(final String[] args)
//            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
//            CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
//
//        // Configure logging
//        BasicConfigurator.configure();
//        @SuppressWarnings("unchecked")
//        final List<Logger> loggers = Collections.<Logger>list(LogManager.getCurrentLoggers());
//        loggers.add(LogManager.getRootLogger());
//        for (Logger logger : loggers) {
//            logger.setLevel(Level.OFF);
//        }
//
//        // Delete BFT SMaRt's cache of the view
//        final File configPath = new File("config");
//        final File cachedView = new File(configPath, "currentView");
//        cachedView.delete();
//
//        // Print launch configuration
//        logger.info(Arrays.toString(args));
//
//        // Parse arguments
//        if (args.length < 2) {
//            logger.error.println("USAGE: config-dir server-index");
//            System.exit(-1);
//        }
//        final File baseDirectory = new File(args[0]);
//        final int serverIndex = Integer.parseInt(args[1]);
//
//        // Start server
//        new ClientApplication(baseDirectory, serverIndex);
//    }

}