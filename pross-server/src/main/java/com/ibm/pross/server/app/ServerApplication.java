package com.ibm.pross.server.app;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.communication.MessageDeliveryManager;
import com.ibm.pross.server.communication.handlers.ChainBuildingMessageHandler;
import com.ibm.pross.server.communication.pointtopoint.MessageReceiver;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissionLoader;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class ServerApplication {

	static {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new EdDSASecurityProvider());
	}

	public static String CONFIG_FILENAME = "common.config";
	public static String SERVER_KEYS_DIRECTORY = "keys";
	public static String CERTS_DIRECTORY = "certs";
	public static String SAVE_DIRECTORY = "state";
	public static String CLIENT_KEYS_DIRECTORY = "../client/keys";
	public static String AUTH_DIRECTORY = "../client/clients.config";
	public static String CA_DIRECTORY = "../ca";

	private static final Logger logger = LogManager.getLogger(ServerApplication.class);

	public ServerApplication(final File baseDirectory, final int serverIndex)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
			CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {

		long overall_start, overall_end;
		long start, end;

		// Load configuration
		overall_start = System.nanoTime();
		start = System.nanoTime();
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
		logger.info(configuration);
		end = System.nanoTime();
		logger.info("PerfMeas:InitConfigLoad:"+ (end-start));

		// Load server keys
		start = System.nanoTime();
		final File keysDirectory = new File(baseDirectory, SERVER_KEYS_DIRECTORY);
		final KeyLoader serverKeys = new KeyLoader(keysDirectory, configuration.getNumServers(), serverIndex);
		end = System.nanoTime();
		logger.info("Loaded encryption and verification keys");
		logger.info("PerfMeas:InitServerKeysLoad:"+ (end-start));

		// Load Client Access Controls
		start = System.nanoTime();
		final AccessEnforcement accessEnforcement = ClientPermissionLoader.loadIniFile(new File(baseDirectory, AUTH_DIRECTORY));
		end = System.nanoTime();
		logger.info("PerfMeas:InitAccessControlLoad:"+ (end-start));

		// Setup persistent state for message broadcast and processing
		start = System.nanoTime();
		final List<InetSocketAddress> serverAddresses = configuration.getServerAddresses();
		final File saveDir = new File(baseDirectory, SAVE_DIRECTORY);
		final File serverSaveDir = new File(saveDir, "server-" + serverIndex);
		serverSaveDir.mkdirs();
		end = System.nanoTime();
		logger.info("PerfMeas:InitPersistState:"+ (end-start));

		// Wait for messages and begin processing them as they arrive
		start = System.nanoTime();
		final int myPort = configuration.getServerAddresses().get(serverIndex - 1).getPort();
		final MessageReceiver messageReceiver = new MessageReceiver(myPort);
		messageReceiver.start();
		logger.info("Listening on port: " + myPort);
		end = System.nanoTime();
		logger.info("PerfMeas:InitMessageReceiver:"+ (end-start));

		// Perform basic benchmark before starting up
		logger.info("Benchmarking Algorithms: ");
		start = System.nanoTime();
		BenchmarkCli.runAllBenchmarks();
		end = System.nanoTime();
		logger.info("PerfMeas:InitBench:"+ (end-start));

		// Create message handler for the Certified Chain
		start = System.nanoTime();
		final int optQuorum = (configuration.getNumServers() - configuration.getMaxLivenessFaults());
		final ChainBuildingMessageHandler chainBuilder = new ChainBuildingMessageHandler(serverIndex, optQuorum,
				serverKeys, serverSaveDir);

		// Create message manager to manage messages received over point to point links;
		final MessageDeliveryManager messageManager = new MessageDeliveryManager(serverAddresses, serverIndex,
				serverKeys, serverSaveDir, chainBuilder, messageReceiver);
		chainBuilder.setMessageManager(messageManager);
		end = System.nanoTime();
		logger.info("PerfMeas:InitBftChannel:"+ (end-start));

		// Create Shareholder for each secret to be maintained
		start = System.nanoTime();
		final ConcurrentMap<String, ApvssShareholder> shareholders = new ConcurrentHashMap<>();
		final int n = configuration.getNumServers();
		final int k = configuration.getReconstructionThreshold();
		for (final String secretName : accessEnforcement.getKnownSecrets()) {
			// Create Shareholder
			logger.info("Starting APVSS Shareholder for secret: " + secretName);
			final ApvssShareholder shareholder = new ApvssShareholder(secretName, serverKeys, chainBuilder, serverIndex,
					n, k, configuration.getRefreshFrequency());
			shareholder.start(false); // Start the message processing thread but don't start the DKG
			shareholders.put(secretName, shareholder);
		}
		end = System.nanoTime();
		logger.info("PerfMeas:InitSecrets:"+ (end-start));

		// Wait for BFT to setup
		while (!chainBuilder.isBftReady()) {
			Thread.sleep(100);
		}
		logger.info("BFT ready.");

		// Load certificates to support TLS
		start = System.nanoTime();
		final File caDirectory = new File(baseDirectory, CA_DIRECTORY);
		final File certDirectory = new File(baseDirectory, CERTS_DIRECTORY);
		final File hostCertificateFile = new File(certDirectory, "cert-" + serverIndex);
		final List<X509Certificate> caCerts = new ArrayList<>();
		for (int i = 1; i <= configuration.getNumServers(); i++) {
			final File caCertificateFile = new File(caDirectory, "ca-cert-server-" + i + ".pem");
			caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
		}
		final File caCertificateFile = new File(caDirectory, "ca-cert-clients.pem");
		caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
		final X509Certificate hostCert = Pem.loadCertificateFromFile(hostCertificateFile);

		// Load client authentication keys
		final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
		final KeyLoader clientKeys = new KeyLoader(clientKeysDirectory, accessEnforcement.getKnownUsers());
		logger.info("Loaded client keys");
		end = System.nanoTime();
		logger.info("PerfMeas:InitTlsKeys:"+ (end-start));

		start = System.nanoTime();
		// Start server to process client requests
		final HttpRequestProcessor requestProcessor = new HttpRequestProcessor(serverIndex, configuration,
				accessEnforcement, shareholders, caCerts, hostCert, serverKeys.getTlsKey(), clientKeys, serverKeys);
		end = System.nanoTime();
		logger.info("PerfMeas:InitTlsSessions:"+ (end-start));
		overall_end = System.nanoTime();
		logger.info("PerfMeas:InitOverall:"+ (overall_end-overall_start));

		requestProcessor.start();

	}

	public static void main(final String[] args)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
			CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		
		// Configure logging
//		BasicConfigurator.configure();
//		@SuppressWarnings("unchecked")
//		final List<Logger> loggers = Collections.<Logger>list(LogManager.getCurrentLoggers());
//		loggers.add(LogManager.getRootLogger());
//		for (Logger logger : loggers) {
//			logger.setLevel(Level.OFF);
//		}

		// Delete BFT SMaRt's cache of the view
		final File configPath = new File("config");
		final File cachedView = new File(configPath, "currentView");
		cachedView.delete();

		// Print launch configuration
		logger.info(Arrays.toString(args));

		// Parse arguments
		if (args.length < 2) {
			logger.error("USAGE: config-dir server-index");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final int serverIndex = Integer.parseInt(args[1]);

		// Start server
		new ServerApplication(baseDirectory, serverIndex);
	}

}
