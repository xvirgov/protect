package com.ibm.pross.common.config;

import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcCurveBc;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class ServerConfigurationLoader {

	public static final String NUM_SERVERS_KEY = "num_servers";
	public static final String REFRESH_FREQUENCY_KEY = "refresh_frequency";
	public static final String SECURITY_LEVEL = "security_level";
	public static final String MAX_BFT_FAULTS_KEY = "max_bft_faults";
	public static final String RECONSTRUCT_THRESHOLD_KEY = "reconstruction_threshold";
	public static final String MAX_SAFETY_FAULTS_KEY = "max_safety_faults";
	public static final String MAX_LIVENESS_FAULTS_KEY = "max_liveness_faults";
	public static final String NUM_SERVERS_KEY_PREFIX = "server.";

	public static ServerConfiguration load(final File configFile) throws IOException {

		final Properties properties = new Properties();

		final FileInputStream inputStream = new FileInputStream(configFile);

		// Load the properties file
		properties.load(inputStream);

		// Parse the number of servers
		final int numServers = Integer.parseInt(properties.getProperty(NUM_SERVERS_KEY));

		// Compute default properties from numServers
		final String defaultReconstructionThreshold = Integer.toString(((numServers - 1) / 2) + 1);
		final String defaultMaxBftFaults = Integer.toString((numServers - 1) / 3);

		// Get the reconstruction threshold from the file or from the default value
		final int reconstructionThreshold = Integer
				.parseInt(properties.getProperty(RECONSTRUCT_THRESHOLD_KEY, defaultReconstructionThreshold));

		final int refreshFrequency = Integer.parseInt(properties.getProperty(REFRESH_FREQUENCY_KEY, "60"));

		final int securityLevel = Integer.parseInt(properties.getProperty(SECURITY_LEVEL, "128"));

		// SETUP key sizes
		if(securityLevel == 128) {
			CommonConfiguration.RSA_KEY_SIZE = 3076;
			CommonConfiguration.CURVE = EcCurveBc.createByName(EcCurve.secp256r1.getName());
			CommonConfiguration.KYBER_K = 2;
		}
		else if(securityLevel == 156) {
			CommonConfiguration.RSA_KEY_SIZE = 4096;
			CommonConfiguration.CURVE = EcCurveBc.createByName(EcCurve.secp384r1.getName());
			CommonConfiguration.KYBER_K = 3;
		}
		else if (securityLevel == 192) {
			CommonConfiguration.RSA_KEY_SIZE = 4096;
			CommonConfiguration.CURVE = EcCurveBc.createByName(EcCurve.secp384r1.getName());
			CommonConfiguration.KYBER_K = 3;
		}
		else if (securityLevel == 256) {
			CommonConfiguration.RSA_KEY_SIZE = 4096;
			CommonConfiguration.CURVE = EcCurveBc.createByName(EcCurve.secp521r1.getName());
			CommonConfiguration.KYBER_K = 4;
		}

		CommonConfiguration.g = CommonConfiguration.CURVE.getPointHasher().hashToCurve(new byte[] { 0x01 });
		CommonConfiguration.h = CommonConfiguration.CURVE.getPointHasher().hashToCurve(new byte[] { 0x02 });

		// Compute default properties from reconstructionThreshold
		final String defaultMaxSafetyFaults = Integer.toString(reconstructionThreshold - 1);

		// Get the max safety faults from the file or from the default value
		final int maxSafetyFaults = Integer
				.parseInt(properties.getProperty(MAX_SAFETY_FAULTS_KEY, defaultMaxSafetyFaults));

		// Compute the default properties from maxSafetyFaults
		final String defaultMaxLivenessFaults = Integer.toString((numServers - maxSafetyFaults - 1) / 2);

		// Get the max liveness faults from the file or from the default value
		final int maxLivenessFaults = Integer
				.parseInt(properties.getProperty(MAX_LIVENESS_FAULTS_KEY, defaultMaxLivenessFaults));

		// Get the max bft faults from the file or from the default value
		final int maxBftFaults = Integer.parseInt(properties.getProperty(MAX_BFT_FAULTS_KEY, defaultMaxBftFaults));

		// Load each server's address
		final List<InetSocketAddress> serverAddresses = new ArrayList<>(numServers);
		for (int i = 1; i <= numServers; i++) {
			final String hostPort = properties.getProperty(NUM_SERVERS_KEY_PREFIX + i);
			final String[] parts = hostPort.split(":");
			final String host = parts[0];
			final int port = Integer.parseInt(parts[1]);
			final InetSocketAddress serverAddress = new InetSocketAddress(host, port);
			serverAddresses.add(serverAddress);
		}

		inputStream.close();

		return new ServerConfiguration(numServers, maxBftFaults, reconstructionThreshold, maxSafetyFaults,
				maxLivenessFaults, serverAddresses, refreshFrequency);
	}

}
