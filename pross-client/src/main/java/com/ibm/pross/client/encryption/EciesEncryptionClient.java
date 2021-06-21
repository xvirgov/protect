package com.ibm.pross.client.encryption;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SortedMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.net.ssl.HttpsURLConnection;

import com.ibm.pross.client.util.EciesPublicParams;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.serialization.Parse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.elgamal.EciesEncryption;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.common.util.shamir.Polynomials;

import org.apache.commons.io.IOUtils;

/**
 * Performs ECIES (Elliptic Curve based ElGamal Encryption and Decryption of
 * files used a distributed secret key)
 */
public class EciesEncryptionClient extends BaseClient {

	// Parameters of operation
	private final String secretName;
	private File inputFile;
	private File outputFile;
	private InputStream inputStream;

	private static final Logger logger = LogManager.getLogger(EciesEncryptionClient.class);

	public EciesEncryptionClient(final ServerConfiguration serverConfiguration,
			final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
			final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
			final File inputFile, final File outputFile) {

		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

		this.secretName = secretName;
		this.inputFile = inputFile;
		this.outputFile = outputFile;
	}

	public EciesEncryptionClient(final ServerConfiguration serverConfiguration,
								 final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
								 final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
								 InputStream inputStream) {

		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

		this.secretName = secretName;
		this.inputStream = inputStream;
	}

	public void encryptFile() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException {

		// Print status
		logger.info("-----------------------------------------------------------");
		logger.info("Beginning encryption of file: " + this.inputFile);

		// Get public key and current epoch from the server
		logger.info("Accessing public key for secret: " + this.secretName + "... ");
//		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
		final EciesPublicParams shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);

//		shareVerificationKeysAndEpoch.getValue()
		logger.info(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getPublicKey();
		final long currentEpoch = shareVerificationKeysAndEpoch.getEpoch();
		logger.info("Public key for secret:    " + publicKey);
		logger.info("Current epoch for secret: " + currentEpoch);

		// Reading
		logger.info("Reading input file: " + this.inputFile + "... ");
		final byte[] plaintextData = Files.readAllBytes(inputFile.toPath());
		logger.info(" (done)");
		logger.info("Read " + plaintextData.length + " bytes.");

		// Perform ECIES encryption
		logger.info("Performing ECIES encryption of file content... ");
		final byte[] ciphertext = EciesEncryption.encrypt(plaintextData, publicKey);
		logger.info(" (done)");
		logger.info("Encrypted length " + ciphertext.length + " bytes.");

		// Write ciphertext to output file
		logger.info("Writing ciphertext to file: " + this.outputFile + "... ");
		Files.write(this.outputFile.toPath(), ciphertext);
		logger.info(" (done)");
		logger.info("Wrote " + ciphertext.length + " bytes.");

		logger.info("Done.");
	}

	public void decryptFile() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException {

		// Print status
		logger.info("-----------------------------------------------------------");
		logger.info("Beginning decryption of file: " + this.inputFile);

		// Reading ciphertext
		logger.info("Reading input file: " + this.inputFile + "... ");
		final byte[] ciphertextData = Files.readAllBytes(inputFile.toPath());
		logger.info(" (done)");
		logger.info("Read " + ciphertextData.length + " bytes of ciphertext.");


		// Extract public value from ciphertext
		logger.info("Extracting public value from ciphertext: " + this.inputFile + "... ");
		final EcPoint publicValue = EciesEncryption.getPublicValue(ciphertextData);
		logger.info(" (done)");
		logger.info("Public Value is: " + publicValue);


		// Get public key and current epoch from the server
		logger.info("Accessing public key for secret: " + this.secretName + "... ");
//		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
		final EciesPublicParams shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
		logger.info(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getPublicKey();
		final long currentEpoch = shareVerificationKeysAndEpoch.getEpoch();
		logger.info("Public key for secret:    " + publicKey);
		logger.info("Current epoch for secret: " + currentEpoch);

		// Get public key and current epoch from the server
		logger.info("Performing threshold exponentiation on public value using: " + this.secretName + "... ");
		final EcPoint exponentiationResult = this.exponentiatePoint(publicValue, currentEpoch, null);
		logger.info(" (done)");
		logger.info("Shared secret obtained:    " + exponentiationResult);

		// Perform ECIES decryption
		logger.info("Performing ECIES decryption of file content... ");
		final byte[] plaintext = EciesEncryption.decrypt(ciphertextData, exponentiationResult);
		logger.info(" (done)");
		logger.info("Plaintext length " + plaintext.length + " bytes.");
		;

		// Write plaintext to output file
		logger.info("Writing plaintext to file: " + this.outputFile + "... ");
		Files.write(this.outputFile.toPath(), plaintext);
		logger.info(" (done)");
		logger.info("Wrote " + plaintext.length + " bytes.");

		logger.info("Done.");

	}

	public byte[] encryptStream() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException {
		long start, end;
		logger.info("Beginning ECIES encryption...");
		// Print status
//		logger.info("-----------------------------------------------------------");
//		logger.info("Beginning encryption of file: " + this.inputFile);

		// Get public key and current epoch from the server
		logger.info("Accessing public key for secret: " + this.secretName + "... ");
//		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
		start = System.nanoTime();
		final EciesPublicParams shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
//		logger.info(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getPublicKey();
		final long currentEpoch = shareVerificationKeysAndEpoch.getEpoch();
		end = System.nanoTime();
		logger.info("PerfMeas:EciesInfoGet:" + (end - start));

		// Reading
//		logger.info("Reading input file: " + this.inputFile + "... ");
//		final byte[] plaintextData = Files.readAllBytes(inputFile.toPath());
//		final byte[] plaintextData = inputStream.readAllBytes();

		final byte[] plaintextData = IOUtils.toByteArray(inputStream);


//		logger.info(" (done)");
//		logger.info("Read " + plaintextData.length + " bytes.");

		// Perform ECIES encryption
//		logger.info("Performing ECIES encryption of file content... ");
		start = System.nanoTime();
		final byte[] ciphertext = EciesEncryption.encrypt(plaintextData, publicKey);
		end = System.nanoTime();

		logger.info("PerfMeas:EciesEncEnd:" + (end - start));
		logger.info("PerfMeas:EciesEncCiphertextBytes:" + ciphertext.length);
		logger.info("PerfMeas:EciesEncPkBits:" + (publicKey.getX().bitLength() + publicKey.getY().bitLength()));

//		logger.info(" (done)");
//		logger.info("Encrypted length " + ciphertext.length + " bytes.");

//		// Write ciphertext to output file
//		logger.info("Writing ciphertext to file: " + this.outputFile + "... ");
////		Files.write(this.outputFile.toPath(), ciphertext);
//		logger.info(" (done)");
//		logger.info("Wrote " + ciphertext.length + " bytes.");
//
//		logger.info("Done.");
		logger.info("Public key for secret:    " + publicKey);
		logger.info("Current epoch for secret: " + currentEpoch);
		logger.info("Size of the plaintext:    " + plaintextData.length);
		logger.info("Size of the ciphertext:   " + ciphertext.length);
		return ciphertext;
	}

	public byte[] decryptStream() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException {
		long start, end;
		long start_total, end_total;

		logger.info("Beginning ECIES decryption...");
		// Print status
//		logger.info("-----------------------------------------------------------");
//		logger.info("Beginning decryption of file: " + this.inputFile);

		// Reading ciphertext
//		logger.info("Reading input file: " + this.inputFile + "... ");
//		final byte[] ciphertextData = Files.readAllBytes(inputFile.toPath());
//		final byte[] ciphertextData = inputStream.readAllBytes();
		final byte[] ciphertextData = IOUtils.toByteArray(inputStream);
//		logger.info(" (done)");
//		logger.info("Read " + ciphertextData.length + " bytes of ciphertext.");


		// Extract public value from ciphertext
//		logger.info("Extracting public value from ciphertext: " + this.inputFile + "... ");
		final EcPoint publicValue = EciesEncryption.getPublicValue(ciphertextData);
//		logger.info(" (done)");
//		logger.info("Public Value is: " + publicValue);


		// Get public key and current epoch from the server
//		logger.info("Accessing public key for secret: " + this.secretName + "... ");
//		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);

		start = System.nanoTime();
		final EciesPublicParams shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
//		logger.info(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getPublicKey();
		final long currentEpoch = shareVerificationKeysAndEpoch.getEpoch();
		end = System.nanoTime();
		logger.info("PerfMeas:EciesInfoGet:" + (end - start));

//		logger.info("Public key for secret:    " + publicKey);
//		logger.info("Current epoch for secret: " + currentEpoch);

		// Get public key and current epoch from the server
		start = System.nanoTime();
		logger.info("Performing threshold exponentiation on public value using: " + this.secretName + "... ");
		final EcPoint exponentiationResult = this.exponentiatePoint(publicValue, currentEpoch, shareVerificationKeysAndEpoch.getVerificationValues());
//		logger.info(" (done)");
//		logger.info("Shared secret obtained:    " + exponentiationResult);

		// Perform ECIES decryption
//		logger.info("Performing ECIES decryption of file content... ");
		start_total = System.nanoTime();
		final byte[] plaintext = EciesEncryption.decrypt(ciphertextData, exponentiationResult);
		end_total = System.nanoTime();
		end = System.nanoTime();

		logger.info("PerfMeas:EciesDecCombineTotal:" + (end - start));
		logger.info("PerfMeas:EciesDecEnd:" + (end - start));
//		logger.info(" (done)");
//		logger.info("Plaintext length " + plaintext.length + " bytes.");
		;

		// Write plaintext to output file
//		logger.info("Writing plaintext to file: " + this.outputFile + "... ");
////		Files.write(this.outputFile.toPath(), plaintext);
//		logger.info(" (done)");
//		logger.info("Wrote " + plaintext.length + " bytes.");
//
//		logger.info("Done.");

		logger.info("Public key for secret:    " + publicKey);
		logger.info("Current epoch for secret: " + currentEpoch);
		logger.info("Size of the ciphertext:   " + ciphertextData.length);
		logger.info("Size of the plaintext:    " + plaintext.length);
		return plaintext;
	}

	public static void main(final String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			CertificateException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			ResourceUnavailableException, BelowThresholdException {

		// Parse arguments
		if (args.length < 6) {
			System.err.println("USAGE: config-dir username secretname [ENCRYPT/DECRYPT] input-file output-file");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final String username = args[1];
		final String secretName = args[2];
		final boolean encrypt = "ENCRYPT".equalsIgnoreCase(args[3]);
		final File inputFile = new File(args[4]);
		final File outputFile = new File(args[5]);

		if (!inputFile.exists()) {
			System.err.println("Input file does not exist: " + inputFile.getAbsolutePath());
			System.exit(-1);
		}

		// Load server configuration (learn n and k)
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
		logger.info(configuration);

		// TODO: Get these directly from the shareholder responses
		// final int n = configuration.getNumServers();
		// final int k = configuration.getReconstructionThreshold();

		// Load server keys
		final File keysDirectory = new File(baseDirectory, SERVER_KEYS_DIRECTORY);
		final KeyLoader serverKeys = new KeyLoader(keysDirectory, configuration.getNumServers(), null);

		// Load client certificate
		final File clientDirectory = new File(baseDirectory, CLIENT_DIRECTORY);
		final File certDirectory = new File(clientDirectory, CERTS_DIRECTORY);
		final File clientCertificateFile = new File(certDirectory, "cert-" + username);
		final X509Certificate clientCertificate = Pem.loadCertificateFromFile(clientCertificateFile);

		// Load client key
		final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
		final File clientKeysFile = new File(clientKeysDirectory, "private-" + username);
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

		// Create encryption client
		final EciesEncryptionClient encryptionClient = new EciesEncryptionClient(configuration, caCerts, serverKeys,
				clientCertificate, clientPrivateKey, secretName, inputFile, outputFile);

		// Perform operation
		if (encrypt) {
			encryptionClient.encryptFile();
		} else {
			encryptionClient.decryptFile();
		}
	}

	private static DerivationResult createDerivationResult(Object obj) {
		return (DerivationResult) obj;
	}

	/**
	 * Interacts with the servers to exponentiate a point for the given secret
	 * 
	 * @param inputPoint
	 * @return
	 * @throws ResourceUnavailableException
	 */
	private EcPoint exponentiatePoint(final EcPoint inputPoint, final long expectedEpoch, SortedMap<Integer, EcPoint> verificationValues)
			throws ResourceUnavailableException {

		logger.info("Initiating exponentiation on each shareholder...");
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
//		final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());
		ConcurrentHashMap<Integer, Object> verifiedResults = new ConcurrentHashMap<>(numShareholders);

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/exponentiate?secretName="
					+ this.secretName + "&x=" + inputPoint.getX() + "&y=" + inputPoint.getY() + "&json=true";

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
			executor.submit(new PartialResultTask(this, serverId, linkUrl, latch, failureCounter,
					maximumFailures) {
				@Override
				protected void parseJsonResult(final String json) throws Exception {
					long start, end;

					// Parse JSON
					final JSONParser parser = new JSONParser();
					final Object obj = parser.parse(json);
					final JSONObject jsonObject = (JSONObject) obj;
					final Long responder = (Long) jsonObject.get("responder");
					final long epoch = (Long) jsonObject.get("epoch");
					final JSONArray resultPoint = (JSONArray) jsonObject.get("result_point");
					final BigInteger x = new BigInteger((String) resultPoint.get(0));
					final BigInteger y = new BigInteger((String) resultPoint.get(1));

					final SignatureShareProof signatureShareProof = SignatureShareProof.getInstance((JSONObject) jsonObject.get("dec_proof"));

//					logger.info("Received proof::: " + signatureShareProof.getJson().toString());

					// Check received proof: c' = H(G, R, si.G, si.R, z.G - c.si.G, z.R - c.si.R)

					start = System.nanoTime();

					logger.info("Received a decryption share from agent " + responder);
					BigInteger z = signatureShareProof.getZ();
					BigInteger c = signatureShareProof.getC();

					EcPoint G = CommonConfiguration.g;
					EcPoint R = inputPoint;

					EcPoint siG = verificationValues.get(responder.intValue());
					EcPoint siR = new EcPoint(x, y);

					EcPoint zG = CommonConfiguration.CURVE.multiply(CommonConfiguration.g, z);
					EcPoint mcsiG = CommonConfiguration.CURVE.multiply(siG, c.multiply(BigInteger.valueOf(-1)).mod(CommonConfiguration.CURVE.getR()));
					EcPoint zG_mcsiG = CommonConfiguration.CURVE.addPoints(zG, mcsiG);

					EcPoint zR = CommonConfiguration.CURVE.multiply(R, z);
					EcPoint mcsiR = CommonConfiguration.CURVE.multiply(siR, c.multiply(BigInteger.valueOf(-1)).mod(CommonConfiguration.CURVE.getR()));
					EcPoint zR_mcsiR = CommonConfiguration.CURVE.addPoints(zR, mcsiR);

					byte[] cBytes = Parse.concatenate(G, R, siG, siR, zG_mcsiG, zR_mcsiR);
					BigInteger cPrime = ThresholdSignatures.hashToInteger(cBytes, ThresholdSignatures.HASH_MOD);

					end = System.nanoTime();
					logger.info("PerfMeas:EciesDecCombineVerify:" + (end - start));
//					logger.info("===========================================================================");
//					logger.info("Recieved: " + c);
//					logger.info("computed: " + cPrime);

//					if(!c.equals(cPrime))

					// Verify result
					// TODO: Separate results by their epoch, wait for enough results of the same
					// epoch
					// TOOD: Implement retry if epoch mismatch and below threshold
					if ((responder == thisServerId) && (epoch == expectedEpoch) && (c.equals(cPrime))) {
						logger.info("Decryption share from server " + responder + " is consistent");
						final EcPoint partialResult = siR;

						// Store result for later processing
//						synchronized (verifiedResults) {
//							verifiedResults.add(new DerivationResult(BigInteger.valueOf(responder), partialResult));
//						}
						verifiedResults.put((int) (responder-1), new DerivationResult(BigInteger.valueOf(responder), partialResult));

						// Everything checked out, increment successes
						latch.countDown();
					} else {
						throw new Exception(
								"Server " + thisServerId + " sent inconsistent results (likely during epoch change)");
					}

				}
			});
		}

		try {
			// Once we have K successful responses we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				logger.info("Collected sufficient amount of shares");

				List<DerivationResult> results = verifiedResults.values().stream().map(EciesEncryptionClient::createDerivationResult)
						.collect(Collectors.toList());
				long start = System.nanoTime();
				// When complete, interpolate the result at zero (where the secret lies)
				final EcPoint interpolatedResult = Polynomials.interpolateExponents(results, reconstructionThreshold,
						0);
				long end = System.nanoTime();
				logger.info("PerfMeas:EciesDecCombineInterpolate:" + (end - start));
				executor.shutdown();

				return interpolatedResult;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

}
