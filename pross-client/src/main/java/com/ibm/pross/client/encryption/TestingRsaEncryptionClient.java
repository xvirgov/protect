package com.ibm.pross.client.encryption;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.client.util.RsaPublicParameters;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.GcdTriplet;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class TestingRsaEncryptionClient extends BaseClient {

    private final String secretName;
    private final InputStream inputStream;

    private static final Logger logger = LogManager.getLogger(TestingRsaEncryptionClient.class);

    public TestingRsaEncryptionClient(final ServerConfiguration serverConfiguration,
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

//        logger.info(rsaPublicParameters);

        final byte[] plaintextData = IOUtils.toByteArray(inputStream);

//        logger.info("Encrypting message: " + Arrays.toString(plaintextData));
//        BigInteger plaintext = new BigInteger(plaintextData);
//        logger.debug("Encrypting message: " + plaintext);

//        final byte[] ciphertext = RsaUtil.rsaVerify(plaintext, rsaPublicParameters.getExponent(), rsaPublicParameters.getModulus()).toByteArray();

//        logger.debug("Ciphertext: " + Arrays.toString(ciphertext));

        final byte[] hybridCiphertext = rsaAesEncrypt(plaintextData, rsaPublicParameters.getExponent(), rsaPublicParameters.getModulus());
        return hybridCiphertext;
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
//        return ciphertext;
    }

    private byte[] rsaAesEncrypt(final byte[] message, BigInteger exponent, BigInteger modulus) {

        try {
            // Initialise random and generate session AES key
            SecureRandom random = SecureRandom.getInstanceStrong();
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE, random);
            SecretKey secretKey = keyGenerator.generateKey();

            // Encrypt
            Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
            final byte[] nonce = new byte[GCM_IV_LENGTH/8];
            random.nextBytes(nonce);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            aesGcmCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            final byte[] messageCiphertext = aesGcmCipher.doFinal(message);

            // Compute hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(message);

            // Encrypt symmetric key with RSA
            final byte[] symmetricKeyCiphertext = Exponentiation.modPow(new BigInteger(secretKey.getEncoded()), exponent, modulus).toByteArray();

            return Parse.concatenate(symmetricKeyCiphertext, messageCiphertext, hash);
        }
        catch (GeneralSecurityException e) {
            logger.error(e);
            throw new RuntimeException(e);
        }

    }

    public byte[] decryptionStream() throws IOException, BelowThresholdException, ResourceUnavailableException, BadArgumentException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        logger.info("Starting RSA decryption with secret " + secretName);

        final byte[] ciphertextData = IOUtils.toByteArray(inputStream);
        BigInteger ciphertext = new BigInteger(ciphertextData);

        logger.info("Decrypting message: " + ciphertext);

        RsaPublicParameters rsaPublicParameters = this.getRsaPublicParams(secretName);

//        logger.debug(rsaPublicParameters);

        // Get encrypted symmetric key
        final byte[][] combined = Parse.splitArrays(ciphertextData);
        if (combined.length != 3) {
            throw new BadPaddingException("Invalid ciphertext");
        }

        final BigInteger encryptedAesKey = new BigInteger(combined[0]);

        // Get partial decryption shares
        final List<SignatureResponse> decryptionShares = requestPartialRsaDecryptions(encryptedAesKey, rsaPublicParameters.getEpoch()).stream().map(obj -> (SignatureResponse) obj).collect(Collectors.toList());

        // Perform validation of decryption shares
        List<SignatureResponse> validatedDecryptionShares = new ArrayList<>();
        for (SignatureResponse decryptionShare : decryptionShares) {
            BigInteger serverIndex = decryptionShare.getServerIndex();

            try {
                if (this.validateDecryptionShare(encryptedAesKey, decryptionShare, rsaPublicParameters)) {
                    validatedDecryptionShares.add(decryptionShare);
                    logger.debug("Decryption share from server " + serverIndex + " passed validation");
                }
                else {
                    logger.error("Decryption share from server " + serverIndex + " failed validation, excluding from operation");
                }
            } catch (Exception exception) {
                logger.error("Decryption share from server " + serverIndex + " failed validation, excluding from operation, error = " + exception);
            }
        }

        BigInteger recoveredPlaintext = recoverPlaintext(encryptedAesKey, validatedDecryptionShares, rsaPublicParameters);
        final byte[] recoveredSymmetricKey = recoveredPlaintext.toByteArray();
        SecretKey secretKey = new SecretKeySpec(recoveredSymmetricKey, 0, recoveredSymmetricKey.length, "AES");

//        ByteBuffer

        // Decrypt using AES
        Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
//        aesGcmCipher.init(Cipher.DECRYPT_MODE, secretKey, );

//
//        logger.info("==================================================================================");
//        logger.info("Recovered plaintext: " + recoveredPlaintext);

        return recoveredPlaintext.toByteArray();
    }

    private List<Object> requestPartialRsaDecryptions(final BigInteger message, final long expectedEpoch) throws ResourceUnavailableException {
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

            logger.info("Requesting partial RSA decryption from server " + serverId);
//            logger.debug("Request: " + linkUrl);

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
                    final Long responder = (Long) jsonObject.get("responder");
                    final long epoch = (Long) jsonObject.get("epoch");

                    final JSONArray shareProof = (JSONArray) jsonObject.get("share_proof");
                    SignatureShareProof decryptionShareProof = new SignatureShareProof(new BigInteger(shareProof.get(0).toString()),
                            new BigInteger(shareProof.get(1).toString()));

                    BigInteger decryptionShare = new BigInteger(jsonObject.get("share").toString());

//                    final JSONArray resultPoint = (JSONArray) jsonObject.get("result_point");
//                    final BigInteger x = new BigInteger((String) resultPoint.get(0));
//                    final BigInteger y = new BigInteger((String) resultPoint.get(1));

//                    logger.info(json);

                    // Verify result
                    // TODO: Separate results by their epoch, wait for enough results of the same
                    // epoch
                    // TOOD: Implement retry if epoch mismatch and below threshold
                    if ((responder == thisServerId) && (epoch == expectedEpoch)) {

                        // FIXME: Do verification of the results (using proofs)
//                        final EcPoint partialResult = new EcPoint(x, y);

                        // Store result for later processing
//                        verifiedResults.add(new DerivationResult(BigInteger.valueOf(responder), partialResult));
                        verifiedResults.add(new SignatureResponse(new BigInteger(responder.toString()), decryptionShare, decryptionShareProof));

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

//                List<DerivationResult> results = verifiedResults.stream().map(obj -> createDerivationResult(obj))
//                        .collect(Collectors.toList());
//
//                // When complete, interpolate the result at zero (where the secret lies)
//                final EcPoint interpolatedResult = Polynomials.interpolateExponents(results, reconstructionThreshold,
//                        0);
//                logger.info("-------------------------------------------------------aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa--------------------------------");
//                logger.info(verifiedResults);



                executor.shutdown();
                return verifiedResults;
//                return interpolatedResult;
            } else {
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private BigInteger recoverPlaintext(final BigInteger ciphertext,
                                              final List<SignatureResponse> signatureResponses, final RsaPublicParameters rsaPublicParameters)
            throws BadArgumentException {

        // Extract values from configuration
        final BigInteger n = rsaPublicParameters.getModulus();
        final BigInteger e = rsaPublicParameters.getExponent();
        final int serverCount = this.serverConfiguration.getNumServers();
        final BigInteger delta = Polynomials.factorial(BigInteger.valueOf(serverCount));
        final int threshold = this.serverConfiguration.getReconstructionThreshold();

        // Determine coordinates
        final BigInteger[] xCoords = new BigInteger[threshold];
        for (int i = 0; i < threshold; i++) {
            final SignatureResponse signatureResponse = signatureResponses.get(i);
            xCoords[i] = signatureResponse.getServerIndex();
        }

        // Interpolate polynomial
        logger.info("Interpolate decryption shares from servers: " + Arrays.toString(xCoords));
        BigInteger w = BigInteger.ONE;
        for (int i = 0; i < threshold; i++) {
            final SignatureResponse signatureResponse = signatureResponses.get(i);

            final BigInteger j = signatureResponse.getServerIndex();
            final BigInteger signatureShare = signatureResponse.getSignatureShare();
            final BigInteger L_ij = Polynomials.interpolateNoModulus(xCoords, delta, BigInteger.ZERO, j);

            w = w.multiply(Exponentiation.modPow(signatureShare, ThresholdSignatures.TWO.multiply(L_ij), n));
        }

        // Use Extended Euclidean Algorithm to solve for the signature
        final BigInteger ePrime = delta.multiply(delta).multiply(BigInteger.valueOf(4)); // 4*D*D
        final GcdTriplet gcdTriplet = GcdTriplet.extendedGreatestCommonDivisor(ePrime, e);
        final BigInteger a = gcdTriplet.getX();
        final BigInteger b = gcdTriplet.getY();

        return Exponentiation.modPow(w, a, n).multiply(Exponentiation.modPow(ciphertext, b, n)).mod(n);
    }

    private boolean validateDecryptionShare(final BigInteger ciphertext, final SignatureResponse decryptionShare,
                                            final RsaPublicParameters rsaPublicParameters) {

        // Extract configuration items
        final BigInteger n = rsaPublicParameters.getModulus();
        final BigInteger v = rsaPublicParameters.getVerificationKey();
        final List<BigInteger> verificationKeys = rsaPublicParameters.getShareVerificationKeys();

        final int serverCount = this.serverConfiguration.getNumServers();

        // Extract elements from returned signature triplet
        final BigInteger index = decryptionShare.getServerIndex();
        final BigInteger signatureShare = decryptionShare.getSignatureShare();
        final BigInteger z = decryptionShare.getSignatureShareProof().getZ();
        final BigInteger c = decryptionShare.getSignatureShareProof().getC();

        // Perform verification
        final BigInteger vToZ = Exponentiation.modPow(v, z, n);
        final int keyIndex = index.intValue() - 1;
        if ((keyIndex < 0) || (keyIndex >= verificationKeys.size())) {
            return false;
        }
        final BigInteger vk = verificationKeys.get(keyIndex);
        final BigInteger invVerificationKey = Exponentiation.modInverse(vk, n);
        final BigInteger invVkToC = Exponentiation.modPow(invVerificationKey, c, n);
        final BigInteger vTerms = vToZ.multiply(invVkToC).mod(n);

        final BigInteger delta = Polynomials.factorial(BigInteger.valueOf(serverCount));
        final BigInteger mToFourD = Exponentiation.modPow(ciphertext, BigInteger.valueOf(4).multiply(delta), n);
        final BigInteger xToZ = Exponentiation.modPow(mToFourD, z, n);
        final BigInteger invShare = Exponentiation.modInverse(signatureShare, n);
        final BigInteger invShareToTwoC = Exponentiation.modPow(invShare, ThresholdSignatures.TWO.multiply(c), n);
        final BigInteger xTerms = xToZ.multiply(invShareToTwoC).mod(n);

        final BigInteger shareSquared = Exponentiation.modPow(signatureShare, ThresholdSignatures.TWO, n);

        final byte[] verificationString = Parse.concatenate(v, mToFourD, vk, shareSquared, vTerms, xTerms);
        final BigInteger recomputedC = hashToInteger(verificationString, ThresholdSignatures.HASH_MOD);

        if (recomputedC.equals(c)) {
            return true;
        } else {
            return false;
        }
    }

    private static BigInteger hashToInteger(final byte[] input, final BigInteger modulus) {
        try {
            byte[] hashed = MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM).digest(input);
            return (new BigInteger(1, hashed)).mod(modulus);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 96;
    public static final int GCM_TAG_LENGTH = 128;
    public static final int SALT_LENGTH = 256;

    public static void main(String[] args) {
        System.out.println("Enc/Dec beginning");
        final byte[] message = "trolololo lolo lolo loossosososooso".getBytes();
        try {
            System.out.println("Plaintext: " + Arrays.toString(message));

            // Create arrays
            byte[] iv = new byte[GCM_IV_LENGTH/8];
            byte[] salt = new byte[SALT_LENGTH/8];
            byte[] aesEncResult = null;

            // Create a random source
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            // Initialise iv and salt
            System.out.println("Initialising iv and salt...");
            random.nextBytes(iv);
            random.nextBytes(salt);

            // Initialise random and generate session key
            System.out.println("Generating session key...");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE, random);
            SecretKey secretKey = keyGenerator.generateKey();

            // Salt session key
            System.out.println("Salting session key...");
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(Arrays.toString(secretKey.getEncoded()).toCharArray(), salt, 65536, AES_KEY_SIZE);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");

            // Encrypt data using AES
            System.out.println("Encrypting data...");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            byte[] encrypted = cipher.doFinal(message);

            // Concatenate salt, iv and encryption result
            System.out.println("Concatenating salt, iv and encrypted data to create a result of AES-GCM encryption...");
            byte[] result = new byte[encrypted.length + salt.length + iv.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(iv, 0, result, salt.length, iv.length);
            System.arraycopy(encrypted, 0, result, salt.length + iv.length, encrypted.length);

            // Begin decryption
            System.out.println("Beginning decryption...");

            System.out.println("Retrieve all values and password...");
            byte[] passwordDec = secretKey.getEncoded();
            byte[] saltDec = Arrays.copyOfRange(result, 0, SALT_LENGTH/8);
            byte[] ivDec = Arrays.copyOfRange(result, SALT_LENGTH/8, SALT_LENGTH/8 + GCM_IV_LENGTH/8);
            byte[] encryptedDataDec = Arrays.copyOfRange(result, SALT_LENGTH/8 + GCM_IV_LENGTH/8, result.length);

            System.out.println("Salting session key...");
            SecretKeyFactory secretKeyFactoryDec = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpecDec = new PBEKeySpec(Arrays.toString(passwordDec).toCharArray(), saltDec, 65536, AES_KEY_SIZE);
            SecretKeySpec secretKeySpecDec = new SecretKeySpec(secretKeyFactoryDec.generateSecret(keySpecDec).getEncoded(), "AES");

            System.out.println("Decrypting data using retrieved values...");
            Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpecDec = new GCMParameterSpec(GCM_TAG_LENGTH, ivDec);
            cipherDec.init(Cipher.DECRYPT_MODE, secretKeySpecDec, gcmParameterSpecDec);

            byte[] recoveredPlaintext = cipherDec.doFinal(encryptedDataDec);

            System.out.println("Recovered plaintext: " + Arrays.toString(recoveredPlaintext));


//            // Encrypt
//            Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
//            final byte[] nonce = new byte[GCM_IV_LENGTH/8];
//            random.nextBytes(nonce);
//            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
//            aesGcmCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
//            final byte[] messageCiphertext = aesGcmCipher.doFinal(message);
//
//            // Compute hash
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            final byte[] hash = digest.digest(message);
//
//            // Encrypt symmetric key with RSA
////            final byte[] symmetricKeyCiphertext = Exponentiation.modPow(new BigInteger(secretKey.getEncoded()), exponent, modulus).toByteArray();
////
////            return Parse.concatenate(symmetricKeyCiphertext, messageCiphertext, hash);
        }
        catch (GeneralSecurityException e) {
            logger.error(e);
            throw new RuntimeException(e);
        }
    }

}
