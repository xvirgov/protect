package com.ibm.pross.client.encryption;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.client.util.RsaPublicParameters;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.rsa.OaepUtil;
import com.ibm.pross.common.util.crypto.rsa.RsaUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.GcdTriplet;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.util.DigestFactory;
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
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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

public class RsaEncryptionClient extends BaseClient {

    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 96;
    public static final int GCM_TAG_LENGTH = 128;
    public static final int HASH_LENGTH = 256;

    //    public byte[] pad(byte[] message, int length) {
//        int messageLength = message.length;
//        int seedLength = 32;
//
//        if (messageLength > length - (seedLength << 1) - 1) {
//            throw new RuntimeException("Message too long for padding scheme.");
//        }
//        int zeroPad = length - messageLength - (seedLength << 1) - 1;
//        byte[] dataBlock = new byte[length - seedLength];
//
//    }
    private static final Logger logger = LogManager.getLogger(RsaEncryptionClient.class);
    private final String secretName;
    private final InputStream inputStream;

    public RsaEncryptionClient(final ServerConfiguration serverConfiguration,
                               final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
                               final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
                               InputStream inputStream) {

        super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

        this.secretName = secretName;
        this.inputStream = inputStream;
    }

    private static BigInteger hashToInteger(final byte[] input, final BigInteger modulus) {
        try {
            byte[] hashed = MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM).digest(input);
            return (new BigInteger(1, hashed)).mod(modulus);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }
//    public static final int SALT_LENGTH = 256;

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
//            SecureRandom random = SecureRandom.getInstanceStrong();
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//            keyGenerator.init(AES_KEY_SIZE, random);
//            SecretKey secretKey = keyGenerator.generateKey();
//
//            // Encrypt
//            Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
//            final byte[] nonce = new byte[GCM_NONCE_LENGTH/8];
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
//            final byte[] symmetricKeyCiphertext = Exponentiation.modPow(new BigInteger(secretKey.getEncoded()), exponent, modulus).toByteArray();
//
//            return Parse.concatenate(symmetricKeyCiphertext, messageCiphertext, hash);

            // Create arrays
            byte[] iv = new byte[GCM_IV_LENGTH / 8];
//            byte[] salt = new byte[SALT_LENGTH/8];
            byte[] aesEncResult = null;

            // Create a random source
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            // Initialise iv and salt
            logger.info("Initialising iv...");
            random.nextBytes(iv);
//            random.nextBytes(salt);

            // Initialise random and generate session key
            logger.info("Generating session key...");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE, random);
            SecretKey secretKey = keyGenerator.generateKey();

            logger.info("Generated AES key: " + Arrays.toString(secretKey.getEncoded()));

            // Salt session key
//            logger.info("Salting session key...");
//            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//            KeySpec keySpec = new PBEKeySpec(Arrays.toString(secretKey.getEncoded()).toCharArray(), salt, 65536, AES_KEY_SIZE);
//            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");

            // Encrypt data using AES
            logger.info("Encrypting data using AES-GCM...");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            byte[] encrypted = cipher.doFinal(message);
            logger.info("[DONE]");

            // Concatenate salt, iv and encryption result
            logger.info("Concatenating iv and encrypted data to create a result of AES-GCM encryption...");
            byte[] result = new byte[encrypted.length + iv.length];
//            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            logger.info("[DONE]");

            // Compute hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(message);

            logger.info("Plaintext hash: " + Arrays.toString(hash));

            byte[] paddedSecretKey = OaepUtil.pad(secretKey.getEncoded(), RsaSharing.DEFAULT_RSA_KEY_SIZE, HASH_LENGTH);

            // Encrypt symmetric key with RSA
            final byte[] symmetricKeyCiphertext = Exponentiation.modPow(new BigInteger(paddedSecretKey), exponent, modulus).toByteArray();

//            logger.debug("Ciphertext - after encrypt: " + Arrays.toString(encrypted));
//            logger.debug("symm key   - after encrypt: " + Arrays.toString(secretKeySpec.getEncoded()));
//            logger.debug("iv         - after encrypt: " + Arrays.toString(iv));
//            logger.debug("salt       - after encrypt: " + Arrays.toString(salt));

            return Parse.concatenate(symmetricKeyCiphertext, result, hash);
        } catch (GeneralSecurityException e) {
            logger.error(e);
            throw new RuntimeException(e);
        }

    }

//    /**
//     * int to octet string.
//     */
//    private void ItoOSP(
//            int i,
//            byte[] sp) {
//        sp[0] = (byte) (i >>> 24);
//        sp[1] = (byte) (i >>> 16);
//        sp[2] = (byte) (i >>> 8);
//        sp[3] = (byte) (i >>> 0);
//    }
//
//    /**
//     * mask generator function, as described in PKCS1v2.
//     */
//    private byte[] maskGeneratorFunction1(
//            byte[] Z,
//            int zOff,
//            int zLen,
//            int length) {
//        Digest mgf1Hash = DigestFactory.createSHA256();
//        byte[] mask = new byte[length];
//        byte[] hashBuf = new byte[mgf1Hash.getDigestSize()];
//        byte[] C = new byte[4];
//        int counter = 0;
//
//        mgf1Hash.reset();
//
//        while (counter < (length / hashBuf.length)) {
//            ItoOSP(counter, C);
//
//            mgf1Hash.update(Z, zOff, zLen);
//            mgf1Hash.update(C, 0, C.length);
//            mgf1Hash.doFinal(hashBuf, 0);
//
//            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, hashBuf.length);
//
//            counter++;
//        }
//
//        if ((counter * hashBuf.length) < length) {
//            ItoOSP(counter, C);
//
//            mgf1Hash.update(Z, zOff, zLen);
//            mgf1Hash.update(C, 0, C.length);
//            mgf1Hash.doFinal(hashBuf, 0);
//
//            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, mask.length - (counter * hashBuf.length));
//        }
//
//        return mask;
//    }
//
//    // Based on OAEP implementation in bouncycastle
//    public byte[] pad(byte[] message) throws NoSuchAlgorithmException {
//        logger.info("Padding the message using OAEP...");
//        int blockSize = RSA_MODULUS_SIZE / 8;
//
//        // Check if the message can be padded
//        if (message.length > blockSize) {
//            throw new RuntimeException("Message size is too large! Padding failed.");
//        }
//
//        byte[] block = new byte[blockSize];
//
//        // Copy message into the block
//        System.arraycopy(message, 0, block, block.length - message.length, message.length);
//
//        // Add sentinel
//        block[block.length - message.length - 1] = 0x01;
//
//        // Block is already zeroed - no need to add the padding string
//
//        // Generate the seed
//        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//        byte[] seed = new byte[HASH_LENGTH / 8];
//        random.nextBytes(seed);
//
//        // Mask the message block
//        byte[] mask = maskGeneratorFunction1(seed, 0, seed.length, block.length - HASH_LENGTH / 8);
//
//        for (int i = HASH_LENGTH / 8; i != block.length; i++) {
//            block[i] ^= mask[i - HASH_LENGTH / 8];
//        }
//
//        // Add in the seed
//        System.arraycopy(seed, 0, block, 0, HASH_LENGTH / 8);
//
//        // Mask the seed
//        mask = maskGeneratorFunction1(block, HASH_LENGTH / 8, block.length - HASH_LENGTH / 8, HASH_LENGTH / 8);
//
//        for (int i = 0; i != HASH_LENGTH / 8; i++) {
//            block[i] ^= mask[i];
//        }
//
//        logger.info("[DONE]");
//        return block;
//    }
//
//    public byte[] unpad(byte[] data) {
//        logger.info("Extracting the message from the OAEP-padded block...");
//
//        int blockSize = RSA_MODULUS_SIZE / 8;
//        byte[] block = new byte[blockSize];
//
//        // Remove any leading zeroes that might be a result of encryption process
//        System.arraycopy(data, 0, block, block.length - data.length, data.length);
//
//        boolean shortData = (data.length < (HASH_LENGTH / 8) + 1);
//
//        // Unmask the seed
//        byte[] mask = maskGeneratorFunction1(block, HASH_LENGTH / 8, block.length - HASH_LENGTH / 8, HASH_LENGTH / 8);
//
//        for (int i = 0; i != HASH_LENGTH/8; i++) {
//            block[i] ^= mask[i];
//        }
//
//        // Unmask the message
//        mask = maskGeneratorFunction1(block, 0, HASH_LENGTH/8, block.length - HASH_LENGTH/8);
//        for( int i = HASH_LENGTH/8; i != block.length; i++) {
//            block[i] ^= mask[i - HASH_LENGTH/8];
//        }
//
//        // Find the data block
//        int start = block.length;
//        for (int index = 2*HASH_LENGTH/8; index != block.length; index++) {
//            if(block[index] != 0 & start == block.length) {
//                start = index;
//            }
//        }
//
//        boolean dataStartWrong = (start > (block.length - 1) | block[start] != 1);
//
//        start++;
//
//        if ( shortData | dataStartWrong ) {
//            throw new RuntimeException("Unpadding failed: wrong data");
//        }
//
//        // Extract the data block
//        byte[] output = new byte[block.length - start];
//
//        System.arraycopy(block, start, output, 0, output.length);
//
//        logger.info("[DONE]");
//
//        return output;
//    }

    public byte[] decryptionStream() throws IOException, BelowThresholdException, ResourceUnavailableException, BadArgumentException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        logger.info("Starting RSA decryption with secret " + secretName);

        final byte[] ciphertextData = IOUtils.toByteArray(inputStream);
        BigInteger ciphertext = new BigInteger(ciphertextData);

//        logger.info("Decrypting message: " + ciphertext);

        RsaPublicParameters rsaPublicParameters = this.getRsaPublicParams(secretName);

//        logger.debug(rsaPublicParameters);

        // Get encrypted symmetric key
        final byte[][] combined = Parse.splitArrays(ciphertextData);
        if (combined.length != 3) {
            throw new BadPaddingException("Invalid ciphertext");
        }

        // Retrieve values
        BigInteger encryptedPaddedSecretKey = new BigInteger(combined[0]);
        final byte[] aesCiphertextData = combined[1];
        final byte[] plaintextHash = combined[2];

//        BigInteger encryptedAesKey = new BigInteger(unpad(paddedSecretKey));

        // Get partial decryption shares
        final List<SignatureResponse> decryptionShares = requestPartialRsaDecryptions(encryptedPaddedSecretKey, rsaPublicParameters.getEpoch()).stream().map(obj -> (SignatureResponse) obj).collect(Collectors.toList());

        // Perform validation of decryption shares
        List<SignatureResponse> validatedDecryptionShares = new ArrayList<>();
        for (SignatureResponse decryptionShare : decryptionShares) {
            BigInteger serverIndex = decryptionShare.getServerIndex();

            try {
                if (this.validateDecryptionShare(encryptedPaddedSecretKey, decryptionShare, rsaPublicParameters)) {
                    validatedDecryptionShares.add(decryptionShare);
                    logger.debug("Decryption share from server " + serverIndex + " passed validation");
                } else {
                    logger.error("Decryption share from server " + serverIndex + " failed validation, excluding from operation");
                }
            } catch (Exception exception) {
                logger.error("Decryption share from server " + serverIndex + " failed validation, excluding from operation, error = " + exception);
            }
        }

//        BigInteger recoveredSymmetricKey = recoverPlaintext(encryptedAesKey, validatedDecryptionShares, rsaPublicParameters);
        final byte[] recoveredPaddedSymmetricKey = recoverPlaintext(encryptedPaddedSecretKey, validatedDecryptionShares, rsaPublicParameters).toByteArray();
        final byte[] recoveredSymmetricKey = OaepUtil.unpad(recoveredPaddedSymmetricKey, RsaSharing.DEFAULT_RSA_KEY_SIZE, HASH_LENGTH);
//        SecretKey secretKey = new SecretKeySpec(recoveredSymmetricKey, 0, recoveredSymmetricKey.length, "AES");

//        byte[] saltDec = Arrays.copyOfRange(aesCiphertextData, 0, SALT_LENGTH/8);
        byte[] ivDec = Arrays.copyOfRange(aesCiphertextData, 0, GCM_IV_LENGTH / 8);
        byte[] encryptedDataDec = Arrays.copyOfRange(aesCiphertextData, GCM_IV_LENGTH / 8, aesCiphertextData.length);

//        logger.debug("Ciphertext - in decrypt: " + Arrays.toString(encryptedDataDec));
//        logger.debug("Symm key   - in decrypt: " + Arrays.toString(recoveredSymmetricKey));
//        logger.debug("iv         - in decrypt: " + Arrays.toString(ivDec));
//        logger.debug("salt       - in decrypt: " + Arrays.toString(saltDec));

//        logger.info("Salting session key..."); // FIXME-thesis: think about if salting here is really useful - only in case if someone esl provides aes key, can this happen?
//        SecretKeyFactory secretKeyFactoryDec = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//        KeySpec keySpecDec = new PBEKeySpec(Arrays.toString(recoveredSymmetricKey).toCharArray(), saltDec, 65536, AES_KEY_SIZE);
//        SecretKeySpec secretKeySpecDec = new SecretKeySpec(secretKeyFactoryDec.generateSecret(keySpecDec).getEncoded(), "AES");

        logger.info("Computed AES key: " + Arrays.toString(recoveredSymmetricKey));
        SecretKey secretKeySpecDec = new SecretKeySpec(recoveredSymmetricKey, 0, recoveredSymmetricKey.length, "AES");


        logger.info("Decrypting data using retrieved values...");
        Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpecDec = new GCMParameterSpec(GCM_TAG_LENGTH, ivDec);
        cipherDec.init(Cipher.DECRYPT_MODE, secretKeySpecDec, gcmParameterSpecDec);

//        byte[] recoveredPlaintext = cipherDec.doFinal(encryptedDataDec);

        // Do hash verification

        byte[] resultPlaintext = cipherDec.doFinal(encryptedDataDec);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(resultPlaintext);

        if (!Arrays.equals(hash, plaintextHash)) {
            throw new RuntimeException("Hashes of plaintexts don't match!");
        }

        return resultPlaintext;
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

}
