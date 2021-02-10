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
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
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
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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

    public byte[] encryptStream() throws BelowThresholdException, ResourceUnavailableException, IOException {
        logger.info("Starting RSA encryption with secret " + secretName);

        RsaPublicParameters rsaPublicParameters = this.getRsaPublicParams(secretName);

        final byte[] plaintextData = IOUtils.toByteArray(inputStream);

        final byte[] hybridCiphertext = rsaAesEncrypt(plaintextData, rsaPublicParameters.getExponent(), rsaPublicParameters.getModulus());

        logger.info("[DONE]");

        return hybridCiphertext;
    }

    private byte[] rsaAesEncrypt(final byte[] message, BigInteger exponent, BigInteger modulus) {

        try {
            // Create arrays
            byte[] iv = new byte[GCM_IV_LENGTH / 8];

            // Create a random source
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            // Initialise iv and salt
            logger.info("Initialising iv...");
            random.nextBytes(iv);
            logger.info("[DONE]");

            // Initialise random and generate session key
            logger.info("Generating session key...");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE, random);
            SecretKey secretKey = keyGenerator.generateKey();
            logger.info("[DONE]");

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
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            logger.info("[DONE]");

            // Compute hash
            logger.info("Computing hash of plaintext...");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(message);
            logger.info("[DONE]");

            byte[] paddedSecretKey = OaepUtil.pad(secretKey.getEncoded(), RsaSharing.DEFAULT_RSA_KEY_SIZE, HASH_LENGTH);

            // Encrypt symmetric key with RSA
            logger.info("Encrypting AES key with threshold RSA...");
            final byte[] symmetricKeyCiphertext = Exponentiation.modPow(new BigInteger(paddedSecretKey), exponent, modulus).toByteArray();
            logger.info("[DONE]");

            logger.info("Encryption process finished");

            return Parse.concatenate(symmetricKeyCiphertext, result, hash);
        } catch (GeneralSecurityException e) {
            logger.error(e);
            throw new RuntimeException(e);
        }

    }

    public byte[] decryptionStream() throws IOException, BelowThresholdException, ResourceUnavailableException, BadArgumentException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        logger.info("Starting RSA decryption with secret " + secretName + "...");

        // Store byte input stream into array
        final byte[] ciphertextData = IOUtils.toByteArray(inputStream);

        // Get RSA public parameters
        RsaPublicParameters rsaPublicParameters = this.getRsaPublicParams(secretName);

        // Parse the ciphertext
        final byte[][] combined = Parse.splitArrays(ciphertextData);
        if (combined.length != 3) {
            throw new BadPaddingException("Invalid ciphertext");
        }

        BigInteger encryptedPaddedSecretKey = new BigInteger(combined[0]);
        final byte[] aesCiphertextData = combined[1];
        final byte[] plaintextHash = combined[2];

        // Get partial decryption shares
        final List<SignatureResponse> decryptionShares = requestPartialRsaDecryptions(encryptedPaddedSecretKey, rsaPublicParameters.getEpoch()).stream().map(obj -> (SignatureResponse) obj).collect(Collectors.toList());

        // Perform validation of decryption shares
        logger.info("Verifying decryption shares...");
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
        logger.info("[DONE]");

        // Decrypt symmetric key with threshold RSA
        final byte[] recoveredPaddedSymmetricKey = recoverPlaintext(encryptedPaddedSecretKey, validatedDecryptionShares, rsaPublicParameters).toByteArray();

        // Get decrypted parameters of AES
        final byte[] ivDec = Arrays.copyOfRange(aesCiphertextData, 0, GCM_IV_LENGTH / 8);
        final byte[] encryptedDataDec = Arrays.copyOfRange(aesCiphertextData, GCM_IV_LENGTH / 8, aesCiphertextData.length);

        // Reverse OAEP padding on decrypted AES key
        final byte[] recoveredSymmetricKey = OaepUtil.unpad(recoveredPaddedSymmetricKey, RsaSharing.DEFAULT_RSA_KEY_SIZE, HASH_LENGTH);
        SecretKey secretKeySpecDec = new SecretKeySpec(recoveredSymmetricKey, 0, recoveredSymmetricKey.length, "AES");

        logger.info("Decrypting data using retrieved values...");
        Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpecDec = new GCMParameterSpec(GCM_TAG_LENGTH, ivDec);
        cipherDec.init(Cipher.DECRYPT_MODE, secretKeySpecDec, gcmParameterSpecDec);
        byte[] resultPlaintext = cipherDec.doFinal(encryptedDataDec);
        logger.info("[DONE]");

        logger.info("Checking hash of recovered plaintext...");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(resultPlaintext);
        if (!Arrays.equals(hash, plaintextHash)) {
            throw new RuntimeException("Hashes of plaintexts don't match!");
        }
        logger.info("[DONE]");

        logger.info("Decryption process finished");

        return resultPlaintext;
    }

    private List<Object> requestPartialRsaDecryptions(final BigInteger message, final long expectedEpoch) throws ResourceUnavailableException {
        logger.info("Starting threshold-RSA decryption process...");

        // Server configuration
        final int numShareholders = this.serverConfiguration.getNumServers();
        final int reconstructionThreshold = this.serverConfiguration.getReconstructionThreshold();

        // We create a thread pool with a thread for each task and remote server
        final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

        // The countdown latch tracks progress towards reaching a threshold
        final CountDownLatch latch = new CountDownLatch(reconstructionThreshold);
        final AtomicInteger failureCounter = new AtomicInteger(0);
        final int maximumFailures = (numShareholders - reconstructionThreshold);

        final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/sign?secretName=" + this.secretName
                    + "&message=" + message.toString();

            logger.info("Requesting partial RSA decryption from server " + serverId);

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

                    // Verify result
                    // TODO: Separate results by their epoch, wait for enough results of the same
                    // epoch
                    if ((responder == thisServerId) && (epoch == expectedEpoch)) {

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
                executor.shutdown();
                logger.info("Enough of shares was received.");
                return verifiedResults;
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
