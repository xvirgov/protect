package com.ibm.pross.client.encryption;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.kyber.Kyber;
import com.ibm.pross.common.util.crypto.kyber.KyberCiphertext;
import com.ibm.pross.common.util.crypto.kyber.KyberPublicParameters;
import com.ibm.pross.common.util.crypto.kyber.KyberUtils;
import com.ibm.pross.common.util.crypto.rsa.OaepUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaPublicParameters;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.provider.digest.SHA3;
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

public class KyberEncryptionClient extends BaseClient {

    public static final int AES_KEY_SIZE = 128;
    public static final int GCM_IV_LENGTH = 96;
    public static final int GCM_TAG_LENGTH = 128;
    public static final int HASH_LENGTH = 128;

    private static final Logger logger = LogManager.getLogger(KyberEncryptionClient.class);

    public KyberEncryptionClient(final ServerConfiguration serverConfiguration,
                                 final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
                                 final X509Certificate clientCertificate, PrivateKey clientTlsKey) {

        super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

    }

    public static byte[] kyberEncrypt(final byte[] message, final KyberPublicParameters kyberPublicParameters) {

//        try {
//            // Create arrays
//            byte[] iv = new byte[GCM_IV_LENGTH / 8];
//
//            // Create a random source
//            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//
//            // Initialise iv and salt
//            logger.info("Initialising iv...");
//            random.nextBytes(iv);
//            logger.info("[DONE]");
//
//            // Initialise random and generate session key
//            logger.info("Generating session key...");
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//            keyGenerator.init(AES_KEY_SIZE, random);
//            SecretKey secretKey = keyGenerator.generateKey();
//            logger.info("[DONE]");
//
//            // Encrypt data using AES
//            logger.info("Encrypting data using AES-GCM...");
//            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
//            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
//            byte[] encrypted = cipher.doFinal(message);
//            logger.info("[DONE]");
//
//            // Concatenate salt, iv and encryption result
//            logger.info("Concatenating iv and encrypted data to create a result of AES-GCM encryption...");
//            byte[] result = new byte[encrypted.length + iv.length];
//            System.arraycopy(iv, 0, result, 0, iv.length);
//            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
//            logger.info("[DONE]");
//
//            // Compute hash
//            logger.info("Computing hash of plaintext...");
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            final byte[] hash = digest.digest(message);
//            logger.info("[DONE]");
//
//            byte[] paddedSecretKey = OaepUtil.pad(secretKey.getEncoded(), RsaSharing.DEFAULT_RSA_KEY_SIZE, HASH_LENGTH);
//
//            logger.debug("BEFORE ENCRYPTION: " + Arrays.toString(paddedSecretKey));
//
//            logger.info("Modulus: " + modulus.toString(2).length());
//
//            // Encrypt symmetric key with RSA
//            logger.info("Encrypting AES key with threshold RSA...");
//            final byte[] symmetricKeyCiphertext = Exponentiation.modPow(new BigInteger(1, paddedSecretKey), exponent, modulus).toByteArray();
//            logger.info("[DONE]");
//
//            logger.info("Encryption process finished");

        try {
            // random, hashed m
            logger.info("Generating randmo m...");
            byte[] m = new byte[Kyber.KYBER_SYMBYTES];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(m);

            SHA3.DigestSHA3 mdH = new SHA3.DigestSHA3(256);
            mdH.update(m);
            m = mdH.digest();
            logger.info("[DONE]");

            // H(pk)
            logger.info("Hashing pk...");
            mdH.reset();
            for(int i = 0; i < kyberPublicParameters.getPk().size(); i++) {
                mdH.update(KyberUtils.shortsToBytes(kyberPublicParameters.getPk().get(i).poly));
            }
            byte[] hashedPk = mdH.digest();
            logger.info("[DONE]");

            // K||r = G(m || H(pk))
            logger.info("Hashing m with pk...");
            SHA3.DigestSHA3 mdG = new SHA3.DigestSHA3(512);
            mdG.update(Parse.concatenate(m, hashedPk));
            byte[] kr = mdG.digest();

            byte[] K1 = Arrays.copyOfRange(kr, 0, Kyber.KYBER_SYMBYTES);
            byte[] r = Arrays.copyOfRange(kr,  Kyber.KYBER_SYMBYTES, kr.length);
            logger.info("[DONE]");

            // c := Kyber.CPAPKE.Enc(pk,m,r)
            logger.info("Encrypting random m...");
            KyberCiphertext kyberCiphertext = Kyber.indcpa_enc_no_gen_mat(m, kyberPublicParameters.getPk(), kyberPublicParameters.getAtCombined(), r);
            logger.info("[DONE]");

            // H(c)
            logger.info("Hashing ciphertext...");
            mdH.reset();
            mdH.update(kyberCiphertext.toByteArray());
//            for(int i = 0; i < kyberCiphertext.getC1().size(); i++) {
//                mdH.update(KyberUtils.shortsToBytes(kyberCiphertext.getC1().get(i).poly));
//            }
//            mdH.update(KyberUtils.shortsToBytes(kyberCiphertext.getC2().poly));
            byte[] hc = mdH.digest();
            logger.info("[DONE]");

            // K := KDF(K1 || H(C))
            logger.info("Using KDF to generate key...");
            byte[] K1_HC = Parse.concatenate(K1, hc);
            SHAKEDigest kdf = new SHAKEDigest(256);
            kdf.update(K1_HC, 0, K1_HC.length);
            byte[] K = new byte[Kyber.KYBER_SYMBYTES];
            kdf.doFinal(K, 0, Kyber.KYBER_SYMBYTES);
            logger.info("[DONE]");

            logger.info("KDF BEFORE::: " + Arrays.toString(K));

            // use K to encrypt secret
            byte[] iv = new byte[GCM_IV_LENGTH / 8];
            logger.info("Initialising iv...");
            random.nextBytes(iv);
            logger.info("[DONE]");

            SecretKeySpec secretKeySpec = new SecretKeySpec(K, "AES");

            logger.info("Encrypting data using AES-GCM...");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] encrypted = cipher.doFinal(message);
            logger.info("[DONE]");

            logger.info("ECRYPTED PLAINTEXT:: " + Arrays.toString(encrypted));

            logger.info("Concatenating iv and encrypted data to create a result of AES-GCM encryption...");
            byte[] result = new byte[encrypted.length + iv.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            logger.info("[DONE]");

            logger.info("Computing hash of plaintext...");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(message);
            logger.info("[DONE]");

            logger.info("ENCRYPTED PLAINTEXT::: " + Arrays.toString(encrypted));
            logger.info("KEY::: " + Arrays.toString(K));
            logger.info("IV::: " + Arrays.toString(iv));
            logger.info("PLAINTEXT::: " + Arrays.toString(message));


            byte[] concatenatedAesParams = Parse.concatenate(result, hash);

            // concat encryption of m, and AES encryption of plaintext

//            final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
//            md1.update(new byte[]{1, 2, 4, 5, 6, 7});
//            byte[] m = md1.digest();
//
//            logger.info("ENCRETING:: " + Arrays.toString(m));
//
//            final SHA3.DigestSHA3 md2 = new SHA3.DigestSHA3(256);
//            md2.update(new byte[]{2, 3});
//            byte[] coins = md2.digest();
//            md2.update(new byte[]{1, 2, 3});
//            byte[] coins1 = md2.digest();

            return Parse.concatenate(concatenatedAesParams, kyberCiphertext.toByteArray());
//            return Parse.concatenate(kyberCiphertext.toByteArray());
        } catch (GeneralSecurityException e) {
            logger.error(e);
            throw new RuntimeException(e);
        }

    }

    public static BigInteger recoverPlaintext(final BigInteger ciphertext,
                                              final List<SignatureResponse> signatureResponses, final ProactiveRsaPublicParameters rsaPublicParameters,
                                              final ServerConfiguration serverConfiguration) throws BadArgumentException {

        logger.info("recoverPlaintext");

        // Extract values from configuration
        final BigInteger n = rsaPublicParameters.getPublicKey().getModulus();
        final int threshold = serverConfiguration.getReconstructionThreshold();

        // Determine coordinates
        List<BigInteger> xCoords = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            xCoords.add(signatureResponses.get(i).getServerIndex());
        }

        // Interpolate polynomial
        BigInteger L = rsaPublicParameters.getL();
        BigInteger preFactor = ciphertext.modPow(L.pow(3).multiply(rsaPublicParameters.getD_pub()), rsaPublicParameters.getPublicKey().getModulus());
        BigInteger gamma = BigInteger.ONE;
        for (int i = 0; i < threshold; i++) {
            final BigInteger decryptionShareCurrentIndex = xCoords.get(i);
            final BigInteger decryptionShareValue = signatureResponses.get(i).getSignatureShare();
            final BigInteger lambda_0j = Polynomials.interpolateNoModulus(xCoords, L, BigInteger.ZERO, decryptionShareCurrentIndex);
            gamma = gamma.multiply(decryptionShareValue.modPow(lambda_0j, rsaPublicParameters.getPublicKey().getModulus()));
        }
        gamma = preFactor.multiply(gamma).mod(rsaPublicParameters.getPublicKey().getModulus());

        final BigInteger a = rsaPublicParameters.getaGcd();
        final BigInteger b = rsaPublicParameters.getbGcd();

        return Exponentiation.modPow(gamma, a, n).multiply(Exponentiation.modPow(ciphertext, b, n)).mod(n);
    }

    public static boolean validateDecryptionShare(final BigInteger ciphertext, final SignatureResponse decryptionShare,
                                                  final ProactiveRsaPublicParameters rsaPublicParameters) {
        final int n = rsaPublicParameters.getNumServers();
        final BigInteger modulus = rsaPublicParameters.getPublicKey().getModulus();
        final BigInteger g = rsaPublicParameters.getG();
        final BigInteger index = decryptionShare.getServerIndex();
        final BigInteger verificationShare = rsaPublicParameters.getbAgent().get(index.intValue() - 1).getY();
        final BigInteger c = decryptionShare.getSignatureShareProof().getC();
        final BigInteger recomputedC = ThresholdSignatures.recomputeC(ciphertext, n, modulus, g, verificationShare, decryptionShare);
        return recomputedC.equals(c);
    }

    public byte[] kyberDecrypt(final byte[] ciphertextData, KyberPublicParameters kyberPublicParameters, ServerConfiguration serverConfiguration, String secretName) throws BadPaddingException, ResourceUnavailableException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadArgumentException {

//        final byte[][] combined = Parse.splitArrays(ciphertextData);
//        if (combined.length != 3) {
//            throw new BadPaddingException("Invalid ciphertext");
//        }

//        BigInteger encryptedPaddedSecretKey = new BigInteger(1, combined[0]);
//        final byte[] aesCiphertextData = combined[1];
//        final byte[] plaintextHash = combined[2];

        byte[][] parts = Parse.splitArrays(ciphertextData);

        //        final byte[] aesCiphertextData = combined[1];
//        final byte[] plaintextHash = combined[2];

        byte[][] concatenatedAesParams = Parse.splitArrays(parts[0]);
        byte[] aesCiphertextData = concatenatedAesParams[0];
        byte[] plaintextHash = concatenatedAesParams[1];

        KyberCiphertext kyberCiphertext = KyberCiphertext.getCiphertext(parts[1]);

        // Get partial decryption shares
//        final List<SignatureResponse> decryptionShares = requestPartialRsaDecryptions(encryptedPaddedSecretKey, rsaPublicParameters.getEpoch(), serverConfiguration, secretName)
//                .stream().map(obj -> (SignatureResponse) obj).collect(Collectors.toList());
        final List<Kyber.Polynomial> decryptionShares = requestPartialKyberDecryptions(parts[1], kyberPublicParameters, serverConfiguration, secretName)
                .stream().map(obj -> (Kyber.Polynomial) obj).collect(Collectors.toList());

        byte[] combined = Kyber.combine_dec_shares(kyberCiphertext, decryptionShares);

        // H(pk)
        SHA3.DigestSHA3 mdH = new SHA3.DigestSHA3(256);
        mdH.reset();
        for(int i = 0; i < kyberPublicParameters.getPk().size(); i++) {
            mdH.update(KyberUtils.shortsToBytes(kyberPublicParameters.getPk().get(i).poly));
        }
        byte[] hashedPk = mdH.digest();

        // K||r = G(m || H(pk))
        SHA3.DigestSHA3 mdG = new SHA3.DigestSHA3(512);
        mdG.update(Parse.concatenate(combined, hashedPk));
        byte[] kr = mdG.digest();

        byte[] K1 = Arrays.copyOfRange(kr, 0, Kyber.KYBER_SYMBYTES);
//        byte[] r = Arrays.copyOfRange(kr,  Kyber.KYBER_SYMBYTES, kr.length);

        // H(c)
        mdH.reset();
        mdH.update(kyberCiphertext.toByteArray());
        byte[] hc = mdH.digest();

        // K := KDF(K1 || H(C))
        byte[] K1_HC = Parse.concatenate(K1, hc);
        SHAKEDigest kdf = new SHAKEDigest(256);
        kdf.update(K1_HC, 0, K1_HC.length);
        byte[] K = new byte[Kyber.KYBER_SYMBYTES];
        kdf.doFinal(K, 0, Kyber.KYBER_SYMBYTES);

        // decrypt using AES
        // Get decrypted parameters of AES
        final byte[] ivDec = Arrays.copyOfRange(aesCiphertextData, 0, GCM_IV_LENGTH / 8);
        final byte[] encryptedDataDec = Arrays.copyOfRange(aesCiphertextData, GCM_IV_LENGTH / 8, aesCiphertextData.length);

        SecretKey secretKeySpecDec = new SecretKeySpec(K, "AES");

        logger.info("Decrypting data using retrieved values...");
        Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpecDec = new GCMParameterSpec(GCM_TAG_LENGTH, ivDec);
        cipherDec.init(Cipher.DECRYPT_MODE, secretKeySpecDec, gcmParameterSpecDec);
        byte[] resultPlaintext = cipherDec.doFinal(encryptedDataDec);
        logger.info("[DONE]");

        logger.info("DECRYPTING::: " + Arrays.toString(encryptedDataDec));
        logger.info("KEY::: " + Arrays.toString(K));
        logger.info("IV::: " + Arrays.toString(ivDec));
        logger.info("RECOEVERD::: " + Arrays.toString(resultPlaintext));

        logger.info("Checking hash of recovered plaintext...");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(resultPlaintext);
        if (!Arrays.equals(hash, plaintextHash)) {
            throw new RuntimeException("Hashes of plaintexts don't match!");
        }
        logger.info("[DONE]");

        return resultPlaintext;


//        logger.info("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
//        logger.info("DECRYPTED:: " + Arrays.toString(combined));
//
//        logger.info("Decryption shares generated");

        // Perform validation of decryption shares
//        List<SignatureResponse> validatedDecryptionShares = new ArrayList<>();
//        for (SignatureResponse decryptionShare : decryptionShares) {
//            BigInteger serverIndex = decryptionShare.getServerIndex();
//
//            try {
//                if (validateDecryptionShare(encryptedPaddedSecretKey, decryptionShare, rsaPublicParameters)) {
//                    validatedDecryptionShares.add(decryptionShare);
//                    logger.debug("Decryption share from server " + serverIndex + " passed validation");
//                } else {
//                    logger.info(serverIndex);
//                    logger.error("Decryption share from server " + serverIndex + " failed validation, excluding from operation");
//                }
//            } catch (Exception exception) {
//                logger.error("Decryption share from server " + serverIndex + " failed validation, excluding from operation, error = " + exception);
//            }
//        }
//        logger.info("Number of validated shares: " + validatedDecryptionShares.size());
//        logger.info("[DONE]");

        // Decrypt symmetric key with threshold RSA
//        final byte[] recoveredPaddedSymmetricKey = recoverPlaintext(encryptedPaddedSecretKey, validatedDecryptionShares, rsaPublicParameters, serverConfiguration).toByteArray();

//        logger.debug("RECOVERED SECRET: " + Arrays.toString(recoveredPaddedSymmetricKey));
//        logger.debug("Encrypted data: " + aesCiphertextData.length);
//
//        // Get decrypted parameters of AES
//        final byte[] ivDec = Arrays.copyOfRange(aesCiphertextData, 0, GCM_IV_LENGTH / 8);
//        final byte[] encryptedDataDec = Arrays.copyOfRange(aesCiphertextData, GCM_IV_LENGTH / 8, aesCiphertextData.length);
//
//        // Reverse OAEP padding on decrypted AES key
//        final byte[] recoveredSymmetricKey = OaepUtil.unpad(recoveredPaddedSymmetricKey, RsaSharing.DEFAULT_RSA_KEY_SIZE, HASH_LENGTH);
//        SecretKey secretKeySpecDec = new SecretKeySpec(recoveredSymmetricKey, 0, recoveredSymmetricKey.length, "AES");
//
//        logger.info("Decrypting data using retrieved values...");
//        Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
//        GCMParameterSpec gcmParameterSpecDec = new GCMParameterSpec(GCM_TAG_LENGTH, ivDec);
//        cipherDec.init(Cipher.DECRYPT_MODE, secretKeySpecDec, gcmParameterSpecDec);
//        byte[] resultPlaintext = cipherDec.doFinal(encryptedDataDec);
//        logger.info("[DONE]");
//
//        logger.info("Checking hash of recovered plaintext...");
//        MessageDigest digest = MessageDigest.getInstance("SHA-256");
//        final byte[] hash = digest.digest(resultPlaintext);
//        if (!Arrays.equals(hash, plaintextHash)) {
//            throw new RuntimeException("Hashes of plaintexts don't match!");
//        }
//        logger.info("[DONE]");

//        return combined;
    }

    private List<Object> requestPartialKyberDecryptions(final byte[] message, KyberPublicParameters kyberPublicParameters, final ServerConfiguration serverConfiguration, String secretName) throws ResourceUnavailableException {
        logger.info("Starting kyber decryption process...");

        // Server configuration
        final int numShareholders = serverConfiguration.getNumServers();
        final int reconstructionThreshold = serverConfiguration.getReconstructionThreshold();

        // We create a thread pool with a thread for each task and remote server
        final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

        // The countdown latch tracks progress towards reaching a threshold
        final CountDownLatch latch = new CountDownLatch(numShareholders); // n-out-of-n
        final AtomicInteger failureCounter = new AtomicInteger(0);
        final int maximumFailures = (numShareholders - numShareholders);

        final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());

        // Create a partial result task for everyone except ourselves
        int serverId = 0;
        for (final InetSocketAddress serverAddress : serverConfiguration.getServerAddresses()) {
            serverId++;
            final String serverIp = serverAddress.getAddress().getHostAddress();
            final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
            final String linkUrl = "https://" + serverIp + ":" + serverPort + "/sign?secretName=" + secretName;

            logger.info("Requesting partial kyber decryption from server " + serverId);

            final int thisServerId = serverId;

            JSONObject jMessage = new JSONObject();

            jMessage.put("message", KyberUtils.bytesToBase64(message));

            // Create new task to get the partial exponentiation result from the server
            executor.submit(new PartialResultTask(this, serverId, linkUrl, jMessage.toJSONString() + "\n", "POST", verifiedResults, latch, failureCounter,
                    maximumFailures) {
                @Override
                protected void parseJsonResult(final String json) throws Exception {

                    // Parse JSON
                    final JSONParser parser = new JSONParser();
                    final Object obj = parser.parse(json);
                    final JSONObject jsonObject = (JSONObject) obj;
//                    final long epoch = Long.parseLong(jsonObject.get("epoch").toString());

                    logger.info("ResponseeeeeeEE: " + jsonObject.get("signatureResponse").toString());

                    final String signatureResponseJson = jsonObject.get("signatureResponse").toString();

                    final Kyber.Polynomial decryptionShare = new Kyber.Polynomial(KyberUtils.bytesToShorts(KyberUtils.base64ToBytes(signatureResponseJson)));

                    // Verify result
                    // TODO: Separate results by their epoch, wait for enough results of the same
                    // epoch
//                    if ((signatureResponse.getServerIndex().equals(BigInteger.valueOf(thisServerId)))) {

                    verifiedResults.add(decryptionShare);

                    // Everything checked out, increment successes
                    latch.countDown();
//                    } else {
//                        throw new Exception(
//                                "Server " + thisServerId + " sent inconsistent results (likely during epoch change)");
//                    }

                }
            });
        }

        try {
            // Once we have K successful responses we can interpolate our share
            latch.await();

            // Check that we have enough results to interpolate the share
            if (failureCounter.get() <= maximumFailures) {
                executor.shutdown();
                logger.info("Enough of shares was received, number of indices: " + verifiedResults.size());
                return verifiedResults;
            } else {
                executor.shutdown();
                throw new ResourceUnavailableException();
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptStream(final String secretName, InputStream inputStream) throws BelowThresholdException, ResourceUnavailableException, IOException {
        logger.info("Starting Kyber encryption with secret " + secretName);

//        ProactiveRsaPublicParameters rsaPublicParameters = this.getProactiveRsaPublicParams(secretName);
        KyberPublicParameters kyberPublicParameters = this.getKyberPublicParams(secretName);

        final byte[] plaintextData = IOUtils.toByteArray(inputStream);

//        final SHA3.DigestSHA3 md1 = new SHA3.DigestSHA3(256);
//        md1.update(new byte[]{1, 2});
//        byte[] plaintextData = md1.digest();

        final byte[] hybridCiphertext = kyberEncrypt(plaintextData, kyberPublicParameters);

        logger.info("[DONE]");

        return hybridCiphertext;
    }

    public byte[] decryptStream(final String secretName, InputStream inputStream) throws IOException, BelowThresholdException, ResourceUnavailableException, BadArgumentException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        logger.info("Starting RSA decryption with secret " + secretName + "...");

        // Store byte input stream into array
        final byte[] ciphertextData = IOUtils.toByteArray(inputStream);

        // Get Kyber public parameters
        KyberPublicParameters kyberPublicParameters = this.getKyberPublicParams(secretName);

        // Decrypt the ciphertext with RSA-AES
        byte[] resultPlaintext = kyberDecrypt(ciphertextData, kyberPublicParameters, serverConfiguration, secretName);

        logger.info("Decryption process finished");

        return resultPlaintext;
    }

}
