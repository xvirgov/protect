package com.ibm.pross.client.encryption;

import com.ibm.pross.client.util.RsaPublicParameters;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.util.crypto.rsa.OaepUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaShareConfiguration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.ShamirShare;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.ibm.pross.client.encryption.RsaEncryptionClient.GCM_TAG_LENGTH;


public class TestRsaProactiveHybrid {

    public static int performHybridRsaEncDec(byte[] plaintext, RsaSharing rsaSharing, RsaPublicParameters rsaPublicParameters, ServerConfiguration serverConfiguration) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, BadArgumentException {
        try {
            byte[] ciphertext = RsaEncryptionClient.rsaAesEncrypt(plaintext, rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus());
            System.out.println("Ciphertext: " + new BigInteger(ciphertext));

            // Decrypt data
            List<BigInteger> shares = Arrays.stream(rsaSharing.getShares()).map(ShamirShare::getY).collect(Collectors.toList());
//            System.out.println(shares);

            byte[][] combined = Parse.splitArrays(ciphertext);

            if (combined.length != 3) {
                System.out.println("Not correctly encrypted");
                return 1;
            }

            BigInteger encryptedPaddedSecretKey = new BigInteger(1, combined[0]);
            final byte[] aesCiphertextData = combined[1];
            final byte[] plaintextHash = combined[2];

            System.out.println(new BigInteger(combined[0]));
            System.out.println("AAAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: " + new BigInteger(combined[0]).compareTo(BigInteger.ZERO));
            if (new BigInteger(combined[0]).compareTo(BigInteger.ZERO) < 0) {
                System.out.println("IT'S GOING TO FAIL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                System.out.println(new BigInteger(combined[0]));
            }

            ServerPublicConfiguration serverPublicConfiguration = new ServerPublicConfiguration(serverConfiguration.getNumServers(), serverConfiguration.getReconstructionThreshold(),
                    rsaSharing.getPublicKey().getModulus(), rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getV(), rsaSharing.getVerificationKeys());

            List<SignatureResponse> partialDecryptions = new ArrayList<>();
            for (int i = 0; i < serverConfiguration.getReconstructionThreshold(); i++) {
                RsaShareConfiguration rsaShareConfiguration = new RsaShareConfiguration(serverPublicConfiguration, new ShamirShare(BigInteger.valueOf(i+1), shares.get(i)));
                partialDecryptions.add(ThresholdSignatures.produceSignatureResponse(encryptedPaddedSecretKey, rsaShareConfiguration));

                // Validate decryption share
                if(!RsaEncryptionClient.validateDecryptionShare(encryptedPaddedSecretKey, partialDecryptions.get(i), rsaPublicParameters, serverConfiguration)) {
                    System.out.println("Share didnt pass validation");
                    return 1;
                }
            }
            System.out.println("Validation of all shares passed");

            byte[] recoveredPaddedSymmetricKey = RsaEncryptionClient.recoverPlaintext(encryptedPaddedSecretKey, partialDecryptions, rsaPublicParameters, serverConfiguration).toByteArray();

            final byte[] ivDec = Arrays.copyOfRange(aesCiphertextData, 0, RsaEncryptionClient.GCM_IV_LENGTH / 8);
            final byte[] encryptedDataDec = Arrays.copyOfRange(aesCiphertextData, RsaEncryptionClient.GCM_IV_LENGTH / 8, aesCiphertextData.length);

            final byte[] recoveredSymmetricKey = OaepUtil.unpad(recoveredPaddedSymmetricKey, RsaSharing.DEFAULT_RSA_KEY_SIZE, RsaEncryptionClient.HASH_LENGTH);
            SecretKey secretKeySpecDec = new SecretKeySpec(recoveredSymmetricKey, 0, recoveredSymmetricKey.length, "AES");

            Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpecDec = new GCMParameterSpec(GCM_TAG_LENGTH, ivDec);
            cipherDec.init(Cipher.DECRYPT_MODE, secretKeySpecDec, gcmParameterSpecDec);
            byte[] resultPlaintext = cipherDec.doFinal(encryptedDataDec);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(resultPlaintext);
            if (!Arrays.equals(hash, plaintextHash)) {
                return 1;
            }

            if(!Arrays.equals(plaintext, resultPlaintext)) {
                System.out.println("Decryption failed");
                return 1;
            }
            System.out.println("Decryption succeeded");
        }
        catch (Exception ex) {
            System.out.println(ex);
            return 1;
        }

        return 0;
    }

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, UnknownHostException, BadArgumentException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int genEncDecTries = 1;
        int encDecTries = 1;
        int faults = 0;
        List<Float> failureRates = new ArrayList<>();

        byte[] plaintext = "Aasdas ds dasf sdf sdfsd f".getBytes();

        final int numServers = 5;
        final int threshold = 3;

        List<InetSocketAddress> inetSocketAddresses = new ArrayList<InetSocketAddress>();
        for (int i = 0; i < 5; i++) {
            inetSocketAddresses.add(new InetSocketAddress(i));
        }

        ServerConfiguration serverConfiguration = new ServerConfiguration(numServers, 0, threshold, 0, 0, inetSocketAddresses);

        for(int gtr = 0; gtr < genEncDecTries; gtr++) {
            // Generate keys
            System.out.println("Generating threshold rsa keys...");
            final RsaSharing rsaSharing = RsaSharing.generateSharing(numServers, threshold);
            System.out.println("Done: ");
            System.out.println(rsaSharing);

//            RsaPublicParameters rsaPublicParameters = new RsaPublicParameters(rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus(), rsaSharing.getV(), Arrays.asList(rsaSharing.getVerificationKeys().clone()), 0L);
//
//            faults = 0;
//            for(int tr = 0; tr < encDecTries; tr++) {
//
//                try {
//                    faults += performHybridRsaEncDec(plaintext, rsaSharing, rsaPublicParameters, serverConfiguration);
//                } catch (Exception ex) {
//                    faults++;
//                    System.out.println("Decryption failed with exception");
//                    System.out.println(ex);
//                }
//
//                if(faults > 0) {
//                    System.out.println("oh no");
//                }
//            }
//            failureRates.add(((float) faults)/((float)encDecTries));

//            System.out.println("Number of tries: " + encDecTries);
//            System.out.println("Number of fails: " + faults);
        }
//        System.out.println("Failure rates: ");
//        System.out.println(failureRates);
//        System.out.println("Plaintext after decryption: " + Arrays.toString(resultPlaintext));
    }

}
