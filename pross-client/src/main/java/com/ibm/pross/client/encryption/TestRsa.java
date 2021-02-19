package com.ibm.pross.client.encryption;

import com.ibm.pross.client.util.RsaPublicParameters;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.rsa.OaepUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaShareConfiguration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.ShamirShare;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.InetAddress;
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

public class TestRsa {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, UnknownHostException, BadArgumentException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, DecoderException {
        int genEncDecTries = 3;
        int encDecTries = 10;
        int faults = 0;
        List<Float> failureRates = new ArrayList<>();

//        byte[] plaintext = "Aasdas ds dasf sdf sdfsd f".getBytes();
        byte[] plaintext = Hex.decodeHex("da6272fc".toCharArray());
        System.out.println("Plaintext: " + Hex.encodeHexString(plaintext));
        System.out.println(new BigInteger(1, plaintext));
        //        List<Byte> plaintextBytes = new ArrayList<>();
//        int[] arr = {-102, 43, -121, -110, 90, -115, -38, 96, 106, 16, -8, 36, 61, -112, -119, -65, -57, -110, -55, 102, -45, -36, -127, 30, -104, -69, -88, -111, -90, 22, -5, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 27, 127, 12, 67, 3, -58, -44, -64, 118, -39, -26, -118, 97, -81, -54, -112, 28, -48, -89, 50, 38, 113, 123, 52, -38, -118, -22, 69, 50, -126, 31, -23};
//        for (int el : arr) {
//            byte ele = (byte) el;
//        }


        final int numServers = 5;
        final int threshold = 3;

        List<InetSocketAddress> inetSocketAddresses = new ArrayList<InetSocketAddress>();
        for (int i = 0; i < 5; i++) {
            inetSocketAddresses.add(new InetSocketAddress(i));
        }

        ServerConfiguration serverConfiguration = new ServerConfiguration(numServers, 0, threshold, 0, 0, inetSocketAddresses);

        for(int gTr = 0; gTr < genEncDecTries; gTr++) {
            // Generate keys
            System.out.println("Generating threshold rsa keys...");
            final RsaSharing rsaSharing = RsaSharing.generateSharing(numServers, threshold);
            System.out.println("Done: ");
            System.out.println(rsaSharing);

            RsaPublicParameters rsaPublicParameters = new RsaPublicParameters(rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus(), rsaSharing.getV(), Arrays.asList(rsaSharing.getVerificationKeys().clone()), 0L);

            faults = 0;

            for(int tr = 0; tr < encDecTries; tr++) {

                try {
                    // Encrypt data
                    byte[] ciphertext = Exponentiation.modPow(new BigInteger(1, plaintext), rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getPublicKey().getModulus()).toByteArray();
                    System.out.println("Ciphertext: " + Arrays.toString(ciphertext));

                    // Decrypt data
                    List<BigInteger> shares = Arrays.stream(rsaSharing.getShares()).map(ShamirShare::getY).collect(Collectors.toList());
                    System.out.println(shares);

                    ServerPublicConfiguration serverPublicConfiguration = new ServerPublicConfiguration(numServers, threshold,
                            rsaSharing.getPublicKey().getModulus(), rsaSharing.getPublicKey().getPublicExponent(), rsaSharing.getV(), rsaSharing.getVerificationKeys());

                    List<SignatureResponse> partialDecryptions = new ArrayList<>();
                    for (int i = 0; i < threshold; i++) {
                        RsaShareConfiguration rsaShareConfiguration = new RsaShareConfiguration(serverPublicConfiguration, new ShamirShare(BigInteger.valueOf(i+1), shares.get(i)));
                        partialDecryptions.add(ThresholdSignatures.produceSignatureResponse(new BigInteger(1, ciphertext), rsaShareConfiguration));

                        // Validate decryption share
                        if(!RsaEncryptionClient.validateDecryptionShare(new BigInteger(1, ciphertext), partialDecryptions.get(i), rsaPublicParameters, serverConfiguration)) {
                            System.out.println("Share didnt pass validation");
                            faults++;
                            continue;
                        }
                    }
                    System.out.println("Validation of all shares passed");

                    byte[] resultPlaintext = RsaEncryptionClient.recoverPlaintext(new BigInteger(1, ciphertext), partialDecryptions, rsaPublicParameters, serverConfiguration).toByteArray();

                    System.out.println("FINNNNN:: " + Hex.encodeHexString(plaintext));
                    System.out.println("FINNNNN:: " + Hex.encodeHexString(resultPlaintext));

                    if(!(new BigInteger(1, resultPlaintext).equals(new BigInteger(1, plaintext)))) {
                        System.out.println("Decryption failed");
                        faults++;
                        continue;
                    }
                    System.out.println("Decryption succeeded");
                } catch (Exception ex) {
                    faults++;
                    System.out.println("Decryption failed with exception");
                    System.out.println(ex);
                }
            }
            failureRates.add(((float) faults)/((float)encDecTries));
        }

        System.out.println("Failure rates: ");
        System.out.println(failureRates);
    }

}
