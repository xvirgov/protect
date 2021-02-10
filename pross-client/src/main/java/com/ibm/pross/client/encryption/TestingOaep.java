package com.ibm.pross.client.encryption;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class TestingOaep {
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 96;
    public static final int GCM_TAG_LENGTH = 128;
    public static final int HASH_LENGTH = 256;
    public static final int RSA_MODULUS_SIZE = 1024;

    /**
     * int to octet string.
     */
    private static void ItoOSP(
            int i,
            byte[] sp) {
        sp[0] = (byte) (i >>> 24);
        sp[1] = (byte) (i >>> 16);
        sp[2] = (byte) (i >>> 8);
        sp[3] = (byte) (i >>> 0);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private static byte[] maskGeneratorFunction1(
            byte[] Z,
            int zOff,
            int zLen,
            int length) {
        Digest mgf1Hash = DigestFactory.createSHA256();
        byte[] mask = new byte[length];
        byte[] hashBuf = new byte[mgf1Hash.getDigestSize()];
        byte[] C = new byte[4];
        int counter = 0;

        mgf1Hash.reset();

        while (counter < (length / hashBuf.length)) {
            ItoOSP(counter, C);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.update(C, 0, C.length);
            mgf1Hash.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, hashBuf.length);

            counter++;
        }

        if ((counter * hashBuf.length) < length) {
            ItoOSP(counter, C);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.update(C, 0, C.length);
            mgf1Hash.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, mask.length - (counter * hashBuf.length));
        }

        return mask;
    }

    // Based on OAEP implementation in bouncycastle
    public static byte[] pad(byte[] message) throws NoSuchAlgorithmException {
        System.out.println("Padding the message using OAEP...");
        int blockSize = RSA_MODULUS_SIZE / 8;

        // Check if the message can be padded
        if (message.length > blockSize) {
            throw new RuntimeException("Message size is too large! Padding failed.");
        }

        byte[] block = new byte[blockSize];

        // Copy message into the block
        System.arraycopy(message, 0, block, block.length - message.length, message.length);

        // Add sentinel
        block[block.length - message.length - 1] = 0x01;

        // Block is already zeroed - no need to add the padding string

        // Hash of the encoding parameters - TODO decide if we need to keep it

        // Generate the seed
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] seed = new byte[HASH_LENGTH / 8];
        random.nextBytes(seed);

        // Mask the message block
        byte[] mask = maskGeneratorFunction1(seed, 0, seed.length, block.length - HASH_LENGTH / 8);

        for (int i = HASH_LENGTH / 8; i != block.length; i++) {
            block[i] ^= mask[i - HASH_LENGTH / 8];
        }

        // Add in the seed
        System.arraycopy(seed, 0, block, 0, HASH_LENGTH / 8);

//        byte[] tmp = new byte[blockSize];
//        System.arraycopy(message, 0, tmp, tmp.length - message.length, message.length);
//        block[block.length - message.length - 1] = 0x01;
//        System.arraycopy(seed, 0, tmp, 0, HASH_LENGTH / 8);
//        System.out.println("Padded data without mask: " + Arrays.toString(tmp));


        // Mask the seed
        mask = maskGeneratorFunction1(block, HASH_LENGTH / 8, block.length - HASH_LENGTH / 8, HASH_LENGTH / 8);

        for (int i = 0; i != HASH_LENGTH / 8; i++) {
            block[i] ^= mask[i];
        }

        System.out.println("[DONE]");
        System.out.println("Padded data before enc: " + Arrays.toString(block));

        return block;
    }

    public static byte[] unpad(byte[] data) {
        System.out.println("Extracting the message from the OAEP-padded block...");
        System.out.println("Padded data after dec: " + Arrays.toString(data));

        int blockSize = RSA_MODULUS_SIZE / 8;
        byte[] block = new byte[blockSize];

        // Remove any leading zeroes that might be a result of encryption process
        System.arraycopy(data, 0, block, block.length - data.length, data.length);

        boolean shortData = (data.length < (2*HASH_LENGTH / 8) + 1);

        // Unmask the seed
        byte[] mask = maskGeneratorFunction1(block, HASH_LENGTH / 8, block.length - HASH_LENGTH / 8, HASH_LENGTH / 8);

        for (int i = 0; i != HASH_LENGTH/8; i++) {
            block[i] ^= mask[i];
        }

        // Unmask the message
        mask = maskGeneratorFunction1(block, 0, HASH_LENGTH/8, block.length - HASH_LENGTH/8);
        for( int i = HASH_LENGTH/8; i != block.length; i++) {
            block[i] ^= mask[i - HASH_LENGTH/8];
        }

        // Check the hash of encoding params - TODO decide if we need to keep it

        // Find the data block
        int start = block.length;
        for (int index = 2*HASH_LENGTH/8; index != block.length; index++) {
            if(block[index] != 0 & start == block.length) {
                start = index;
            }
        }

        boolean dataStartWrong = (start > (block.length - 1) | block[start] != 1);

        start++;

        System.out.println("After unmasking: " + Arrays.toString(block));

        if ( shortData | dataStartWrong ) {
            throw new RuntimeException("Unpadding failed: wrong data");
        }

        // Extract the data block
        byte[] output = new byte[block.length - start];

        System.arraycopy(block, start, output, 0, output.length);

        System.out.println("[DONE]");

        return output;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] data = "aaaaaaaaaaaaaa sdasd asd".getBytes();

        byte[] paddedData = pad(data);
        byte[] recoveredData = unpad(paddedData);

        System.out.println("Recovered data: " + Arrays.toString(recoveredData));
    }

}
