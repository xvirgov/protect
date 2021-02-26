package com.ibm.pross.common.util.crypto.rsa;

import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

// Based on OAEP implementation in bouncycastle

public class OaepUtil {

    private static final Logger logger = LogManager.getLogger(OaepUtil.class);

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

    public static byte[] pad(byte[] message, int rsaModulusSize, int hashSize) throws NoSuchAlgorithmException {
        logger.info("Padding the message using OAEP...");
        int blockSize = rsaModulusSize / 8 - 10;

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

        // Generate the seed
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] seed = new byte[hashSize / 8];
        random.nextBytes(seed);

        // Mask the message block
        byte[] mask = maskGeneratorFunction1(seed, 0, seed.length, block.length - hashSize / 8);

        for (int i = hashSize / 8; i != block.length; i++) {
            block[i] ^= mask[i - hashSize / 8];
        }

        // Add in the seed
        System.arraycopy(seed, 0, block, 0, hashSize / 8);

        // Mask the seed
        mask = maskGeneratorFunction1(block, hashSize / 8, block.length - hashSize / 8, hashSize / 8);

        for (int i = 0; i != hashSize / 8; i++) {
            block[i] ^= mask[i];
        }

        logger.info("[DONE]");

        logger.info("BBBBBBBBBBBBBBBBBBBBBBBBBBBBEFORE encryption: " + Arrays.toString(block));
        return block;
    }

    public static byte[] unpad(byte[] data, int rsaModulusSize, int hashSize) {
        logger.info("Extracting the message from the OAEP-padded block...");
        logger.info("AAAAAAAAAAAAAAAAAAAAAAAAAAAAFTER decryption: " + Arrays.toString(data));

        int blockSize = rsaModulusSize / 8 - 10;
        byte[] block = new byte[blockSize];

        // Remove any leading zeroes that might be a result of encryption process
        int leadingZeroes = 0;
        while (data[leadingZeroes] == 0 && data.length - leadingZeroes > blockSize) {
            leadingZeroes++;
        }
        System.arraycopy(data, leadingZeroes, block, block.length - data.length + leadingZeroes, data.length - leadingZeroes);

        boolean shortData = (data.length < (hashSize / 8) + 1);

        // Unmask the seed
        byte[] mask = maskGeneratorFunction1(block, hashSize / 8, block.length - hashSize / 8, hashSize / 8);

        for (int i = 0; i != hashSize/8; i++) {
            block[i] ^= mask[i];
        }

        // Unmask the message
        mask = maskGeneratorFunction1(block, 0, hashSize/8, block.length - hashSize/8);
        for( int i = hashSize/8; i != block.length; i++) {
            block[i] ^= mask[i - hashSize/8];
        }

        // Find the data block
        int start = block.length;
        for (int index = 2*hashSize/8; index != block.length; index++) {
            if(block[index] != 0 & start == block.length) {
                start = index;
            }
        }

        boolean dataStartWrong = (start > (block.length - 1) | block[start] != 1);

        start++;


        logger.info(Arrays.toString(data));

        if ( shortData | dataStartWrong ) {
            logger.info("shortData : " + shortData);
            logger.info("dataStartWrong : " + dataStartWrong);
            throw new RuntimeException("Unpadding failed: wrong data");
        }

        // Extract the data block
        byte[] output = new byte[block.length - start];

        System.arraycopy(block, start, output, 0, output.length);

        logger.info("[DONE]");

        return output;
    }
}
