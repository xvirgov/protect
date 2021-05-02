package com.ibm.pross.common.util.crypto.kyber;

import junit.framework.TestCase;
import org.junit.Test;

import java.util.Arrays;

public class KyberUtilsTest extends TestCase {

    @Test
    public void testBytesToShortAndBack() {
        int size = 200;
        byte[] byteArr = new byte[size];

        for(int i = 0; i < size; i++) {
            byteArr[i] = (byte) i;
        }

        short[] shorts = KyberUtils.bytesToShorts(byteArr);
        byte[] bytes = KyberUtils.shortsToBytes(shorts);

        // not the same objects
        assertNotSame(byteArr, bytes);

        // same value
        assertTrue(Arrays.equals(byteArr, bytes));
    }

    @Test
    public void testShortsToBytesAndBase64() {
        int size = 200;
        short[] shorts = new short[size];

        for(int i = 0; i < size; i++) {
            shorts[i] = (short) i;
        }

        byte[] bytes = KyberUtils.shortsToBytes(shorts);
        String base64 = KyberUtils.bytesToBase64(bytes);
        byte[] afterBytes = KyberUtils.base64ToBytes(base64);
        short[] afterShorts = KyberUtils.bytesToShorts(afterBytes);

        assertTrue(Arrays.equals(bytes, afterBytes));
        assertTrue(Arrays.equals(shorts, afterShorts));
    }
}