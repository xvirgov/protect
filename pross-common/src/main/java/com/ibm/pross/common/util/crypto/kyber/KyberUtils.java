package com.ibm.pross.common.util.crypto.kyber;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;

public class KyberUtils {

    public static byte[] shortsToBytes(final short[] shorts) {
        byte[] out = new byte[shorts.length * 2];
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().put(shorts);
        return out;
    }

    public static short[] bytesToShorts(final byte[] bytes) {
        short[] out = new short[bytes.length / 2];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(out);
        return out;
    }

    public static String bytesToBase64(final byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] base64ToBytes(final String string) {
        return Base64.getDecoder().decode(string);
    }

}
