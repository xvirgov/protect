package com.ibm.pross.common.util.crypto.kyber;

import com.ibm.pross.common.util.serialization.Parse;
import junit.framework.TestCase;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class KyberCiphertextTest extends TestCase {

    @Test
    public void testConcatination() {
        byte[] a1 = "aa".getBytes(StandardCharsets.UTF_8);
        byte[] a2 = "bb".getBytes(StandardCharsets.UTF_8);

        byte[] concat = Parse.concatenate(a1, a2);

        byte[] b1 = "cc".getBytes(StandardCharsets.UTF_8);

        byte[] concat2 = Parse.concatenate(concat, b1);

        byte[][] split = Parse.splitArrays(concat2);
        byte[][] split1 = Parse.splitArrays(split[0]);

        assertTrue(Arrays.equals(split1[0], a1));
    }

}