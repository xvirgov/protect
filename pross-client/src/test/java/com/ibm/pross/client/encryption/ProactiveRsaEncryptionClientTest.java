package com.ibm.pross.client.encryption;

import junit.framework.TestCase;
import org.junit.Test;

public class ProactiveRsaEncryptionClientTest extends TestCase {

    @Test
    public void testProactiveRsaEncryptionPerformance() {

        long timeNs = 0;

        final long start = System.nanoTime();



        final long end = System.nanoTime();

        timeNs = end - start;

        System.out.println("Time: " + timeNs + " ms");
    }
  
}