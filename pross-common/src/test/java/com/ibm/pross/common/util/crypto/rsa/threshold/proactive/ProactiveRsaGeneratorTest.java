package com.ibm.pross.common.util.crypto.rsa.threshold.proactive;

import junit.framework.TestCase;
import org.json.simple.JSONObject;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class ProactiveRsaGeneratorTest extends TestCase {
    private final int numServers = 5;
    private final int threshold = 5;

    @Test
    public void testGenerateRsaProactiveShareholders() throws InvalidKeySpecException, NoSuchAlgorithmException {
        List<ProactiveRsaShareholder> proactiveRsaShareholders = ProactiveRsaGenerator.generateProactiveRsa(numServers, threshold);

        assertEquals(proactiveRsaShareholders.size(), numServers);
    }

    @Test
    public void testJsonToObjectAndBack() throws InvalidKeySpecException, NoSuchAlgorithmException {
        List<ProactiveRsaShareholder> proactiveRsaShareholders = ProactiveRsaGenerator.generateProactiveRsa(numServers, threshold);

        for(int i = 0; i < numServers; i++) {
            JSONObject jsonObject = proactiveRsaShareholders.get(i).getJson();

            ProactiveRsaShareholder recreatedShareHolderFromJson = ProactiveRsaShareholder.getParams(jsonObject);

            assertTrue(proactiveRsaShareholders.get(i).equals(recreatedShareHolderFromJson));
        }
    }

}