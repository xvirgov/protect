package com.ibm.pross.common.util.pvss;

import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import junit.framework.TestCase;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class ProactiveRsaSharingGeneratorTest extends TestCase {
    private final int numServers = 5;
    private final int threshold = 3;

    @Test
    public void testRefreshAdditiveShares() throws InvalidKeySpecException, NoSuchAlgorithmException {
        List<ProactiveRsaShareholder> proactiveRsaShareholders = ProactiveRsaGenerator.generateProactiveRsa(numServers, threshold);

        List<ProactiveRsaSharing> proactiveRsaSharings = new ArrayList<>();
        for (int i = 0; i < numServers; i++) {
            proactiveRsaSharings.add(ProactiveRsaSharingGenerator.refreshAdditiveShares(i+1, proactiveRsaShareholders.get(i)));
        }

        assertEquals(numServers, proactiveRsaSharings.size());

        for(int i = 0; i < numServers; i++) {
            assertEquals(numServers, proactiveRsaSharings.get(i).getD_i_j().size());
            assertEquals(i+1, proactiveRsaSharings.get(i).getI());
        }
    }
}