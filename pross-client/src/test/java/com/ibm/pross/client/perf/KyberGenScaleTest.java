package com.ibm.pross.client.perf;

import com.ibm.pross.client.encryption.ProactiveRsaEncryptionClient;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.kyber.Kyber;
import com.ibm.pross.common.util.crypto.kyber.KyberKeyGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaPublicParameters;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class KyberGenScaleTest {
       final int iterations = Integer.parseInt(System.getProperty("iterations"));
//    final int iterations = 100;
    final int startIter = 0;
    final int total_iterations =  iterations + startIter;
    final BigInteger e = BigInteger.valueOf(65537);
    List<Integer> numServersChoice = Arrays.asList(10, 20, 30);
    List<Double> thresChoice = Arrays.asList(0.5, 0.75, 1.0);
    long start, end;
    int maxAgents = 15;
    int minAgents = 5;
    int step = 5;
    List<Integer> securityLevels = Arrays.asList(128, 192);

    @Test
    public void testOverallKyberKeyGen() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        // First line - indices on x axis - number of agents
//        String firstLine = "";
//        for (int numServers = minAgents; numServers <= maxAgents; numServers += step) {
//            if (numServers > minAgents)
//                firstLine = firstLine.concat(",");
//            firstLine = firstLine.concat(String.valueOf(numServers));
//        }
//        firstLine = firstLine.concat("\n");

//        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file1, true))) {
//            bw.write(firstLine);
//        }

        for (int sl = 1; sl < securityLevels.size(); sl++) {
            for (int numServers = minAgents; numServers <= maxAgents; numServers += step) {
                int threshold = (int) (numServers);

                File file1 = new File("KyberGenScaleTest-" + numServers + "-" + threshold + "-" + securityLevels.get(sl) +".csv");
                file1.delete();


//                BigInteger accu = BigInteger.ZERO;
                StringBuilder line = new StringBuilder();
                for (int it = 0; it < total_iterations; it++) {

                    start = System.nanoTime();
                    CommonConfiguration.KYBER_K = sl + 2;

                    KyberKeyGenerator.generateKyber(numServers, Kyber.KYBER_N, sl + 2, Kyber.KYBER_Q, Kyber.KYBER_ETA1, Kyber.KYBER_ETA2);

                    end = System.nanoTime();

//                    if (it >= startIter) {
//                        accu = accu.add(BigInteger.valueOf(end - start));
//                    }

                    if (it > startIter)
                        line.append(",");
                    if (it >= startIter)
                        line.append(end - start);
                }

                try (BufferedWriter bw = new BufferedWriter(new FileWriter(file1, true))) {
                    bw.write(line.toString());
//                    if (numServers > minAgents)
//                        bw.write(",");
//
//                    bw.write(String.valueOf(accu.divide(BigInteger.valueOf(iterations))));
//
//                    if (numServers == maxAgents)
//                        bw.write("\n");
                }
//                System.out.println(numServers + " : " + accu.divide(BigInteger.valueOf(iterations)));
            }
        }
    }

}
