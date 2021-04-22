package com.ibm.pross.client.generation;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.Primes;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.pvss.PublicSharingGenerator;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import junit.framework.TestCase;
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
import java.util.List;
import java.util.stream.Collectors;

public class EciesKeyGeneratorClientTest extends TestCase {

    final int ITERATIONS = 10;
    final int[] lengths = new int[]{1024, 2048, 3072, 4096};

    public static final int DEFAULT_RSA_KEY_SIZE = 1024;
    public static final int DEFAULT_TAU = 80;
    public static final BigInteger DEFAULT_PARAMETER_R = BigInteger.valueOf(2).pow(10);
    int numServers = 5;
    int threshold = 3;
    int tau = DEFAULT_TAU;
    BigInteger r = DEFAULT_PARAMETER_R;

    @Test
    public void testProactiveRsaSafePrimesPerformance() {

        long timeGen = 0, timeVerify = 0, start, end;

        List<List<BigInteger>> times_all = new ArrayList<>();

        for(int i = 0; i < lengths.length; i++) {

            List<BigInteger> times_current = new ArrayList<>();
            for(int it = 0; it < ITERATIONS; it++) {
                start = System.nanoTime();

                final BigInteger secret = RandomNumberGenerator.generateRandomInteger(PublicSharingGenerator.curve.getR());

                end = System.nanoTime();
                times_current.add(BigInteger.valueOf(end-start));
            }

            times_all.add(times_current);
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(new File("safe-primes-res.csv")))) {
            for(int i = 0; i < lengths.length; i++) {
                bw.write(times_all.get(i).stream().map(Object::toString).collect(Collectors.joining(",")));
                bw.write("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


}