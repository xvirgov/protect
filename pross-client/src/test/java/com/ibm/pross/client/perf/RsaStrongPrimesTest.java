package com.ibm.pross.client.perf;

import com.ibm.pross.common.util.Primes;
import org.junit.Test;

import java.io.*;
import java.math.BigInteger;

public class RsaStrongPrimesTest {
    final int[] lengths = new int[]{3072, 4096, 7680};
//    final int[] lengths = new int[]{512, 1024};
    long total, start, end;
    int iterations = 10;

    @Test
    public void testGenerateStrongPrimes() throws IOException {
        File file1 = new File("primes-gen-time.csv");
        File file2 = new File("primes.csv");
        file1.delete();
        file2.delete();

        for(int i = 0; i < lengths.length; i++) {
            int primeLength = lengths[i]/2;

            for(int j = 0; j < iterations; j++) {
                start = System.nanoTime();
                final BigInteger p = Primes.generateSafePrime(primeLength);
                end = System.nanoTime();

                total = end - start;

                try (BufferedWriter bw = new BufferedWriter(new FileWriter(file2, true))) {
                    bw.write(primeLength + " : " + p.toString() + "\n");
                }
                try (BufferedWriter bw = new BufferedWriter(new FileWriter(file1, true))) {
                    if(j > 0)
                        bw.write(",");

                    bw.write(String.valueOf(total));

                    if(j == iterations-1)
                        bw.write("\n");
                }
            }


        }
    }

}
