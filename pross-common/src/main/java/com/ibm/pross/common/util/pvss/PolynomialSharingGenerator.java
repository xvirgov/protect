package com.ibm.pross.common.util.pvss;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.shamir.Polynomials;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PolynomialSharingGenerator {

    public static PolynomialSharing refreshPolynomialShares(final int index, final ProactiveRsaShareholder proactiveRsaShareholder) {
        List<SecretShare> shamirShares = new ArrayList<>();
        List<SecretShare> b_i = new ArrayList<>();

        int numServers = proactiveRsaShareholder.getProactiveRsaPublicParameters().getNumServers();
        int threshold = proactiveRsaShareholder.getProactiveRsaPublicParameters().getThreshold();
        BigInteger additiveShare =  proactiveRsaShareholder.getD_i();
        BigInteger L = proactiveRsaShareholder.getProactiveRsaPublicParameters().getL();
        BigInteger coeffR = proactiveRsaShareholder.getProactiveRsaPublicParameters().getCoeffR();
        BigInteger modulus = proactiveRsaShareholder.getProactiveRsaPublicParameters().getPublicKey().getModulus();

        List<BigInteger> coefficients = RandomNumberGenerator.generateRandomArray(BigInteger.valueOf(threshold), coeffR);
        coefficients.set(0, additiveShare.multiply(L));

        for(int j = 0; j < numServers; j++) {
            shamirShares.add(Polynomials.evaluatePolynomial(coefficients, BigInteger.valueOf(j + 1), modulus)); // TODO don't use modulus here maybe
        }

        return new PolynomialSharing(shamirShares, b_i);
    }

    public static PolynomialSharing encryptPolynomialShares(final PolynomialSharing polynomialSharing, final PaillierPublicKey[] shareholderKeys) {
        List<SecretShare> shamirShares = polynomialSharing.getShares();
        List<SecretShare> encryptedShares = new ArrayList<>();

        for(int i = 0; i < shamirShares.size(); i++) {
            encryptedShares.add(new SecretShare(BigInteger.valueOf(i+1), PaillierCipher.encrypt(shareholderKeys[i], shamirShares.get(i).getY())));
        }

        return polynomialSharing.setShares(encryptedShares);
    }

}
