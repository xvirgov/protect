package com.ibm.pross.common.util.pvss;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ProactiveRsaSharingGenerator {

    public static ProactiveRsaSharing refreshAdditiveShares(final int index, final ProactiveRsaShareholder proactiveRsaShareholder) {
        List<SecretShare> d_i_j = new ArrayList<>();
        List<SecretShare> w_i_j = new ArrayList<>();
        SecretShare d_i_pub;

        final BigInteger d_i = proactiveRsaShareholder.getD_i();
        final int numServers = proactiveRsaShareholder.getProactiveRsaPublicParameters().getNumServers();
        final BigInteger rPrime = proactiveRsaShareholder.getProactiveRsaPublicParameters().getBigR().divide(BigInteger.valueOf(numServers));
        final BigInteger g = proactiveRsaShareholder.getProactiveRsaPublicParameters().getG();
        final BigInteger modulus = proactiveRsaShareholder.getProactiveRsaPublicParameters().getPublicKey().getModulus();

        for (int i = 0; i < numServers; i++) {
            BigInteger additiveShare = RandomNumberGenerator.generateRandomInteger(rPrime.multiply(BigInteger.valueOf(2)));
            d_i_j.add(new SecretShare(BigInteger.valueOf(i+1), additiveShare));
            w_i_j.add(new SecretShare(BigInteger.valueOf(i+1), g.modPow(additiveShare, modulus)));

//            System.out.println("G: " + g);
//            System.out.println("MODULUS: " + modulus);
//            System.out.println("w_i_j FROM " + index+ " to "+ (i+1) + " received " + w_i_j.get(i));
//            System.out.println("d_i_j FROM " + index+ " to "+ (i+1) + " received " + d_i_j.get(i));
        }

        d_i_pub = new SecretShare(BigInteger.valueOf(index), d_i.subtract(d_i_j.stream().map(SecretShare::getY).reduce(BigInteger::add).get()));

        return new ProactiveRsaSharing(index, d_i_j, d_i_pub, w_i_j);
    }

    public static ProactiveRsaSharing encryptAdditiveShares(final ProactiveRsaSharing proactiveRsaSharing, final PaillierPublicKey[] shareholderKeys) {
        List<SecretShare> d_i_j = proactiveRsaSharing.getD_i_j();
        List<SecretShare> encryptedD_i_j = new ArrayList<>();

        for(int i = 0; i < d_i_j.size(); i++) {
            encryptedD_i_j.add(new SecretShare(BigInteger.valueOf(i+1), PaillierCipher.encrypt(shareholderKeys[i], d_i_j.get(i).getY())));

//            System.out.println("TO " + (i+1) + " encrypting: " + d_i_j.get(i).getY() + " ecrypted: " + encryptedD_i_j.get(i));
        }

        return proactiveRsaSharing.setD_i_j(encryptedD_i_j);
    }

}
