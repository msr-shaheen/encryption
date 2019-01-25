package com.shaheen.msr.encryption;

import com.shaheen.msr.interfaces.Encryption;
import com.shaheen.msr.utilities.Utility;

public class MD5Tool implements Encryption {

    @Override
    public void generatePrivateKey(int numBit, String fileName) throws Exception {
        throw new UnsupportedOperationException("Operation Not supported.");
    }

    @Override
    public void generatePublicKey(String privateKeyFile, String publicKeyFile) throws Exception {
        throw new UnsupportedOperationException("Operation Not supported.");
    }

    @Override
    public String encrypt(String input, String outputFile, String keyFile) throws Exception {
        String inputContent = input.contains(Utility.DOT) ? Utility.readFromFile(input) : input;
        String encrypted = Utility.getHash(inputContent, Utility.ALGO_MD5);
        Utility.writeToFile(outputFile, encrypted);
        return encrypted;
    }

    @Override
    public String decrypt(String inputFile, String outputFile, String keyFile) throws Exception {
        throw new UnsupportedOperationException("Operation Not supported.");
    }
}