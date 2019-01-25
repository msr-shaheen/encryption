package com.shaheen.msr.encryption;

import com.shaheen.msr.interfaces.Encryption;
import com.shaheen.msr.utilities.Base64;
import com.shaheen.msr.utilities.Utility;

public class Base64Tool implements Encryption {

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
        String encrypted = Base64.encode(inputContent.getBytes());
        Utility.writeToFile(outputFile, encrypted);
        return encrypted;
    }

    @Override
    public String decrypt(String inputFile, String outputFile, String keyFile) throws Exception {
        String inputContent = Utility.readFromFile(inputFile);
        byte[] plainByte = Base64.decode(inputContent);
        String decrypted = new String(plainByte, Utility.UTF_8);
        Utility.writeToFile(outputFile, decrypted);
        return decrypted;
    }
}
