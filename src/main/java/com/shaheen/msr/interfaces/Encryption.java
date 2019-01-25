package com.shaheen.msr.interfaces;

public interface Encryption {

    public void generatePrivateKey(int numBit, String fileName) throws Exception;

    public void generatePublicKey(String privateKeyFile, String publicKeyFile) throws Exception;

    public String encrypt(String input, String outputFile, String keyFile) throws Exception;

    public String decrypt(String inputFile, String outputFile, String keyFile) throws Exception;
}