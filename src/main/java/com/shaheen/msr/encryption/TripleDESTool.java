package com.shaheen.msr.encryption;

import com.shaheen.msr.exception.CustomException;
import com.shaheen.msr.interfaces.Encryption;
import com.shaheen.msr.utilities.Base64;
import com.shaheen.msr.utilities.Utility;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

public class TripleDESTool implements Encryption {

    public final static String CIPHER_TYPE = "DESede/ECB/PKCS5Padding";
    public final static String CIPHER_NAME = "DESede";
    private KeySpec keySpec;
    private SecretKeyFactory secretKeyFactory;
    private Cipher cipher;
    private SecretKey key;
    private byte[] keyByte;

    private void init(String desKey) throws Exception {
        this.keyByte = getKey(desKey);
        this.keySpec = new DESedeKeySpec(keyByte);
        this.secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_NAME);
        this.cipher = Cipher.getInstance(CIPHER_TYPE);
        this.key = secretKeyFactory.generateSecret(keySpec);
    }

    @Override
    public void generatePrivateKey(int length, String fileName) throws Exception {
        System.out.println("Generating DES Key...");
        byte[] binaryKey;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_NAME);
            //keyGenerator.init(length);
            binaryKey = keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        String base64EncodedKey = Base64.encode(binaryKey);
        Utility.writeToFile(fileName, base64EncodedKey);
        System.out.println("Success!!!");
    }

    @Override
    public void generatePublicKey(String privateKeyFile, String publicKeyFile) throws Exception {
        throw new UnsupportedOperationException("Operation Not supported.");
    }

    @Override
    public String encrypt(String input, String outputFile, String keyFile) throws Exception {
        init(keyFile);
        String inputContent = input.contains(Utility.DOT) ? Utility.readFromFile(input) : input;
        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherBytes = this.cipher.doFinal(inputContent.getBytes(Utility.UTF_8));
            String ciphertext = Base64.encode(cipherBytes);
            Utility.writeToFile(outputFile, ciphertext);
            return ciphertext;
        } catch (Exception e) {
            throw new CustomException("Invalid Key File!!!");
        }
    }

    @Override
    public String decrypt(String inputFile, String outputFile, String keyFile) throws Exception {
        init(keyFile);
        String inputContent = Utility.readFromFile(inputFile);
        try {
            this.cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = Base64.decode(inputContent);
            byte[] plainBytes = this.cipher.doFinal(result);
            String plaintext = new String(plainBytes, Utility.UTF_8);
            Utility.writeToFile(outputFile, plaintext);
            return plaintext;
        } catch (Exception e) {
            throw new CustomException("Invalid Key File!!!");
        }
    }

    private byte[] getKey(String desFileName) throws Exception {
        String desKey = Utility.readFromFile(desFileName);
//        byte[] result = Base64.decode(desKey);
        byte[] result = desKey.getBytes(Utility.UTF_8);
        return result;
    }
}
