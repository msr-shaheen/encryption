package com.shaheen.msr.encryption;

import com.shaheen.msr.exception.CustomException;
import com.shaheen.msr.interfaces.Encryption;
import com.shaheen.msr.utilities.Base64;
import com.shaheen.msr.utilities.Hex;
import com.shaheen.msr.utilities.Utility;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class AESTool implements Encryption {

    private Cipher cipher = null;
    byte[] iv = null;
    byte[] key = null;

    private void init(String aesKey) throws Exception {
        this.key = getKey(aesKey);
        try {
            this.iv = Hex.decodeHex(Utility.HEX_DECODE.toCharArray());
            this.cipher = Cipher.getInstance(Utility.AES_INSTANCE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void generatePrivateKey(int length, String fileName) throws Exception {
        System.out.println("Generating AES Key...");

        byte[] binaryKey = null;
        try {
            KeyGenerator kg = KeyGenerator.getInstance(Utility.AES);
            kg.init(length);
            SecretKey sk = kg.generateKey();
            binaryKey = sk.getEncoded();
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
            this.cipher.init(1,
                    new SecretKeySpec(this.key, Utility.AES),
                    new IvParameterSpec(this.iv));
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
            this.cipher.init(2,
                    new SecretKeySpec(this.key, Utility.AES),
                    new IvParameterSpec(this.iv));
            byte[] result = Base64.decode(inputContent);
            byte[] plainBytes = this.cipher.doFinal(result);

            String plaintext = new String(plainBytes, Utility.UTF_8);

            Utility.writeToFile(outputFile, plaintext);

            return plaintext;
        } catch (Exception e) {
            throw new CustomException("Invalid Key File!!!");
        }
    }

    private byte[] getKey(String aesFileName) throws Exception {
        String aesKey = Utility.readFromFile(aesFileName);
        byte[] result = Base64.decode(aesKey);
        return result;
    }
}