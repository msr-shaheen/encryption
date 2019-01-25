package com.shaheen.msr.encryption;

import com.shaheen.msr.exception.CustomException;
import com.shaheen.msr.interfaces.Encryption;
import com.shaheen.msr.utilities.Base64;
import com.shaheen.msr.utilities.Utility;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSATool implements Encryption {

    private final Cipher cipher;

    public RSATool() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance(Utility.RSA);
    }

    @Override
    public void generatePrivateKey(int numBit, String fileName) throws Exception {
        System.out.println("Generating RSA Private Key...");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Utility.RSA);
        keyGen.initialize(numBit);
        KeyPair keyPair = keyGen.genKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        byte[] privateKeyBytes = privateKey.getEncoded();

        String privateKeyStr = Utility.BEGIN_PRIVATE_KEY + "\n" + Base64.encode(privateKeyBytes) + "\n" + Utility.END_PRIVATE_KEY;
        String privateKeyFileName = fileName;

        Utility.writeToFile(privateKeyFileName, privateKeyStr);

        System.out.println("Success!!!");
    }

    @Override
    public void generatePublicKey(String privateKeyFile, String publicKeyFile) throws Exception {
        System.out.println("Generating Public Key...");
        PrivateKey privateKey = getPrivateKey(privateKeyFile);
        RSAPrivateCrtKeyImpl rsaPrivateKey = (RSAPrivateCrtKeyImpl) privateKey;
        PublicKey publicKey = KeyFactory.getInstance(Utility.RSA).generatePublic(new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent()));
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyStr = Utility.BEGIN_PUBLIC_KEY + "\n" + Base64.encode(publicKeyBytes) + "\n" + Utility.END_PUBLIC_KEY;
        String publicKeyFileName = publicKeyFile;
        Utility.writeToFile(publicKeyFileName, publicKeyStr);
        System.out.println("Success!!!");
    }

    @Override
    public String encrypt(String input, String outputFile, String keyFile) throws Exception {
        PublicKey key = this.getPublicKey(keyFile);
        String inputContent = input.contains(Utility.DOT) ? Utility.readFromFile(input) : input;
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        String encryptedContent=Base64.encode(cipher.doFinal(inputContent.getBytes(Utility.UTF_8)));

        Utility.writeToFile(outputFile, encryptedContent);
        return encryptedContent;
    }

    @Override
    public String decrypt(String inputFile, String outputFile, String keyFile) throws Exception {
        PrivateKey key = this.getPrivateKey(keyFile);
        String inputContent = Utility.readFromFile(inputFile);
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        String decryptedContent=new String(cipher.doFinal(Base64.decode(inputContent)), Utility.UTF_8);
        Utility.writeToFile(outputFile, decryptedContent);
        return decryptedContent;
    }

    //Private Methods
    private PrivateKey getPrivateKey(String fileName) throws GeneralSecurityException, IOException, CustomException {

        try {
            File pemFileName = new File(fileName);
            Path path = Paths.get(pemFileName.getAbsolutePath());

            String privateKeyPem = new String(Files.readAllBytes(path));

            if (privateKeyPem.contains(Utility.BEGIN_PRIVATE_KEY)) { // PKCS#8 format
                privateKeyPem = privateKeyPem.replace(Utility.BEGIN_PRIVATE_KEY, "").replace(Utility.END_PRIVATE_KEY, "");
                privateKeyPem = privateKeyPem.replaceAll("\\s", "");

                byte[] pkcs8EncodedKey = Base64.decode(privateKeyPem);

                KeyFactory factory = KeyFactory.getInstance(Utility.RSA);
                return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));

            } else if (privateKeyPem.contains(Utility.BEGIN_RSA_PRIVATE_START)) {  // PKCS#1 format

                privateKeyPem = privateKeyPem.replace(Utility.BEGIN_RSA_PRIVATE_START, "").replace(Utility.END_RSA_PRIVATE_END, "");
                privateKeyPem = privateKeyPem.replaceAll("\\s", "");

                DerInputStream derReader = new DerInputStream(Base64.decode(privateKeyPem));

                DerValue[] seq = derReader.getSequence(0);

                if (seq.length < 9) {
                    throw new GeneralSecurityException(Utility.COULD_NOT_PARSE_PKS1);
                }

                // skip version seq[0];
                BigInteger modulus = seq[1].getBigInteger();
                BigInteger publicExp = seq[2].getBigInteger();
                BigInteger privateExp = seq[3].getBigInteger();
                BigInteger prime1 = seq[4].getBigInteger();
                BigInteger prime2 = seq[5].getBigInteger();
                BigInteger exp1 = seq[6].getBigInteger();
                BigInteger exp2 = seq[7].getBigInteger();
                BigInteger crtCoef = seq[8].getBigInteger();

                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

                KeyFactory factory = KeyFactory.getInstance(Utility.RSA);

                return factory.generatePrivate(keySpec);
            } else {
                throw new GeneralSecurityException(Utility.INVALID_PRIVATE_KEY);
            }

        } catch (java.nio.file.NoSuchFileException nex) {
            throw new CustomException("File " + fileName + " not found!!!");
        }
    }

    private PublicKey getPublicKey(String fileName) throws Exception {
        try {
            File pemFileName = new File(fileName);
            Path path = Paths.get(pemFileName.getAbsolutePath());

            String privateKeyPem = new String(Files.readAllBytes(path));

            privateKeyPem = privateKeyPem.replace(Utility.BEGIN_PUBLIC_KEY, "").replace(Utility.END_PUBLIC_KEY, "");
            privateKeyPem = privateKeyPem.replaceAll("\\s", "");

            byte[] pkcs8EncodedKey = Base64.decode(privateKeyPem);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(pkcs8EncodedKey);
            KeyFactory kf = KeyFactory.getInstance(Utility.RSA);
            return kf.generatePublic(spec);

        } catch (java.nio.file.NoSuchFileException nex) {
            throw new CustomException("File " + fileName + " not found!!!");
        } catch (Exception ex) {
            throw new GeneralSecurityException(Utility.INVALID_PUBLIC_KEY);
        }
    }
}