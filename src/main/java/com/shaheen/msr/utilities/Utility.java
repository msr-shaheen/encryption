package com.shaheen.msr.utilities;

import com.shaheen.msr.exception.CustomException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class Utility {

    // PKCS#8 format
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    // PKCS#1 format
    public static final String BEGIN_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String END_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";
    // Public Key Format
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    // System Commands
    public static final String SYS_COMMANDS = "ls|cd|tree|cat|rm|mkdir|mv|cp|[available commands in os]";
    //Main Command List
    public static final String MAIN_COMMANDS = "help|rsa|aes|3des|base64|sha512|md5";
    public static final String COMMAND_HELP = "help";
    public static final String COMMAND_RSA = "rsa";
    public static final String COMMAND_AES = "aes";
    public static final String COMMAND_DES = "3des";
    public static final String COMMAND_BASE64 = "base64";
    public static final String COMMAND_SHA512 = "sha512";
    public static final String COMMAND_MD5 = "md5";
    //Subcommands
    public static final String COMMAND_GENKEY = "genkey";
    public static final String COMMAND_PUBOUT = "pubout";
    public static final String COMMAND_ENCRYPT = "encrypt";
    public static final String COMMAND_DECRYPT = "decrypt";
    public static final String SINGLE_COMMANDS = "";
    public static final String GENKEY_COMMANDS = "bit|out|";
    public static final String GENKEY_DES = "out|";
    public static final String PUBOUT_COMMANDS = "in|out|";
    public static final String ENCRYPT_COMMANDS = "in|key|out|";
    public static final String DECRYPT_COMMANDS = "in|key|out|";
    //Main Commands
    public static final String COMMAND = "command";
    public static final String SUB_COMMAND = "subcommand";

    //Get Valid Command List for any Main Command
    public static Map<String, String> getValidCommands() {
        Map<String, String> validCommands = new HashMap<>();
        validCommands.put(COMMAND_HELP + DASH, Utility.SINGLE_COMMANDS);
        //RSA Hash Map
        validCommands.put(COMMAND_RSA + DASH + COMMAND_GENKEY, GENKEY_COMMANDS);
        validCommands.put(COMMAND_RSA + DASH + COMMAND_PUBOUT, PUBOUT_COMMANDS);
        validCommands.put(COMMAND_RSA + DASH + COMMAND_ENCRYPT, ENCRYPT_COMMANDS);
        validCommands.put(COMMAND_RSA + DASH + COMMAND_DECRYPT, DECRYPT_COMMANDS);
        //AES Hash Map
        validCommands.put(COMMAND_AES + DASH + COMMAND_GENKEY, GENKEY_COMMANDS);
        validCommands.put(COMMAND_AES + DASH + COMMAND_ENCRYPT, ENCRYPT_COMMANDS);
        validCommands.put(COMMAND_AES + DASH + COMMAND_DECRYPT, DECRYPT_COMMANDS);
        //3DES Hash Map
        validCommands.put(COMMAND_DES + DASH + COMMAND_GENKEY, GENKEY_DES);
        validCommands.put(COMMAND_DES + DASH + COMMAND_ENCRYPT, ENCRYPT_COMMANDS);
        validCommands.put(COMMAND_DES + DASH + COMMAND_DECRYPT, DECRYPT_COMMANDS);
        //Base64 Hash Map
        validCommands.put(COMMAND_BASE64 + DASH + COMMAND_ENCRYPT, PUBOUT_COMMANDS);
        validCommands.put(COMMAND_BASE64 + DASH + COMMAND_DECRYPT, PUBOUT_COMMANDS);
        //SHA-512 Hash Map
        validCommands.put(COMMAND_SHA512 + DASH + COMMAND_ENCRYPT, PUBOUT_COMMANDS);
        //MD5 Hash Map
        validCommands.put(COMMAND_MD5 + DASH + COMMAND_ENCRYPT, PUBOUT_COMMANDS);

        return validCommands;
    }
    // Params
    public static final String CMD_BIT = "bit";
    public static final String CMD_IN = "in";
    public static final String CMD_OUT = "out";
    public static final String CMD_KEY = "key";
    // Error Message
    public static final String NOT_VALID_COMMAND = "Not a valid command: ";
    public static final String NOT_VALID_OPTION = "Not a valid option: ";
    public static final String NOT_VALID_ARGUMENT = "Not a valid argument: ";
    public static final String EXPECTED_ARGUMENT = "Expected argument after: ";
    public static final String DUPLICATE_ARGUMENT = "Duplicate argument : ";
    public static final String INVALID_ARGUMENT_LIST = "Invalid argument list!!!";
    public static final String ARGUMENT_REQUIRED = "Argument required!!!";
    public static final String INVALID_PUBLIC_KEY = "Invalid Public Key!!!";
    public static final String INVALID_PRIVATE_KEY = "Invalid Private Key!!!";
    public static final String COULD_NOT_PARSE_PKS1 = "Could not parse a PKCS1 private key.";
    public static final String UTF_8 = "UTF-8";
    public static final String RSA = "RSA";
    public static final String AES_INSTANCE = "AES/CBC/PKCS5PADDING";
    public static final String AES = "AES";
    public static final String ALGO_SHA512 = "SHA-512";
    public static final String ALGO_MD5 = "MD5";
    public static final String HEX_DECODE = "31323334353630303030303030303030";
    public static final String TXT_EXT1 = ".txt";
    public static final String TXT_EXT2 = ".TXT";
    public static final String DOT = ".";
    public static final String DASH = "-";
    public static final String ENCRYPTED_TEXT = "Encrypted Text:\n";
    public static final String DECRYPTED_TEXT = "Decrypted Text:\n";

    public static String readFromFile(String fileName) throws IOException, CustomException {
        try {
            File file = new File(fileName);
            Path path = Paths.get(file.getAbsolutePath());
            String fileContent = new String(Files.readAllBytes(path));
            return fileContent;
        } catch (IOException ex) {
        }
        throw new CustomException("File " + fileName + " not found!!!");
    }

    public static void writeToFile(String fileName, String fileContent) throws IOException, CustomException {
        if (fileName == null) {
            throw new CustomException("Invalid File Name!!!");
        }
        File f = new File(fileName);

        File f2  = new File(f.getAbsolutePath());

        try (FileOutputStream fos = new FileOutputStream(f2)) {
            fos.write(fileContent.getBytes());
            fos.flush();
        }
    }

    public static void printHelp() {
        System.out.println("RSA");
        System.out.println(get2500(7)+"PrivateKey"+get2500(2)+"$ rsa genkey -bit [rsa-bit] -out [private-key-file]");
        System.out.println(get2500(7)+"PublicKey"+get2500(3)+"$ rsa pubout -in [private-key-file] -out [public-key-file]");
        System.out.println(get2500(7)+"Encrypt"+get2500(5)+"$ rsa encrypt -in [input-file|text] -out [output-file] -key [public-key-file]");
        System.out.println(get2500(7)+"Decrypt"+get2500(5)+"$ rsa decrypt -in [input-file] -out [output-file] -key [private-key-file]");
        System.out.println("AES");
        System.out.println(get2500(7)+"GenerateKey"+get2500(1)+"$ aes genkey -bit [aes-bit] -out [key-file]");
        System.out.println(get2500(7)+"Encrypt"+get2500(5)+"$ aes encrypt -in [input-file|text] -out [output-file] -key [key-file]");
        System.out.println(get2500(7)+"Decrypt"+get2500(5)+"$ aes decrypt -in [input-file] -out [output-file] -key [key-file]");
        System.out.println("3DES");
        System.out.println(get2500(7)+"GenerateKey"+get2500(1)+"$ 3des genkey -out [key-file]");
        System.out.println(get2500(7)+"Encrypt"+get2500(5)+"$ 3des encrypt -in [input-file|text] -out [output-file] -key [key-file]");
        System.out.println(get2500(7)+"Decrypt"+get2500(5)+"$ 3des decrypt -in [input-file] -out [output-file] -key [key-file]");
        System.out.println("Base64");
        System.out.println(get2500(7)+"Encrypt"+get2500(5)+"$ base64 encrypt -in [input-file|text] -out [output-file]");
        System.out.println(get2500(7)+"Decrypt"+get2500(5)+"$ base64 decrypt -in [input-file] -out [output-file]");
        System.out.println("SHA512");
        System.out.println(get2500(7)+"Encrypt"+get2500(5)+"$ sha512 encrypt -in [input-file|text] -out [output-file]");
        System.out.println("MD5");
        System.out.println(get2500(7)+"Encrypt"+get2500(5)+"$ md5 encrypt -in [input-file|text] -out [output-file]");

        System.out.println("\nOther Commands"+get2500(6)+"$ " + SYS_COMMANDS);
        System.out.println("To Exit"+get2500(13)+"$ exit | EXIT");
    }
    public static String get2500(int number){
        String result="";
        for(int i=0;i<number;i++){
            result+="-";
        }
        return result;
    }

    public static void printError() {
        System.out.println("For HELP"+get2500(12)+"$ help\n");
    }

    public static String getHash(String text, String algorithm) throws NoSuchAlgorithmException {
        String out = "";
        MessageDigest md;
        String message = text;
        try {
            md = MessageDigest.getInstance(algorithm);//Available Algo - SHA-512,SHA-256,MD5,SHA,SHA-1,SHA-384
            md.update(message.getBytes());
            byte[] mb = md.digest();

            for (int i = 0; i < mb.length; i++) {
                byte temp = mb[i];
                String s = Integer.toHexString(new Byte(temp));
                while (s.length() < 2) {
                    s = "0" + s;
                }
                s = s.substring(s.length() - 2);
                out += s;
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
        return out.toLowerCase();
    }
}