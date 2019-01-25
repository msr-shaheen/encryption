package com.shaheen.msr;


import com.shaheen.msr.encryption.*;
import com.shaheen.msr.interfaces.Encryption;
import com.shaheen.msr.utilities.TreeView;
import com.shaheen.msr.utilities.Utility;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

public class EncryptionApplication {
    private static Process process;
    private static final String WIN_SEPERATOR = "\\";
    private static final String LINUX_SEPERATOR = "/";
    private static String seperator;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        System.out.println("\n" + Utility.get2500(35) + "| Encryption Tool |" + Utility.get2500(35) + "\n");
        Utility.printHelp();
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String line;
            String pwd = System.getProperty("user.dir");
            if (pwd.contains(WIN_SEPERATOR)) {
                seperator = WIN_SEPERATOR;
            } else {
                seperator = LINUX_SEPERATOR;
            }

            String user = System.getProperty("user.name");
            System.out.print(pwd + "~[encrypt]$ ");
            String newDir;

            while (!(line = br.readLine()).equalsIgnoreCase("exit")) {
                String[] argsCommands = line.trim().split(" ");
                if (argsCommands[0] != null && argsCommands[0].length() > 0) {
                    if (Utility.MAIN_COMMANDS.contains(argsCommands[0])) {
                        processCommands(argsCommands);
                    } else if (argsCommands[0].equals("cd")) {
                        String currentDir = pwd.replace(seperator, "#");
                        newDir = cd(currentDir, line.split(" ")[1].replaceAll(LINUX_SEPERATOR, "#"));
                        //System.out.println("new Dir: "+ newDir);
                        System.setProperty("user.dir", newDir);
                    } else if (argsCommands[0].equals("tree")) {
                        pwd = System.getProperty("user.dir");
                        TreeView view = new TreeView();
                        File dir = new File(pwd);
                        view.printDirectoryTree(dir);
                    } else if (argsCommands[0].equals("cls") || argsCommands[0].equals("clear")) {
                        // new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
                        try {
                            if (System.getProperty("os.name").contains("Windows")) {
                                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
                            } else {
                                Runtime.getRuntime().exec("clear");
                            }
                        } catch (IOException ex) {
                        }
                        System.out.println("");
                    } else {
                        pwd = System.getProperty("user.dir");
                        try {
                            ProcessBuilder pb = new ProcessBuilder(line.split(" "));
                            pb.directory(new File(pwd));
                            process = pb.start();
                            processSysCommands();
                        } catch (Exception ex) {
                            System.out.println("Error: " + ex.getMessage());
                        }
                    }
                }
                pwd = System.getProperty("user.dir");
                System.out.print(pwd + "~[encrypt]$ ");
            }
        } catch (Exception ex) {
            System.out.println("Error-" + ex.getMessage());
        }
    }

    private static void processCommands(String[] args) throws Exception {
        Map<String, String> commands;
        String bit;
        String in;
        String out;
        String key;
        String output;
        Encryption enc = new Base64Tool();//Default Loading
        try {
            commands = parseCommands(args);
            String mainCommand = commands.get(Utility.COMMAND);
            String subCommand = commands.get(Utility.SUB_COMMAND);
            switch (mainCommand) {
                case Utility.COMMAND_HELP:
                    Utility.printHelp();
                    break;
                case Utility.COMMAND_RSA:
                    enc = new RSATool();
                    break;
                case Utility.COMMAND_AES:
                    enc = new AESTool();
                    break;
                case Utility.COMMAND_DES:
                    enc = new TripleDESTool();
                    break;
                case Utility.COMMAND_BASE64:
                    enc = new Base64Tool();
                    break;
                case Utility.COMMAND_SHA512:
                    enc = new SHA512Tool();
                    break;
                case Utility.COMMAND_MD5:
                    enc = new MD5Tool();
                    break;
                default:
                    Utility.printError();
                    break;
            }

            if (!mainCommand.equals(Utility.COMMAND_HELP)) {
                switch (subCommand) {
                    case Utility.COMMAND_GENKEY:
                        bit = commands.get(Utility.CMD_BIT);
                        out = commands.get(Utility.CMD_OUT);
                        bit = bit == null ? "0" : bit;
                        enc.generatePrivateKey(Integer.parseInt(bit), out);
                        break;
                    case Utility.COMMAND_PUBOUT:
                        in = commands.get(Utility.CMD_IN);
                        out = commands.get(Utility.CMD_OUT);
                        enc.generatePublicKey(in, out);
                        break;
                    case Utility.COMMAND_ENCRYPT:
                        in = commands.get(Utility.CMD_IN);
                        out = commands.get(Utility.CMD_OUT);
                        key = commands.get(Utility.CMD_KEY);
                        output = enc.encrypt(in, out, key);
                        System.out.println(Utility.ENCRYPTED_TEXT + output);
                        break;
                    case Utility.COMMAND_DECRYPT:
                        in = commands.get(Utility.CMD_IN);
                        out = commands.get(Utility.CMD_OUT);
                        key = commands.get(Utility.CMD_KEY);
                        output = enc.decrypt(in, out, key);
                        System.out.println(Utility.DECRYPTED_TEXT + output);
                        break;
                }
            }

        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            Utility.printError();
        }
    }

    private static Map<String, String> parseCommands(String[] args) throws Exception {
        Map<String, String> commands = new HashMap<>();
        Map<String, String> validCommands = Utility.getValidCommands();
        String mainCommand = args[0];
        String subCommand = "";
        String params = "";

        if (!Utility.MAIN_COMMANDS.contains(mainCommand)) {
            throw new IllegalArgumentException(Utility.NOT_VALID_COMMAND + mainCommand);
        }
        if (!mainCommand.equals(Utility.COMMAND_HELP) && args.length > 1) {
            if (!validCommands.containsKey(mainCommand + Utility.DASH + args[1])) {
                throw new IllegalArgumentException(Utility.NOT_VALID_OPTION + args[1]);
            } else {
                subCommand = args[1];
            }
        }
        for (int i = 2; i < args.length; i++) {
            if (args[i].startsWith("-")) {
                if (args.length - 1 == i) {
                    throw new IllegalArgumentException(Utility.EXPECTED_ARGUMENT + args[i]);
                } else if (args[i + 1].startsWith("-")) {
                    throw new IllegalArgumentException(Utility.NOT_VALID_ARGUMENT + args[i + 1]);
                }
                String cmd = args[i].substring(1, args[i].length());
                if (commands.containsKey(cmd)) {
                    throw new IllegalArgumentException(Utility.DUPLICATE_ARGUMENT + cmd);
                }
                commands.put(cmd, args[i + 1]);
                i++;
            } else {
                throw new IllegalArgumentException(Utility.NOT_VALID_ARGUMENT + args[i]);
            }
        }
        for (String key : commands.keySet()) {
            params = params + key + "|";
        }
        //System.out.println("SubCommands: " + subCommand);

        if (!params.equals(validCommands.get(mainCommand + Utility.DASH + subCommand))) {
            throw new IllegalArgumentException(Utility.INVALID_ARGUMENT_LIST);
        }
        commands.put(Utility.SUB_COMMAND, subCommand);
        commands.put(Utility.COMMAND, mainCommand);
        return commands;
    }

    private static void processSysCommands() {
        String sysCmdOutput;
        try {
//            process = Runtime.getRuntime().exec(sysCommand);
//            process.waitFor();

            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((sysCmdOutput = stdInput.readLine()) != null) {
                System.out.println(sysCmdOutput);
            }
            String error = "";
            while ((sysCmdOutput = stdError.readLine()) != null) {
                error += sysCmdOutput + "\n";
            }
            if (error.length() > 0) {
                System.out.println(error);
            }
            // process.destroy();
        } catch (Exception ex) {
            System.out.println("Error Message-" + ex.getMessage());
        }
    }

    private static String cd(String currentDir, String cdCmd) {
        String newPath = "";

        String[] curDir2 = new String[20];

        String[] curDir = currentDir.split("#");
        // System.out.println("CurDir: " + Arrays.asList(curDir));
        int curDirCounter = curDir.length;



        String[] cdParams = cdCmd.split("#");
        //System.out.println("cdParams: " + Arrays.asList(cdParams));
        if (cdParams[0].contains(":") || cdCmd.startsWith("#")) {

            newPath = cdCmd.replaceAll("#", LINUX_SEPERATOR);
        } else {

            System.arraycopy(curDir, 0, curDir2, 0, curDirCounter);

            for (int i = 0; i < cdParams.length; i++) {
                //System.out.println("Evaluating cdParams: " + i + " Value: " + cdParams[i]);
                switch (cdParams[i]) {
                    case "..":
                        if (curDirCounter == 1) {
                            continue;
                        }
                        // curDir[curDirCounter++]=cdParams[i];
                        curDirCounter--;
                        break;
                    case ".":
                        continue;
                    default:
                        curDir2[curDirCounter++] = cdParams[i];
                        break;
                }
            }

            for (int i = 0; i < curDirCounter; i++) {
                // System.out.print(curDir[i] + " ");
                newPath += curDir2[i] + " ";
            }
            newPath = newPath.trim();
            newPath = newPath.replace(" ", seperator);
            // newPath = curDirCounter == 1 ? newPath + seperator : newPath;

        }
        if (!newPath.contains(seperator)) {
            newPath += seperator;
        }

        File directory = new File(newPath);
        if (!directory.exists()) {
            System.out.println("Invalid Directory: " + newPath);
            return currentDir.replace("#", seperator);
        }
        return newPath;
    }
}

