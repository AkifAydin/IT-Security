package haw.aydosch.Blatt1.A3;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class SecureFile {
    public static void main(String[] args) {
        String fileEnDecryptFile = args[0];
        String fileKey = args[1];
        String resultFile = args[2];
        String operation = args[3];

        // Read Keys from Key-File
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        byte[] key3 = new byte[8];
        byte[] iv = new byte[8];
        try {
            byte[] bytesKeyFile = Files.readAllBytes(Paths.get(fileKey));
            key1 = Arrays.copyOfRange(bytesKeyFile, 0, 8);
            key2 = Arrays.copyOfRange(bytesKeyFile, 8, 16);
            key3 = Arrays.copyOfRange(bytesKeyFile, 16, 24);
            iv = Arrays.copyOfRange(bytesKeyFile, 24, 32);

        } catch (IOException exception) {
            exception.printStackTrace();
            System.exit(-1);
        }

        System.out.println(key1.length);

        TripleDES tdes = new TripleDES(key1, key2, key3);

        byte[] result;
        if(operation.equals("encrypt"))
            result = SecureFile.encrypt(tdes, iv, fileEnDecryptFile);
        else
            result = SecureFile.decrypt(tdes, iv, fileEnDecryptFile);

        try {
            FileOutputStream out = new FileOutputStream(resultFile);
            out.write(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] encrypt(TripleDES tdes, byte[] iv, String toEncrypt) {
        byte[] target = new byte[0];

        try {
            byte[] sourceFile = Files.readAllBytes(Paths.get(toEncrypt));
            byte[] cipher = tdes.encryptBytes(iv);

            int offset = 0;
            byte[] plain;
            byte[] curr;
            target = new byte[sourceFile.length];

            // Erhöhe nach jedem Durchlauf den Offset um 8 Bytes
            for (int x = 0; x < sourceFile.length; x += 8) {
                if (x + 8 > sourceFile.length - 1) {
                    offset = sourceFile.length;
                }
                else {
                    offset = x + 8;
                }

                // Befülle den PlaintextArray
                plain = Arrays.copyOfRange(target, x, offset);

                // CFB XOR
                curr = xor(cipher, plain);
                System.arraycopy(curr, 0, target, x, offset - x);
                cipher = tdes.encryptBytes(curr);
            }
        } catch (IOException exception) {
            exception.printStackTrace();
        }

        return target;
    }

    private static byte[] decrypt(TripleDES tdes, byte[] iv, String toEncrypt) {
        byte[] target = new byte[0];

        try {
            byte[] sourceFile = Files.readAllBytes(Paths.get(toEncrypt));
            target = new byte[sourceFile.length];


            byte[] curr = tdes.decryptBytes(iv);

            // Plaintext buffer
            byte[] plain = new byte[8];

            // Chiffre buffer
            byte[] cipher = new byte[8];
            int offset = 0;

            // Erhöhe nach jedem Durchlauf den Offset um 8 Bytes
            for (int x = 0; x < sourceFile.length; x += 8) {
                if (x + 8 > sourceFile.length - 1) {
                    offset = sourceFile.length;
                }
                else {
                    offset = x + 8;
                }

                cipher = Arrays.copyOfRange(target, x, offset);

                // CFB XOR
                plain = xor(curr, cipher);

                System.arraycopy(plain, 0, target, x, offset - x);
                curr = tdes.encryptBytes(cipher);
            }
        } catch (IOException exception) {
            exception.printStackTrace();
        }

        return target;
    }


    public static byte[] xor(byte[] o1, byte[] o2) {
        byte[] temp = new byte[o1.length];

        for (int x = 0; x < o2.length; x++) {
            temp[x] = (byte)(o1[x] ^ o2[x]);
        }

        return temp;
    }
}
