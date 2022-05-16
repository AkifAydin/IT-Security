package haw.aydosch.Blatt1.A3;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class SecureFile {
    public static void main(String[] args) {
        // Parse arguments
        String fileEnDecryptFile = args[0];
        String fileKey = args[1];
        String resultFile = args[2];
        String operation = args[3];

        // Prepare TripleDES relevant data
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        byte[] key3 = new byte[8];
        byte[] iv = new byte[8];

        // Prepare file arrays
        byte[] src = new byte[0];
        byte[] target = new byte[0];

        try {
            // Read Source File
            src = Files.readAllBytes(Paths.get(fileEnDecryptFile));

            // Create target array using source file length
            target = new byte[src.length];

            // Read key file and extract relevant data
            byte[] keyfile = Files.readAllBytes(Paths.get(fileKey));
            key1 = Arrays.copyOfRange(keyfile, 0, 8);
            key2 = Arrays.copyOfRange(keyfile, 8, 16);
            key3 = Arrays.copyOfRange(keyfile, 16, 24);
            iv = Arrays.copyOfRange(keyfile, 24, 32);
        } catch (Exception exception) {
            exception.printStackTrace();
            System.exit(-1);
        }

        // create TripleDES Object
        TripleDES tdes = new TripleDES(key1, key2, key3);

        // Perform operation
        if(operation.equals("encrypt")) SecureFile.encrypt(tdes, iv, src, target);
        if(operation.equals("decrypt")) SecureFile.decrypt(tdes, iv, src, target);

        // Write target to result file
        try (FileOutputStream fos = new FileOutputStream(resultFile)) {
            fos.write(target);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] encrypt(TripleDES tdes, byte[] iv, byte[] src, byte[] target) {
        byte[] prev_c = iv;

        for(int i = 0; i < src.length; i+=8) {
            // Get 8 bytes of plaintext
            byte[] m_i = Arrays.copyOfRange(src, i, i+8);

            // Calculate chiffretext
            byte[] result_c = xor(m_i, tdes.encryptBytes(prev_c));

            // Update prev_c
            prev_c = result_c;

            // Append to target
            for(int j = 0; j < 8; j++) {
                // Break if target length is reached (Everything above length is going to be padding)
                if(i+j == src.length)
                    break;

                target[i+j] = result_c[j];
            }
        }

        return target;
    }

    private static byte[] decrypt(TripleDES tdes, byte[] iv, byte[] src, byte[] target) {
        byte[] prev_c = iv;

        for(int i = 0; i < src.length; i+=8) {
            // Get 8 bytes of plaintext
            byte[] m_i = Arrays.copyOfRange(src, i, i+8);

            // Calculate chiffretext
            byte[] result_c = xor(m_i, tdes.decryptBytes(prev_c));

            // Update prev_c
            prev_c = result_c;

            // Append to target
            for(int j = 0; j < 8; j++) {
                // Break if target length is reached (Everything above length is going to be padding)
                if(i+j == target.length)
                    break;

                target[i+j] = result_c[j];
            }
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
