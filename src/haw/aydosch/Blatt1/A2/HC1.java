package haw.aydosch.Blatt1.A2;

import haw.aydosch.Blatt1.A1.LCG;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

public class HC1 {
    public static void main(String[] args) {
        int x_0 = Integer.parseInt(args[0]);
        String file = args[1];

        // Create LCG Object
        LCG BASIC = new LCG(x_0, 214013, 13523655, (int)Math.pow(2, 24));             // BASIC

        FileInputStream in = null;
        FileOutputStream out = null;
        try {
            in = new FileInputStream(file);
            out = new FileOutputStream("./src/haw/aydosch/Blatt1/A2/result.txt");

            byte[] buffer = new byte[1];
            int len;
            while ((len = in.read(buffer)) > 0) {
                int random = BASIC.nextInt() & 0xFF;

                byte[] result = new byte[1];
                result[0] = (byte)((int)buffer[0] ^ random);

                out.write(result, 0, len);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
