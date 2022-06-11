package haw.aydosch.Blatt3.Aufg1;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyCreation {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_LENGTH = 2048;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        if(args.length == 0)
            throw new IllegalArgumentException("Usage: RSAKeyCreation <Owner-Name>");

        // Parse KeyOwner
        String keyOwner = args[0];

        // Generate KeyGenerator using RSA
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyGenerator.initialize(KEY_LENGTH);
        KeyPair keyPair = keyGenerator.genKeyPair();

        // Using keyPair, keyOwner and keyLength - generate public and private key file
        createPublicKey(keyOwner, keyPair);
        createPrivateKey(keyOwner, keyPair);
    }

    public static void createPublicKey(String owner, KeyPair keyPair) throws IOException {
        DataOutputStream outputFile = new DataOutputStream(new FileOutputStream(String.format("./src/haw/aydosch/Blatt3/Aufg1/out/%s.pub", owner)));

        // 1. Länge des Inhaber-Namens (integer)
        outputFile.writeInt(owner.length());

        // 2. Inhaber-Name (Bytefolge)
        outputFile.writeBytes(owner);

        // 3. Länge des privaten Schlüssels (integer)
        outputFile.writeInt(keyPair.getPublic().getEncoded().length);

        // Privater Schlüssel (Bytefolge) [PKCS8-Format]
        outputFile.write(keyPair.getPublic().getEncoded());

        outputFile.close();
    }

    public static void createPrivateKey(String owner, KeyPair keyPair) throws IOException {
        // Create bytestream with at least KEY_LENGTH bytes. (Will grow as needed)
        DataOutputStream outputFile = new DataOutputStream(new FileOutputStream(String.format("./src/haw/aydosch/Blatt3/Aufg1/out/%s.prv", owner)));

        // 1. Länge des Inhaber-Namens (integer)
        outputFile.writeInt(owner.length());

        // 2. Inhaber-Name (Bytefolge)
        outputFile.writeBytes(owner);

        // 3. Länge des privaten Schlüssels (integer)
        outputFile.writeInt(keyPair.getPrivate().getEncoded().length);

        // Privater Schlüssel (Bytefolge) [PKCS8-Format]
        outputFile.write(keyPair.getPrivate().getEncoded());


        outputFile.close();
    }
}
