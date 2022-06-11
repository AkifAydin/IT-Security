package haw.aydosch.Blatt3.Aufg2;

import javax.crypto.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * SendSecureFile
 */
public class SSF {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        if(args.length != 4)
            throw new IllegalArgumentException("Usage: SSF <PrivateKey> <PublicKey> <File> <EncryptedFile>");

        String pathPrivateKey = args[0];
        String pathPublicKey = args[1];
        String pathFile = args[2];
        String pathEncryptedFile = args[3];

        // General
        KeyFactory kf = KeyFactory.getInstance("RSA");

        // a) Einlesen eines privaten RSA-Schlüssels (.prv) aus einer Datei gemäß Aufgabenteil 1.
        DataInputStream inputStreamPrivate = new DataInputStream(new FileInputStream(pathPrivateKey));
        int nameLenght = inputStreamPrivate.readInt();
        inputStreamPrivate.skipBytes(nameLenght);

        int keyLength = inputStreamPrivate.readInt();
        byte[] key = new byte[keyLength];
        inputStreamPrivate.read(key);
        inputStreamPrivate.close();

        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));


        // b) Einlesen eines öffentlichen RSA-Schlüssels (.pub) aus einer Datei gemäß Aufgabenteil 1.
        DataInputStream inputStreamPublic = new DataInputStream(new FileInputStream(pathPublicKey));
        int nameLenghtPublic = inputStreamPublic.readInt();
        inputStreamPublic.skipBytes(nameLenghtPublic);

        int keyLengthPublic = inputStreamPublic.readInt();
        byte[] keyPublic = new byte[keyLengthPublic];
        inputStreamPublic.read(keyPublic);
        inputStreamPublic.close();

        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(keyPublic));


        // c) Erzeugen eines geheimen Schlüssels für den AES-Algorithmus mit der Schlüssellänge 256 Bit
        KeyGenerator AESKeyGenerator = KeyGenerator.getInstance("AES");
        AESKeyGenerator.init(256);
        Key AESKey = AESKeyGenerator.generateKey();

        // d) Erzeugung einer Signatur für den geheimen Schlüssel aus c) mit dem privaten RSA-Schlüssel (Algorithmus: „SHA512withRSA“)
        Signature sign = Signature.getInstance("SHA512withRSA");
        sign.initSign(privateKey);
        sign.update(AESKey.getEncoded());
        byte[] signedAES = sign.sign();

        // e) Verschlüsselung des geheimen Schlüssel aus c) mit dem öffentlichen RSA-Schlüssel (Algorithmus: „RSA“)
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKey = encryptCipher.doFinal(AESKey.getEncoded());

        // f) Einlesen einer Dokumentendatei, Verschlüsseln der Dateidaten mit dem symmetrische AES-Algorithmus (geheimer Schlüssel aus c) im Counter-Mode („CTR“) und Erzeugen einer Ausgabedatei.
        FileInputStream in = new FileInputStream(pathFile);
        DataOutputStream out = new DataOutputStream(new FileOutputStream(pathEncryptedFile));

        // Ausgabe 1: Länge des verschlüsselten geheimen Schlüssels (integer)
        out.writeInt(encryptedSecretKey.length);
        // Ausgabe 2: Verschlüsselter geheimer Schlüssel (Bytefolge)
        out.write(encryptedSecretKey);
        // Ausgabe 3: Länge der Signatur des geheimen Schlüssels (integer)
        out.writeInt(signedAES.length);
        // Ausgabe 4: Signatur des geheimen Schlüssels (Bytefolge)
        out.write(signedAES);
        // Ausgabe 5: Länge der algorithmischen Parameter für den AES-Algorithmus
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, AESKey);
        out.writeInt(cipher.getParameters().getEncoded().length);
        // Ausgabe 6: Algorithmische Parameter für den AES-Algorithmus (Bytefolge)
        out.write(cipher.getParameters().getEncoded());

        // Ausgabe 7: Verschlüsselte Dateidaten (Ergebnis von f) (Bytefolge)
        byte[] buffer = new byte[1024];
        int len;
        while ((len = in.read(buffer)) > 0) {
            out.write(cipher.update(Arrays.copyOf(buffer, len)));
        }
        cipher.doFinal();

        out.close();
    }
}
