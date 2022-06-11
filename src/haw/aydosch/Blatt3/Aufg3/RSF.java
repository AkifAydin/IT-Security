package haw.aydosch.Blatt3.Aufg3;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;

public class RSF {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        if(args.length != 4)
            throw new IllegalArgumentException("Usage: RSF <PrivateKey> <PublicKey> <EncryptedFile> <DecryptedFile>");

        String pathPrivateKey = args[0];
        String pathPublicKey = args[1];
        String pathEncryptedFile = args[2];
        String pathDecryptedFile = args[3];

        KeyFactory kf = KeyFactory.getInstance("RSA");

        // a) Einlesen eines öffentlichen RSA-Schlüssels aus einer Datei gemäß Aufgabenteil 1.
        DataInputStream inputStreamPublic = new DataInputStream(new FileInputStream(pathPublicKey));
        int nameLengthPublic = inputStreamPublic.readInt();
        inputStreamPublic.skipBytes(nameLengthPublic);

        int keyLengthPublic = inputStreamPublic.readInt();
        byte[] key = new byte[keyLengthPublic];
        inputStreamPublic.read(key);
        inputStreamPublic.close();

        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(key));

        // b) Einlesen eines privaten RSA-Schlüssels aus einer Datei gemäß Aufgabenteil 1.
        DataInputStream inputStreamPrivate = new DataInputStream(new FileInputStream(pathPrivateKey));
        int nameLengthPrivate = inputStreamPrivate.readInt();
        inputStreamPrivate.skipBytes(nameLengthPrivate);

        int keyLengthPrivate = inputStreamPrivate.readInt();
        byte[] keyPrivate = new byte[keyLengthPrivate];
        inputStreamPrivate.read(keyPrivate);
        inputStreamPrivate.close();

        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(keyPrivate));

        // c) Einlesen einer .ssf-Datei gemäß Aufgabenteil 2, Entschlüsselung des geheimen Schlüssels mit
        //    dem privaten RSA-Schlüssel, Entschlüsselung der Dateidaten mit dem geheimen Schlüssel (AES
        //    im Counter-Mode) – mit Anwendung der übermittelten algorithmischen Parameter – sowie Erzeugung einer Klartext-Ausgabedatei.
        DataInputStream inputSSFFile = new DataInputStream(new FileInputStream(pathEncryptedFile));

        int lengthEncryptedSecretKey = inputSSFFile.readInt();
        byte[] encryptedSecretKey = inputSSFFile.readNBytes(lengthEncryptedSecretKey);

        int lengthSignature = inputSSFFile.readInt();
        byte[] signature = inputSSFFile.readNBytes(lengthSignature);

        int lengthParameters = inputSSFFile.readInt();
        byte[] parametersRaw = inputSSFFile.readNBytes(lengthParameters);
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
        parameters.init(parametersRaw);

        byte[] encryptedFile = inputSSFFile.readAllBytes();
        inputSSFFile.close();

        // Geheimer Schlüssel entschlüsseln
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretKey = encryptCipher.doFinal(encryptedSecretKey);
        SecretKey secretKey = new SecretKeySpec(decryptedSecretKey, 0, decryptedSecretKey.length, "AES");

        // Dateidaten entschlüsseln mit AES
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameters);
        byte[] plainText = cipher.doFinal(encryptedFile);

        // Write plaintext file
        DataOutputStream out = new DataOutputStream(new FileOutputStream(pathDecryptedFile));
        out.write(plainText);
        out.close();

        // d) Überprüfung der Signatur für den geheimen Schlüssel aus c) mit dem öffentlichen RSA-Schlüssel (Algorithmus: „SHA512withRSA“)
        Signature sign = Signature.getInstance("SHA512withRSA");
        sign.initVerify(publicKey);
        sign.update(decryptedSecretKey);
        System.out.println(sign.verify(signature) ? "Signatur stimmt überein" : "FEHLER: Signatur stimmt nicht überein");
    }
}
