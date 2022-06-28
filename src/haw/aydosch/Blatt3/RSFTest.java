package haw.aydosch.Blatt3;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class RSFTest {
    public final String SIGNATURE_PARAMETERS = "SHA512withRSA";
    public final String CIPHER_PARAMETERS = "AES/CTR/NoPadding";
    public String privFileName;
    public String pubFileName;
    public String ssfFileName;
    public String docFileName;
    private PrivateKey privKey = null;
    private PublicKey pubKey = null;
    public byte[] encodedSKey = null;
    public byte[] encryptedSKey = null;
    private byte[] signature = null;

    public RSFTest() {
    }

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: java RSFTest filename.prv filename.pub ssf-filename doc-filename");
            System.exit(0);
        } else {
            RSFTest myRSF = new RSFTest();
            myRSF.privFileName = args[0];
            myRSF.pubFileName = args[1];
            myRSF.ssfFileName = args[2];
            myRSF.docFileName = args[3];
            System.out.println("RSFTest startet mit folgenden Argumenten:");
            System.out.println("--------------- PrivateKey-File: " + myRSF.privFileName);
            System.out.println("--------------- PublicKey-File:  " + myRSF.pubFileName);
            System.out.println("--------------- Chipher-File:    " + myRSF.ssfFileName);
            System.out.println("--------------- Plaintext-File:  " + myRSF.docFileName);
            myRSF.readPrivKey();
            myRSF.readPubKey();
            myRSF.convertSSFFile();
            if (myRSF.verifySignature()) {
                System.out.println("\n\n:-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) ");
                System.out.println("Alles fertig, wenn die Datei korrekt entschluesselt wurde. Schon mal herzlichen Glueckwunsch!");
                System.out.println(":-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) ");
            } else {
                System.out.println("RSFTest: Hat leider noch nicht geklappt, schade ... :-(");
            }
        }

    }

    public void readPrivKey() {
        byte[] privKeyEnc = null;
        byte[] sname = null;

        try {
            DataInputStream is = new DataInputStream(new FileInputStream(this.privFileName));
            int len = is.readInt();
            sname = new byte[len];
            is.read(sname);
            len = is.readInt();
            privKeyEnc = new byte[len];
            is.read(privKeyEnc);
            is.close();
        } catch (IOException var8) {
            this.Error("Fehler beim Lesen des private keys!", var8);
        }

        KeyFactory keyFac = null;

        try {
            keyFac = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException var7) {
            this.Error("Es existiert keine KeyFactory fuer RSA.", var7);
        }

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privKeyEnc);

        try {
            this.privKey = keyFac.generatePrivate(pkcs8KeySpec);
        } catch (InvalidKeySpecException var6) {
            this.Error("Fehler beim Konvertieren des Schluessels.", var6);
        }

        String snameStr = new String(sname);
        System.out.println("\nPrivate key fuer <" + snameStr + "> wurde erfolgreich gelesen: " + this.byteArraytoHexString(privKeyEnc));
    }

    public void readPubKey() {
        byte[] pubKeyEnc = null;
        byte[] sname = null;

        try {
            DataInputStream is = new DataInputStream(new FileInputStream(this.pubFileName));
            int len = is.readInt();
            sname = new byte[len];
            is.read(sname);
            len = is.readInt();
            pubKeyEnc = new byte[len];
            is.read(pubKeyEnc);
            is.close();
        } catch (IOException var8) {
            this.Error("Fehler beim Lesen des public keys!", var8);
        }

        KeyFactory keyFac = null;

        try {
            keyFac = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException var7) {
            this.Error("Es existiert keine KeyFactory fuer RSA.", var7);
        }

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);

        try {
            this.pubKey = keyFac.generatePublic(x509KeySpec);
        } catch (InvalidKeySpecException var6) {
            this.Error("Fehler beim Konvertieren des Schluessels.", var6);
        }

        String snameStr = new String(sname);
        System.out.println("\nPublic key fuer <" + snameStr + "> wurde erfolgreich gelesen: " + this.byteArraytoHexString(pubKeyEnc));
    }

    public void convertSSFFile() {
        try {
            DataInputStream is = new DataInputStream(new FileInputStream(this.ssfFileName));
            int len = is.readInt();
            this.encryptedSKey = new byte[len];
            is.read(this.encryptedSKey);
            System.out.println("\nDer geheime Schluessel wurde erfolgreich gelesen!");
            len = is.readInt();
            this.signature = new byte[len];
            is.read(this.signature);
            System.out.println("Die Signatur des geheimen Schl�ssels wurde erfolgreich gelesen!");
            len = is.readInt();
            byte[] encodedAP = new byte[len];
            is.read(encodedAP);
            System.out.println("Die algorithmischen Parameter des geheimen Schl�ssels wurden erfolgreich gelesen!");
            AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");
            ap.init(encodedAP);
            System.out.println("Die algorithmischen Parameter des geheimen Schl�ssels wurden erfolgreich initialisiert!");
            this.decryptKey();
            System.out.println("Der geheime Schluessel: " + this.byteArraytoHexString(this.encodedSKey) + " wurde erfolgreich entschluesselt!");
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec skspec = new SecretKeySpec(this.encodedSKey, "AES");
            cipher.init(2, skspec, ap);
            System.out.println("Das Cipher-Objekt  wurde erfolgreich initialisiert!");
            FileOutputStream out = new FileOutputStream(this.docFileName);
            byte[] data = new byte[1024];

            while((len = is.read(data)) > 0) {
                out.write(cipher.update(data, 0, len));
            }

            out.write(cipher.doFinal());
            is.close();
            out.close();
        } catch (Exception var9) {
            this.Error("Fehler beim Schreiben der Dokumentendatei oder Lesen der .ssf-Datei!", var9);
        }

    }

    public void decryptKey() {
        try {
            Cipher chipher = Cipher.getInstance("RSA");
            chipher.init(2, this.privKey);
            this.encodedSKey = chipher.doFinal(this.encryptedSKey);
        } catch (NoSuchAlgorithmException var2) {
            this.Error("Keine Implementierung fuer RSA vorhanden!", var2);
        } catch (InvalidKeyException var3) {
            this.Error("Falscher Algorithmus?", var3);
        } catch (Exception var4) {
            this.Error("Fehler bei der Entschluesselung des geheimen Schluessels", var4);
        }

    }

    public boolean verifySignature() {
        boolean signaturOK = false;
        Signature rsa = null;

        try {
            rsa = Signature.getInstance("SHA512withRSA");
            rsa.initVerify(this.pubKey);
            rsa.update(this.encodedSKey);
        } catch (NoSuchAlgorithmException var5) {
            this.Error("Keine Implementierung fuer SHA512withRSA vorhanden!", var5);
        } catch (SignatureException var6) {
            this.Error("Fehler beim Ueberpruefen der Signatur!", var6);
        } catch (InvalidKeyException var7) {
            this.Error("Falscher Schluesseltyp bei Ueberpruefung der Signatur!", var7);
        }

        try {
            signaturOK = rsa.verify(this.signature);
            if (signaturOK) {
                System.out.println("\nDie Signatur wurde erfolgreich verifiziert: " + this.byteArraytoHexString(this.signature));
            } else {
                System.out.println("\nDie Signatur " + this.byteArraytoHexString(this.signature) + " konnte nicht verifiziert werden!!!\n");
            }
        } catch (SignatureException var4) {
            this.Error("Fehler beim Verifizieren der Signatur!", var4);
        }

        return signaturOK;
    }

    private String byteArraytoHexString(byte[] byteArray) {
        String ret = "";

        for(int i = 0; i < byteArray.length; ++i) {
            ret = ret + this.bytetoHexString(byteArray[i]) + " ";
        }

        return ret;
    }

    private String bytetoHexString(byte b) {
        String ret = Integer.toHexString(b & 255).toUpperCase();
        ret = (ret.length() < 2 ? "0" : "") + ret;
        return ret;
    }

    private void Error(String msg, Exception ex) {
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        System.out.println(msg);
        System.out.println(ex.getMessage());
        System.out.println("Hat leider noch nicht geklappt --> Abbruch der Verarbeitung, sorry!");
        System.exit(0);
    }
}
