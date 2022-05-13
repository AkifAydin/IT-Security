package haw.aydosch.Blatt1.A3;

import java.io.*;

public class TripleDES {
    private FileInputStream inputStream;
    private DES DES1;
    private DES DES2;
    private DES DES3;

   /* Constructor */
   public TripleDES (byte[] keyPart1, byte[] keyPart2, byte[] keyPart3) {
       // Create DES objects using keys
        this.DES1 = new DES(keyPart1);
        this.DES2 = new DES(keyPart2);
        this.DES3 = new DES(keyPart3);
   }
   
   /* encrypt plaintext block  */
   public byte[] encryptBytes (byte[] plaintextBytes){
       byte[] resultBytes = new byte[8];

       // encrypt (using DES1)
       this.DES1.encrypt(plaintextBytes, 0, resultBytes, 0);

       // decrypt (using DES2)
       this.DES2.decrypt(resultBytes, 0, resultBytes, 0);

       // encrypt (using DES3)
       this.DES3.encrypt(resultBytes, 0, resultBytes, 0);


       return resultBytes;
   }
   
  /* decrypt plaintext block  */
   public byte[] decryptBytes (byte[] chiffreBytes){
       byte[] resultBytes = new byte[8];

       // encrypt (using DES1)
       this.DES3.decrypt(chiffreBytes, 0, resultBytes, 0);

       // decrypt (using DES2)
       this.DES2.encrypt(resultBytes, 0, resultBytes, 0);

       // encrypt (using DES3)
       this.DES1.decrypt(resultBytes, 0, resultBytes, 0);


       return resultBytes;
   }
   
	private String byteArraytoHexString(byte[] byteArray) {
		String ret = "";
		for (int i = 0; i < byteArray.length; ++i) {
			ret = ret + String.format("%02x", byteArray[i]) + " ";
		}
		return ret;
	}
	
	public static void main(String[] args) {
      /* Testcode */
        TripleDES cipher = new TripleDES("qwertzui".getBytes(), "asdfghjk".getBytes(), "yxcvbnm,".getBytes());
      
      byte[] plain = "12345678".getBytes();
      byte[] chiffre = cipher.encryptBytes(plain);
      System.out.println(" Encrypted: " +  cipher.byteArraytoHexString(plain) + " to: " + cipher.byteArraytoHexString(chiffre));
      
      byte[] plainNew = cipher.decryptBytes(chiffre);
      System.out.println(" Decrypted: " + cipher.byteArraytoHexString(plainNew) );
      
      if (java.util.Arrays.equals(plain, plainNew)) {
         System.out.println(" ---> Erfolg!");
      } else {
         System.out.println(" ---> Hat leider noch nicht funktioniert ...!");
      }
	}
}
