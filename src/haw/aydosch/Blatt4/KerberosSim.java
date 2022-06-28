package haw.aydosch.Blatt4;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver */

import java.util.*;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

public class KerberosSim {

	private KDC myKDC;
	private Client myClient;
	private Server myFileserver;

	public static void main(String args[]) {

		/*
		 * Simulation einer Benutzer-Session: Anmeldung und Zugriff auf Fileserver
		 */

		// -------- Start Initialisierung des Systems ------------------
		String userName = "axz467";
		char[] password = { 'S', 'e', 'c', 'r', 'e', 't', '!' };
		String serverName = "myFileserver";
		String tgsName = "myTGS";
		String filePath = "C:/Temp/ITS.txt";

		KerberosSim thisSession = new KerberosSim();

		// KDC + alle Server + Client initialisieren
		thisSession.initKerberos(userName, password, serverName, tgsName);

		// -------- Ende Initialisierung des Systems ------------------

		/* -------- Benutzersession simulieren ------ */
		// Passwort vom Benutzer holen
		System.out.println("Starte Login-Session für Benutzer: " + userName);
		password = thisSession.readPasswd(userName);
		if (password != null) {

			// Benutzeranmeldung beim KDC
			boolean loginOK = thisSession.myClient.login(userName, password);

			// Passwort im Hauptspeicher löschen (überschreiben)!!
			Arrays.fill(password, ' ');

			if (!loginOK) {
				System.out.println("Login fehlgeschlagen!");
			} else {
				System.out.println("Login erfolgreich!\n");

				// Zugriff auf Fileserver
				boolean serviceOK = thisSession.myClient.showFile(thisSession.myFileserver, filePath);
				if (!serviceOK) {
					System.out.println("Zugriff auf Server " + serverName + " ist fehlgeschlagen!");
				}
			}
		}
	}

	private void initKerberos(String userName, char[] password, String serverName, String tgsName) {
		/* KDC initialisieren */
		myKDC = new KDC(tgsName);

		// Server initialisieren
		myFileserver = new Server(serverName);
		myFileserver.setupService(myKDC); // Schlüsselerzeugung und -austausch

		// User-Account und Client erzeugen
		myKDC.userRegistration(userName, password);
		myClient = new Client(myKDC);
	}

	private char[] readPasswd(String userName) {
		/* Passwort des Benutzers zurückgeben oder null, falls Abbruch */
		char[] password = null;

		JPasswordField pf = new JPasswordField();
		int okCxl = JOptionPane.showConfirmDialog(null, pf, "Passwort für " + userName + ": ",
				JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

		if (okCxl == JOptionPane.OK_OPTION) {
			password = pf.getPassword();
		}
		return password;
	}

}
