package haw.aydosch.Blatt4;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

public class Client extends Object {

	private KDC myKDC; // Konstruktor-Parameter

	private String currentUser; // Speicherung bei Login nötig
	private Ticket tgsTicket = null; // Speicherung bei Login nötig
	private long tgsSessionKey; // K(C,TGS) // Speicherung bei Login nötig

	// Konstruktor
	public Client(KDC kdc) {
		myKDC = kdc;
	}

	public boolean login(String userName, char[] password) {
		/* ToDo */
		long nonce = this.generateNonce();
		TicketResponse response = this.myKDC.requestTGSTicket(userName, "myTGS", nonce);
		if (response == null) {
			System.out.println("Invalid ServerName or Username: Can't find ServerName myTGS or Username " + userName);
			return false;
 		}

		long passwordKey = generateSimpleKeyFromPassword(password);
		boolean status = response.decrypt(passwordKey);
		if(!status) {
			response.printError("Invalid Password: Couldn't decrypt with passwordKey!");
			return false;
		}

		// Replay attack prevention
		if(nonce != response.getNonce()) {
			response.printError("Nonce is invalid!");
			return false;
		}


		this.tgsTicket = response.getResponseTicket();
		this.tgsSessionKey = response.getSessionKey();
		this.currentUser = userName;

		return true;
	}

	public boolean showFile(Server fileServer, String filePath) {
		Auth tgsAuth = new Auth(this.currentUser, System.currentTimeMillis());
		tgsAuth.encrypt(tgsSessionKey);

		TicketResponse srvTicketResponse = this.myKDC.requestServerTicket(this.tgsTicket, tgsAuth, fileServer.getName(), generateNonce());
		if(srvTicketResponse == null) {
			tgsAuth.printError("TicketResponse is null!");
			return false;
		}

		if(!srvTicketResponse.decrypt(this.tgsSessionKey)) {
			srvTicketResponse.printError("Session key is not valid!");
			return false;
		}

		Auth serviceAuth = new Auth(currentUser, System.currentTimeMillis());
		serviceAuth.encrypt(srvTicketResponse.getSessionKey());

		boolean statusServiceRequest = fileServer.requestService(srvTicketResponse.getResponseTicket(), serviceAuth, "showFile", filePath);
		if(!statusServiceRequest) {
			System.out.println("Service couldn't be requested. Dunno why");
			return false;
		}


		return true;
		/* ToDo */
	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyFromPassword(char[] passwd) {
		// Liefert einen eindeutig aus dem Passwort abgeleiteten Schlüssel
		// zurück, hier simuliert als long-Wert
		long pwKey = 0;
		if (passwd != null) {
			for (int i = 0; i < passwd.length; i++) {
				pwKey = pwKey + passwd[i];
			}
		}
		return pwKey;
	}

	private long generateNonce() {
		// Liefert einen neuen Zufallswert
		long rand = (long) (100000000 * Math.random());
		return rand;
	}
}
