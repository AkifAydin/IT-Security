package haw.aydosch.Blatt4;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* TicketResponse-Klasse
 */

public class TicketResponse extends Object {

	private long mySessionKey; // Konstruktor-Parameter

	private long myNonce; // Konstruktor-Parameter

	private Ticket myResponseTicket; // Konstruktor-Parameter

	// Geheimer Schlüssel, mit dem diese Antwort (Response) (simuliert)
	// verschlüsselt ist:
	private long myResponseKey;

	private boolean isEncryptedState; // Aktueller Zustand des Objekts

	// Konstruktor
	public TicketResponse(long sessionKey, long nonce, Ticket responseTicket) {
		mySessionKey = sessionKey;
		myNonce = nonce;
		myResponseTicket = responseTicket;
		myResponseKey = -1;
		isEncryptedState = false;
	}

	public long getSessionKey() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsselte Ticket-Response (getSessionKey)");
		}
		return mySessionKey;
	}

	public long getNonce() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsselte Ticket-Response (getNonce)");
		}
		return myNonce;
	}

	public Ticket getResponseTicket() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsselte Ticket-Response (getResponseTicket)");
		}
		return myResponseTicket;
	}

	public boolean encrypt(long key) {
		// TicketResponse mit dem Key verschlüsseln.
		// Falls die TicketResponse bereits verschlüsselt ist, wird false
		// zurückgegeben.
		boolean encOK = false;
		if (isEncryptedState) {
			printError("TicketResponse ist bereits verschlüsselt");
		} else {
			myResponseKey = key;
			isEncryptedState = true;
			encOK = true;
		}
		return encOK;
	}

	public boolean decrypt(long key) {
		// TicketResponse mit dem Key entschlüsseln.
		// Falls der Key falsch ist oder
		// falls die TicketResponse bereits entschlüsselt ist, wird false
		// zurückgegeben.
		boolean decOK = false;
		if (!isEncryptedState) {
			printError("TicketResponse ist bereits entschlüsselt");
		}
		if (myResponseKey != key) {
			printError("TicketResponse-Entschlüsselung mit key " + key
					+ " ist fehlgeschlagen");
		} else {
			isEncryptedState = false;
			decOK = true;
		}
		return decOK;
	}

	public boolean isEncrypted() {
		// Aktuellen Zustand zurückgeben:
		// verschlüsselt (true) / entschlüsselt (false)
		return isEncryptedState;
	}

	public void printError(String message) {
		System.out.println("+++++++++++++++++++");
		System.out.println("+++++++++++++++++++ Fehler +++++++++++++++++++ "
				+ message + "! TicketResponse-Key: " + myResponseKey);
		System.out.println("+++++++++++++++++++");
	}

	public void print() {
		System.out.println("********* TicketResponse *******");
		System.out.println("Session Key: " + mySessionKey);
		System.out.println("Nonce: " + myNonce);
		myResponseTicket.print();
		System.out.println("Response Key: " + myResponseKey);
		if (isEncryptedState) {
			System.out
					.println("TicketResponse-Zustand: verschlüsselt (encrypted)!");
		} else {
			System.out
					.println("TicketResponse-Zustand: entschlüsselt (decrypted)!");
		}
		System.out.println();
	}

}
