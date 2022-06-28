package haw.aydosch.Blatt4;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Ticket-Klasse
 */
import java.util.*;

public class Ticket extends Object {

	private String myClientName; // Konstruktor-Parameter

	private String myServerName; // Konstruktor-Parameter

	private long myStartTime; // Konstruktor-Parameter

	private long myEndTime; // Konstruktor-Parameter

	private long mySessionKey; // Konstruktor-Parameter

	// Geheimer Schlüssel, mit dem das Ticket (simuliert) verschlüsselt ist:
	private long myTicketKey;

	private boolean isEncryptedState; // Aktueller Zustand des Objekts

	// Kalenderobjekt zur Zeitumrechnung (für Testausgaben)
	private Calendar cal;

	// Konstruktor
	public Ticket(String clientName, String serverName, long startTime,
			long endTime, long sessionKey) {

		myClientName = clientName;
		myServerName = serverName;
		myStartTime = startTime;
		myEndTime = endTime;
		mySessionKey = sessionKey;

		myTicketKey = -1;
		isEncryptedState = false;
		cal = new GregorianCalendar(); // für Testausgaben
	}

	public String getClientName() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsseltes Ticket (getClientName)");
		}
		return myClientName;
	}

	public String getServerName() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsseltes Ticket (getServerName)");
		}
		return myServerName;
	}

	public long getStartTime() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsseltes Ticket (getStartTime)");
		}
		return myStartTime;
	}

	public long getEndTime() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsseltes Ticket (getEndTime)");
		}
		return myEndTime;
	}

	public long getSessionKey() {
		if (isEncryptedState) {
			printError("Zugriff auf verschlüsseltes Ticket (getSessionKey)");
		}
		return mySessionKey;
	}

	public boolean encrypt(long key) {
		// Ticket mit dem Key verschlüsseln.
		// Falls das Ticket bereits verschlüsselt ist, wird false zurückgegeben.
		boolean encOK = false;
		if (isEncryptedState) {
			printError("Ticket ist bereits verschlüsselt");
		} else {
			myTicketKey = key;
			isEncryptedState = true;
			encOK = true;
		}
		return encOK;
	}

	public boolean decrypt(long key) {
		// Ticket mit dem Key entschlüsseln.
		// Falls der Key falsch ist oder
		// falls das Ticket bereits entschlüsselt ist, wird false zurückgegeben.
		boolean decOK = false;
		if (!isEncryptedState) {
			printError("Ticket ist bereits entschlüsselt");
		}
		if (myTicketKey != key) {
			printError("Ticket-Entschlüsselung mit key " + key
					+ " ist fehlgeschlagen");
		} else {
			isEncryptedState = false;
			decOK = true;
		}
		return decOK;
	}

	public boolean isEncrypted() {
		// Aktuellen Zustand zurückgeben: verschlüsselt (true) / entschlüsselt
		// (false)
		return isEncryptedState;
	}

	public void print() {
		System.out.println("********* Ticket für " + myClientName + " / "
				+ myServerName + " *******");
		System.out.println("StartTime: " + getDateString(myStartTime)
				+ " - EndTime: " + getDateString(myEndTime));
		System.out.println("Session Key: " + mySessionKey);
		System.out.println("Ticket Key: " + myTicketKey);
		if (isEncryptedState) {
			System.out.println("Ticket-Zustand: verschlüsselt (encrypted)!");
		} else {
			System.out.println("Ticket-Zustand: entschlüsselt (decrypted)!");
		}
	}

	public void printError(String message) {
		System.out.println("+++++++++++++++++++");
		System.out.println("+++++++++++++++++++ Fehler +++++++++++++++++++ "
				+ message + "! Ticket-Key: " + myTicketKey);
		System.out.println("+++++++++++++++++++");
	}

	private String getDateString(long time) {
		// Umrechnung der Zeitangabe time (Millisek. seit 1.1.1970) in einen
		// Datumsstring
		String dateString;

		cal.setTimeInMillis(time);
		dateString = cal.get(Calendar.DAY_OF_MONTH) + "."
				+ (cal.get(Calendar.MONTH) + 1) + "." + cal.get(Calendar.YEAR)
				+ " " + cal.get(Calendar.HOUR_OF_DAY) + ":"
				+ cal.get(Calendar.MINUTE) + ":" + cal.get(Calendar.SECOND)
				+ ":" + cal.get(Calendar.MILLISECOND);
		return dateString;
	}
}
