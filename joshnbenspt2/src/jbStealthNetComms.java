/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetComms.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 * IMPLEMENTS:      initiateSession();
 *                  acceptSession();
 *                  terminateSession();
 *                  sendPacket();
 *                  recvPacket();
 *                  recvReady();
 *
 * REVISION HISTORY:
 *
 **********************************************************************************/

/* Import Libraries **********************************************************/

import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Hashtable;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.*;
import java.nio.*;

/* StealthNetComms class *****************************************************/

public class jbStealthNetComms {
	public static final String SERVERNAME = "localhost";
	public static final int SERVERPORT = 5616;

	public Cipher cipher; // ("blowfish");
	public Mac mac; // HMAC-MD5

	private Socket commsSocket; // communications socket
	private PrintWriter dataOut; // output data stream
	private BufferedReader dataIn; // input data stream

	// Keys
	private KeyPair myKeyPair; // key Pair used in DH
	private SecretKey sharedSecret; // the shared secret after DH
	private byte[] sharedSecretEnc = new byte[8]; // 56 bit encoding of shared
													// secret for blowfish
	private KeyAgreement keyAgree; // Key Agreement used in DH
	private Cipher outCipher = null;
	private Cipher inCipher;

	// Random Numbers
	private int mySeqNum = 0; // The next sequence number to send
	private int otherSeqNum = 0; // the next valid sequence number to expect

	// Random Number Generators
	SecureRandom myRandom; // Sending sequence numbers
	SecureRandom otherRandom; // Recieving sequence numbers

	public PublicKey publicKey = null;

	/*
	 * Takes a cipher to be used for decrypting data that comes in
	 */
	public jbStealthNetComms(Cipher in) {
		try {
			// Initialise Ciphers, random number generators and mac
			cipher = Cipher.getInstance("Blowfish");
			myRandom = SecureRandom.getInstance("SHA1PRNG");
			otherRandom = SecureRandom.getInstance("SHA1PRNG");
			mac = Mac.getInstance("HmacMD5");
			inCipher = in;
		} catch (Exception e) {
			System.err.println("Unsupported algorithm");
		}
	}

	/* sets the cipher to be used for encrypting */
	public void setOutCipher(Cipher out) {
		this.outCipher = out;
	}

	/* sets the public key for RSA sent only for log in attempts */
	public void setPublicKey(PublicKey p) {
		publicKey = p;
	}

	protected void finalize() throws IOException {
		if (dataOut != null)
			dataOut.close();
		if (dataIn != null)
			dataIn.close();
		if (commsSocket != null)
			commsSocket.close();
	}

	/*
	 * Performs our diffie-hellman key exchange encrypted with the corresponding
	 * public keys
	 */
	public boolean initiateSession(Socket socket) {
		try {
			commsSocket = socket;
			dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
			dataIn = new BufferedReader(new InputStreamReader(commsSocket
					.getInputStream()));

			// generate DH parameters
			genDhParams(null);

			/*
			 * In the case where a public key has been set we send our RSA
			 * Public Key off to the server This happens only when we first
			 * connect to the server.
			 */
			if (publicKey != null) {
				jbStealthNetPacket pack = new jbStealthNetPacket(
						jbStealthNetPacket.CMD_PUBKEY, publicKey.getEncoded());
				sendPacket(pack);
			}

			// Send Public key from DH
			jbStealthNetPacket pack = new jbStealthNetPacket(
					jbStealthNetPacket.CMD_PUBKEY, myKeyPair.getPublic()
							.getEncoded());
			sendPacket(pack);

			// Wait for a response
			while (!recvReady()) {
			}

			// Get the encoded public key
			byte[] peerEncKey = recvPacket().data;
			KeyFactory keyGen = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(peerEncKey);
			PublicKey decodedKey = keyGen.generatePublic(x509KeySpec);
			DHPublicKey peerKey = (DHPublicKey) decodedKey;

			// Begin phase of key
			phaseDHKey(peerKey);
		} catch (Exception e) {
			System.err.println("Unable to initialise session");
		}

		return true;
	}

	public void genDhParams(DHPublicKey peerPublicKey) {
		try {
			DHParameterSpec dhSpec;
			if (peerPublicKey == null) {
				// Create the parameter generator for a 1024-bit DH key pair
				AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator
						.getInstance("DH");
				paramGen.init(512);

				// Generate the parameters
				AlgorithmParameters params = paramGen.generateParameters();
				dhSpec = (DHParameterSpec) params
						.getParameterSpec(DHParameterSpec.class);
			} else {
				// get the parameters from the other public key
				dhSpec = peerPublicKey.getParams();
			}

			// Initialise the DH algorithm and generate keys
			KeyPairGenerator pairGen = KeyPairGenerator.getInstance("DH");
			pairGen.initialize(dhSpec);
			myKeyPair = pairGen.generateKeyPair();

			// Generate the DH key agreement
			keyAgree = KeyAgreement.getInstance("DH");
			keyAgree.init(myKeyPair.getPrivate());
		} catch (Exception e) {
			System.err.println("Unable to generate DH parameters");
		}
	}

	public void phaseDHKey(DHPublicKey peerPublicKey) {
		try {
			keyAgree.doPhase(peerPublicKey, true);
			// Generate the secret key
			sharedSecret = keyAgree.generateSecret("Blowfish");

			// Truncate secret to 56 bits from 56 bytes due to incorrect
			// generate secret
			System.arraycopy(sharedSecretEnc, 0, sharedSecret.getEncoded(), 0,
					sharedSecretEnc.length);

			// Seed the random number generators
			otherRandom.setSeed(sharedSecretEnc);
			myRandom.setSeed(sharedSecretEnc);
		} catch (Exception e) {
			System.err.println("Unable to phase DH key");
		}
	}

	public boolean acceptSession(Socket socket) {
		try {
			commsSocket = socket;
			dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
			dataIn = new BufferedReader(new InputStreamReader(commsSocket
					.getInputStream()));

			// Wait for a response
			while (!recvReady()) {
			}

			/*
			 * If we do not have an outCipher this means we don't know the
			 * public key. This can only happen when a user is logging in. The
			 * server is the one accepting the connection so it immediately
			 * accepts the public key then uses it to encrypt the rest of the
			 * transmission. Later on it can decide whether to reject this
			 * connection (based on whether the public key is valid or not).
			 */
			if (outCipher == null) {
				byte[] encodedKey = recvPacket().data;

				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
						encodedKey);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PublicKey otherPublicKey = kf.generatePublic(publicKeySpec);

				Cipher myCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				myCipher.init(Cipher.ENCRYPT_MODE, otherPublicKey);

				publicKey = otherPublicKey;

				setOutCipher(myCipher);
				while (!recvReady()) {
				}
			}

			// Get the public encoded key
			byte[] publicEncKey = recvPacket().data;
			KeyFactory keyGen = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
					publicEncKey);
			PublicKey decodedKey = keyGen.generatePublic(x509KeySpec);
			DHPublicKey otherKey = (DHPublicKey) decodedKey;

			// generate the DH parameters
			genDhParams(otherKey);

			// Send my public key
			jbStealthNetPacket pack = new jbStealthNetPacket(
					jbStealthNetPacket.CMD_PUBKEY, myKeyPair.getPublic()
							.getEncoded());
			sendPacket(pack);

			// Generate shared secret
			phaseDHKey(otherKey);
		} catch (Exception e) {
			System.err.println("Unable to accept session");
		}

		return true;
	}

	public boolean terminateSession() {
		try {
			if (commsSocket == null)
				return false;
			dataIn.close();
			dataOut.close();
			commsSocket.close();
			commsSocket = null;
		} catch (Exception e) {
			return false;
		}

		return true;
	}

	public boolean sendPacket(byte command) {
		return sendPacket(command, new byte[0]);
	}

	public boolean sendPacket(byte command, String data) {
		return sendPacket(command, data.getBytes());
	}

	public boolean sendPacket(byte command, byte[] data) {
		return sendPacket(command, data, data.length);
	}

	public boolean sendPacket(byte command, byte[] data, int size) {
		jbStealthNetPacket pckt = new jbStealthNetPacket();
		pckt.command = command;
		pckt.data = new byte[size];
		System.arraycopy(data, 0, pckt.data, 0, size);
		return sendPacket(pckt);
	}

	public boolean sendPacket(jbStealthNetPacket pckt) {
		if (dataOut == null)
			return false;
		if (outCipher == null)
			return false;

		// If its key exchange time use rsa, otherwise encrypt normally
		if (pckt.getCommand() != jbStealthNetPacket.CMD_PUBKEY) {
			pckt.data = digestData(pckt.data);
			pckt.data = encryptData(pckt.data);
		} else {
			pckt.data = encryptWithRSA(pckt.data);
		}

		dataOut.println(pckt.toString());
		return true;
	}

	public jbStealthNetPacket recvPacket() throws IOException {
		jbStealthNetPacket pckt = null;
		String str = dataIn.readLine();
		pckt = new jbStealthNetPacket(str);

		// If its key exchange time use rsa, otherwise encrypt normally
		if (pckt.getCommand() != jbStealthNetPacket.CMD_PUBKEY) {
			pckt.data = decryptData(pckt.data);
			pckt.data = vomitData(pckt.data);
		} else {
			pckt.data = decryptWithRSA(pckt.data);
		}

		return pckt;
	}

	/*
	 * This encrypts our data with RSA based on the cipher we have been given.
	 * To do this we chop our data up into 100-byte chunks (max for RSA of
	 * 1024-bits is 117-byte chunks). Then send it off. We know that these
	 * chunks will end up as 128 byte chunks so at the other end we can do the
	 * reverse process.
	 */
	private byte[] encryptWithRSA(byte[] data) {
		try {
			ArrayList<Byte> encrypted = new ArrayList<Byte>();
			byte[] buff = new byte[100];
			for (int i = 0; i < data.length; i += 100) {
				if (i + 100 >= data.length) {
					buff = new byte[data.length - i];
					System.arraycopy(data, i, buff, 0, data.length - i);
					byte[] temp = outCipher.doFinal(buff);
					for (byte b : temp) {
						encrypted.add(b);
					}
				} else {
					System.arraycopy(data, i, buff, 0, 100);
					byte[] temp = outCipher.doFinal(buff);
					// System.out.println("Encrypting chunks of: " +
					// temp.length);
					for (byte b : temp) {
						encrypted.add(b);
					}
				}
			}
			byte[] out = new byte[encrypted.size()];
			for (int i = 0; i < encrypted.size(); i++) {
				out[i] = encrypted.get(i);
			}
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// note 100 bytes into cipher = 128 bytes out probably due to padding

	/*
	 * This decrypts a message sent that was encrypted with RSA. We take our
	 * data and chop it up into chunks of 128 bytes. Then decrypt each chunk and
	 * plug it all back together.
	 */
	private byte[] decryptWithRSA(byte[] data) {
		// System.out.println("Decrypting:");

		try {
			ArrayList<Byte> decrypted = new ArrayList<Byte>();
			byte[] buff = new byte[128];
			for (int i = 0; i < data.length; i += 128) {
				if (i + 128 >= data.length) {
					buff = new byte[data.length - i];
					System.arraycopy(data, i, buff, 0, data.length - i);
					byte[] temp = inCipher.doFinal(buff);
					for (byte b : temp) {
						decrypted.add(b);
					}
				} else {
					System.arraycopy(data, i, buff, 0, 128);
					// System.out.println("Decrypting Block:");

					byte[] temp = inCipher.doFinal(buff);
					for (byte b : temp) {
						decrypted.add(b);
					}
				}
			}
			byte[] out = new byte[decrypted.size()];
			for (int i = 0; i < decrypted.size(); i++) {
				out[i] = decrypted.get(i);
			}
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] encryptData(byte[] data) {
		byte[] encrypted = null;

		try {
			// Encrypt data with the Blowfish algorithm and the shared secret
			// key
			SecretKeySpec skeySpec = new SecretKeySpec(sharedSecretEnc,
					"Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			encrypted = cipher.doFinal(data);
		} catch (Exception e) {
			System.err.println("Encryption failed");
		}

		return encrypted;
	}

	public byte[] decryptData(byte[] data) {
		byte[] decrypted = null;

		try {
			// Decrypt data with the Blowfish algorithm and the shared secret
			// key
			SecretKeySpec skeySpec = new SecretKeySpec(sharedSecretEnc,
					"Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			decrypted = cipher.doFinal(data);
		} catch (Exception e) {
			System.err.println("Decryption failed");
		}

		return decrypted;
	}

	public byte[] digestData(byte[] data) {
		byte[] message = new byte[0];
		byte[] hmac = new byte[0];

		try {
			mac.init(sharedSecret);

			// Convert sequence number to byte array
			byte[] sequenceNumberArr = ByteBuffer.allocate(4).putInt(mySeqNum)
					.array();
			// Concatenate message and sequence number
			message = concatByteArray(sequenceNumberArr, data);
			// calculate the mac of |Sequence Number|Message|
			hmac = mac.doFinal(message);

			// Increment my sequence number
			genMySeqNum();
		} catch (Exception e) {
			System.err.println("Digest Data fail");
			return null;
		}

		// Return |Sequence Number|Message|HMAC
		return concatByteArray(message, hmac);
	}

	public byte[] vomitData(byte[] data) {
		byte[] hmac = new byte[16];
		byte[] message = new byte[data.length - 4 - 16];
		byte[] seqMessage = new byte[data.length - 16];
		int sentNumber = ByteBuffer.wrap(data, 0, 4).getInt();

		try {
			mac.init(sharedSecret);

			// Copy the byte segments we need
			System.arraycopy(data, 0, seqMessage, 0, data.length - 16); // |Sequence
																		// Number|Message|
			System.arraycopy(data, data.length - 16, hmac, 0, 16); // HMAC
			System.arraycopy(data, 4, message, 0, data.length - 16 - 4); // Message

			// Check sequence numbers match
			if (sentNumber != otherSeqNum) {
				throw new IOException("Sequence number failed - " + sentNumber
						+ ", expected " + otherSeqNum);
			}

			// Check HMACs are equals
			if (!Arrays.equals(mac.doFinal(seqMessage), hmac)) {
				throw new IOException("HMAC check failed - ");
			}

			// Valid message so increment to next sequence number
			genOtherSeqNum();
		} catch (Exception e) {
			System.err.println("Vomit Data fail");
			e.printStackTrace();
			return null;
		}

		return message;
	}

	public void genMySeqNum() {
		mySeqNum = myRandom.nextInt();
	}

	public void genOtherSeqNum() {
		otherSeqNum = otherRandom.nextInt();
	}

	public byte[] concatByteArray(byte[] arr1, byte[] arr2) {
		byte[] arr = new byte[arr1.length + arr2.length];

		System.arraycopy(arr1, 0, arr, 0, arr1.length);
		System.arraycopy(arr2, 0, arr, arr1.length, arr2.length);

		return arr;
	}

	public boolean recvReady() throws IOException {
		return dataIn.ready();
	}
}

/******************************************************************************
 * END OF FILE: StealthNetComms.java
 *****************************************************************************/

