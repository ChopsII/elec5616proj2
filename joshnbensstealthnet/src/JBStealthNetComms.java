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

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.DHPublicKey;
import java.io.*;
import java.lang.reflect.Array;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/* StealthNetComms class *****************************************************/

public class JBStealthNetComms {
    public static final String SERVERNAME = "localhost";
    public static final int SERVERPORT = 5616;
	public static Cipher cipher;						//("blowfish");
    public static Mac mac;							    // HMAC-MD5

    private Socket commsSocket;            				// communications socket
    private PrintWriter dataOut;            			// output data stream
    private BufferedReader dataIn;          			// input data stream

	// Keys
	private KeyPair myKeyPair;							// key Pair used in DH
	private SecretKey sharedSecret;						// the shared secret after DH
	private byte[] sharedSecretEnc = new byte[8];	    // 56 bit encoding of shared secret for blowfish
	private KeyAgreement keyAgree;						// Key Agreement used in DH

	//Random Numbers
	private int mySeqNum = 0;							// The next sequence number to send
	private int otherSeqNum = 0;						// the next valid sequence number to expect

	//Random Number Generators
	SecureRandom myRandom;							    // Sending sequence numbers
	SecureRandom otherRandom;							// Recieving sequence numbers

    public JBStealthNetComms() {
        try {
			// Initialise Ciphers, random number generators and mac
			cipher = Cipher.getInstance("Blowfish");
			myRandom = SecureRandom.getInstance("SHA1PRNG");
			otherRandom = SecureRandom.getInstance("SHA1PRNG");
			mac = Mac.getInstance("HmacMD5");
        } catch(Exception e) {
            System.err.println("Unsupported algorithm");
        }
    }

    protected void finalize() throws IOException {
        if (dataOut != null)
            dataOut.close();
        if (dataIn != null)
            dataIn.close();
        if (commsSocket != null)
            commsSocket.close();
    }

    public boolean initiateSession(Socket socket) {
      try {
        commsSocket = socket;
        dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
        dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));

        // generate DH parameters
        genDhParams(null);

        //Send Public key from DH
        JBStealthNetPacket pack = new JBStealthNetPacket(JBStealthNetPacket.CMD_PUBKEY, myKeyPair.getPublic().getEncoded());
        sendPacket(pack);

        // Wait for a response
        while (!recvReady()){}

        // Get the encoded public key
        byte[] peerEncKey = recvPacket().data;
        KeyFactory keyGen = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(peerEncKey);
        PublicKey decodedKey = keyGen.generatePublic(x509KeySpec);
        DHPublicKey peerKey = (DHPublicKey)decodedKey;

        // Begin phase of key
        phaseDHKey(peerKey);
      }catch(Exception e){
		System.err.println("Unable to inialise session");
      }

      return true;
    }

	public void genDhParams(DHPublicKey peerPublicKey) {
	  try {
		DHParameterSpec dhSpec;
		if (peerPublicKey == null) {
	    // Create the parameter generator for a 1024-bit DH key pair
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
	    paramGen.init(512);

	    // Generate the parameters
	    AlgorithmParameters params = paramGen.generateParameters();
	    dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
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
	  } catch(Exception e){
        System.err.println("Unable to generate DH parameters");
      }
	}

    public void phaseDHKey(DHPublicKey peerPublicKey){
    	try{
        keyAgree.doPhase(peerPublicKey, true);

		// Generate the secret key
		sharedSecret = keyAgree.generateSecret("Blowfish");

		// Truncate secret to 56 bits from 56 bytes due to incorrect generate secret
		System.arraycopy(sharedSecretEnc, 0, sharedSecret.getEncoded(), 0, Array.getLength(sharedSecretEnc));

		// Seed the random number generators
		otherRandom.setSeed(sharedSecretEnc);
		myRandom.setSeed(sharedSecretEnc);
    	}catch(Exception e){
    		System.err.println("Unable to phase DH key");
    	}
    }

    public boolean acceptSession(Socket socket) {
        try {
			commsSocket = socket;
			dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
			dataIn = new BufferedReader(new InputStreamReader(commsSocket.getInputStream()));

			// Wait for a response
			while (!recvReady()){
			}

            // Get the public encoded key
            byte[] publicEncKey = recvPacket().data;
            KeyFactory keyGen = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicEncKey);
            PublicKey decodedKey = keyGen.generatePublic(x509KeySpec);
            DHPublicKey otherKey = (DHPublicKey)decodedKey;

			// generate the DH parameters
			genDhParams(otherKey);

			// Send my public key
			JBStealthNetPacket pack = new JBStealthNetPacket(JBStealthNetPacket.CMD_PUBKEY, myKeyPair.getPublic().getEncoded());
			sendPacket(pack);

			// Generate shared secret
			phaseDHKey(otherKey);
    	}catch(Exception e){
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

    public boolean sendPacket(byte command, byte[] data)  {
      return sendPacket(command, data, data.length);
    }

    public boolean sendPacket(byte command, byte[] data, int size) {
      JBStealthNetPacket pckt = new JBStealthNetPacket();
      pckt.command = command;
      pckt.data = new byte[size];
      System.arraycopy(data, 0, pckt.data, 0, size);
      return sendPacket(pckt);
    }

    public boolean sendPacket(JBStealthNetPacket pckt) {
      if (dataOut == null)
        return false;

        // Ensure we don't encrypt the key packets during DH
        if(pckt.getCommand() != JBStealthNetPacket.CMD_PUBKEY) {
          	pckt.data = digestData(pckt.data);
          	pckt.data = encryptData(pckt.data);
        }
      dataOut.println(pckt.toString());
      return true;
    }

    public JBStealthNetPacket recvPacket() throws IOException {
        JBStealthNetPacket pckt = null;
        String str = dataIn.readLine();
        pckt = new JBStealthNetPacket(str);

        // Ensure we don't encrypt the key packets during DH
        if(pckt.getCommand() != JBStealthNetPacket.CMD_PUBKEY) {
            pckt.data = decryptData(pckt.data);
            pckt.data = vomitData(pckt.data);
        }

        return pckt;
    }

    public byte[] encryptData(byte[] data){
      byte[] encrypted = null;

      try{
		// Encrypt data with the Blowfish algorithm and the shared secret key
		SecretKeySpec skeySpec = new SecretKeySpec(sharedSecretEnc, "Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        encrypted = cipher.doFinal(data);
      }
      catch(Exception e){
        System.err.println("Encryption failed");
      }

      return encrypted;
    }

    public byte[] decryptData(byte[] data){
        byte[] decrypted = null;

        try{
            // Decrypt data with the Blowfish algorithm and the shared secret key
            SecretKeySpec skeySpec = new SecretKeySpec(sharedSecretEnc, "Blowfish");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            decrypted = cipher.doFinal(data);
        } catch(Exception e) {
          System.err.println("Decryption failed");
        }

        return decrypted;
    }

    public byte[] digestData(byte[] data)  {
        byte[] message = new byte[0];
        byte[] hmac = new byte[0];

        try {
            mac.init(sharedSecret);

            //Convert sequence number to byte array
            byte[] sequenceNumberArr = ByteBuffer.allocate(4).putInt(mySeqNum).array();
            //Concatenate message and sequence number
            message = concatByteArray(sequenceNumberArr, data);
            //calculate the mac of |Sequence Number|Message|
            hmac = mac.doFinal(message);

            // Increment my sequence number
            genMySeqNum();
        } catch(Exception e){
            System.err.println("Digest Data fail");
            return null;
        }

        //Return |Sequence Number|Message|HMAC
        return concatByteArray(message, hmac);
    }

    public byte[] vomitData(byte[] data) {
        byte[] hmac = new byte[16];
        byte[] message = new byte[Array.getLength(data) - 4 - 16];
        byte[] seqMessage = new byte[Array.getLength(data) - 16];
        int sentNumber = ByteBuffer.wrap(data,0,4).getInt();

        try {
            mac.init(sharedSecret);

            // Copy the byte segments we need
            System.arraycopy(data, 0, seqMessage, 0, Array.getLength(data) - 16); //|Sequence Number|Message|
            System.arraycopy(data, Array.getLength(data) - 16, hmac, 0, 16); //HMAC
            System.arraycopy(data, 4, message, 0, Array.getLength(data) - 16 -4); //Message

            // Check sequence numbers match
            if (sentNumber !=	otherSeqNum) {
	            throw new IOException("Sequence number failed - " + sentNumber + ", expected " + otherSeqNum);
            }

            // Check HMACs are equals
            if (!Arrays.equals(mac.doFinal(seqMessage), hmac)) {
	            throw new IOException("HMAC check failed - ");
            }

            // Valid message so increment to next sequence number
            genOtherSeqNum();
        } catch(Exception e){
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
		byte[] arr = new byte[Array.getLength(arr1) + Array.getLength(arr2)];

		System.arraycopy(arr1, 0, arr, 0, Array.getLength(arr1));
		System.arraycopy(arr2, 0, arr, Array.getLength(arr1), Array.getLength(arr2));

		return arr;
	}

    public boolean recvReady() throws IOException {
        return dataIn.ready();
    }

	public static void printByteArray(byte[] arr) {
		for (int i=0; i < Array.getLength(arr); i++) {
			System.out.print(arr[i] + " ");
		}
		System.out.println();
	}
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/

