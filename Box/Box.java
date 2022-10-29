/* hjBox, 22/23
 *
 * This is the implementation of a Box to receive streamed UDP packets
 * (with media segments as payloads encoding MPEG4 frames)
 * The code is inspired (in fact very similar) to the code presented,
 * available, used and discussed in Labs (Lab 2, Part I)
 *
 * You can use this material as a starting point for your Box implementation
 * in TP1, according to the TP1 requirements
 */

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Set;
import java.util.Random;
import java.util.stream.Collectors;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.InvalidKeySpecException;

class Box {
    
    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }    
    
    public static void main(String[] args) throws Exception {

		// Need these variables for instrumentation metrics on
		// received and processed streams delivered to the
		// media player
		String movie; // name of received movie
		String csuite; // used cyphersuite to process the received stream
		String k;   // The key used, in Hexadecimal representation
        int ksize;  // The key size
        String hic; // Hash function used for integrity checks
		int ascsegments;    // average size of encrypted segments received
		int decsegments;    // average size of decrypted segments received	
        int nf;     // number of received frames in a mmvie transmission
		int afs;    // average frame size in a movie transmission
		int ms;     // total size of the receved movie (all segments) in Kbytes
		int etm;    // total elapsed time of the received movie
		int frate;  // observed frame rate in segments/sec)
        int tput;   // observed throughput in the channel (in Kbytes/sec)
        int corruptedframes;   // Nr of corrupted frames discarded (not sent to the media player
		// can add more instrumentation variables considered as interesting

		int BUFF_SIZE = 8192;
	
        InputStream inputStream = new FileInputStream("configs/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);

		/* <PBE> */
		/*
		PBEencryption("configs/box-cryptoconfig", "password");
		PBEdecryption("configs/box-cryptoconfig.enc", "password");
		System.exit(-1);
		*/
		/* </PBE> */



		ArrayList<Properties> listAddr = UtilsBox.parserProperties("configs/config.properties");

		ArrayList<Properties> listConfigServer = new ArrayList<Properties>();
		ArrayList<SocketAddress> inSocketAdressSet = new ArrayList<SocketAddress>();
		ArrayList<SocketAddress> outSocketAddressSet = new ArrayList<SocketAddress>();
		
		System.out.println("\n\n---listAddr");
		System.out.println(listAddr);

		for (Properties propAddr : listAddr){
			listConfigServer.add(UtilsBox.parserCryptoConfig(propAddr.getProperty("remote")));		// get cryptoconfigs
			inSocketAdressSet.add(parseSocketAddress(propAddr.getProperty("remote")));				// get addr remote
			outSocketAddressSet.add(parseSocketAddress(propAddr.getProperty("localdelivery")));		// get addr local
		}		
        
		ArrayList<DatagramSocket> inSocketSet = new ArrayList<DatagramSocket>();
		for (SocketAddress inAddr: inSocketAdressSet){
			inSocketSet.add(new DatagramSocket(inAddr));
		}

		ArrayList<DatagramSocket> outSocketSet = new ArrayList<DatagramSocket>();	
		for (SocketAddress outAddr: outSocketAddressSet){
			outSocketSet.add(new DatagramSocket(outAddr));
		}	

		System.out.println("\n\n---listConfigServer");
		System.out.println(listConfigServer);

		// probably you ned to use a larger buffer for the requirements of
		// TP1 - remember that you will receive datagrams with encrtypted
		// contents, so depending on the crypti configurations, the datagrams
		// will be bigger than the plaintext data in the initial example.

		// Not that this Box is always trying to receive streams
		// You must modify this to contrl the end of one received
		// movie) to obtain the related statistics (see PrintStats)



		for(DatagramSocket inSock : inSocketSet){
			inSock.setSoTimeout(100);
		}
		
		// System.out.println(inSocketSet);
		// System.out.println(outSocketSet);

		byte[] buffer = new byte[BUFF_SIZE * 3];

		DatagramSocket inConn = null;
		DatagramSocket outConn = null;
		InetSocketAddress outAddress = null;
		DatagramSocket outConnData = null;

		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);

		Boolean start = false;
		while (!start){
			for(DatagramSocket inSock : inSocketSet){
				try{
					inSock.receive(inPacket);
					if(inPacket.getData().equals(buffer)){
						inConn = inSock;
						start = true;
						System.out.println("TROVATO");
					}
				} catch (Exception e){
					;
				}
			}
		}

		outConnData = UtilsBox.findOutSocket(inConn, inSocketSet, outSocketSet);
		outAddress = new InetSocketAddress(outConnData.getLocalAddress(), outConnData.getLocalPort());
		outConn =  new DatagramSocket();
		outConnData.close();
		inConn.setSoTimeout(0);		// Don't care about timeout now

		System.out.println(inConn.getLocalAddress() + ":" + String.valueOf(inConn.getLocalPort()));
		Properties propStream = UtilsBox.parserCryptoConfig(inConn.getLocalAddress().toString().substring(1) + ":" + String.valueOf(inConn.getLocalPort()));


		csuite = propStream.getProperty("ciphersuite");
		k = propStream.getProperty("key");
		ksize = 4 * k.length();
		hic = propStream.getProperty("integrity");
		String mackey = propStream.getProperty("Mackey");
		String iv = propStream.getProperty("iv");
		
		System.out.println(csuite + "\t" + k + "\t" + hic + "\t" + mackey + "\t" + iv+ "\t" );		


		MessageDigest digest = null;
		Mac hMac = null;
		byte[] dBuff = null;
		byte[] hBuff = null;
		byte[] data = null;
		byte[] ddBuff = null;

		Cipher c = UtilsBox.prepareCipher(csuite, k, iv);
		if (mackey.equals("NULL") && hic.equals("NULL") ){
			;	// Integrity already provided
		} else if(mackey.equals("NULL")){
			digest = UtilsBox.prepareHashFunc(hic);
		} else {
			hMac = UtilsBox.prepareMacFunc(hic, mackey);
		}


        while (buffer.length > 0 ) {

			inConn.receive(inPacket);

			// System.out.println("len data 1: " + inPacket.getLength());

			data = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());

			boolean ok = false;

			if (mackey.equals("NULL") && hic.equals("NULL") ){
				;	// Integrity already provided
				dBuff = c.doFinal(data);
				ok = true;
			} else if(mackey.equals("NULL")){
				dBuff = c.doFinal(Arrays.copyOfRange(data, 0, inPacket.getLength()-digest.getDigestLength()));
				// System.out.println("dbuff len: " + dBuff.length);
				hBuff = digest.digest(dBuff);
				// System.out.println("\n---hbuff: " + Arrays.toString(hBuff) + "\n");
				// System.out.println("\n---data: " + Arrays.toString(data) + "\n");
				// System.out.println("\n---data: " + Arrays.toString(dBuff) + "\n");
				// System.out.println("hash?: " + (inPacket.getLength()-(inPacket.getLength()-digest.getDigestLength())) + "\t arr: " + Arrays.copyOfRange(data, inPacket.getLength()-digest.getDigestLength(), inPacket.getLength()));
				ddBuff = Arrays.copyOfRange(data, inPacket.getLength()-digest.getDigestLength(), inPacket.getLength());
				// System.out.println("ddBuff len: " + ddBuff.length + "\t arr: \n" + Arrays.toString(ddBuff));
				if( MessageDigest.isEqual(hBuff, ddBuff)){
					ok = true;
				}
			} else {
				dBuff = c.doFinal(Arrays.copyOfRange(data, 0, inPacket.getLength()-hMac.getMacLength()));
				hBuff = hMac.doFinal(dBuff);
				ddBuff = Arrays.copyOfRange(data, inPacket.getLength()-hMac.getMacLength(), inPacket.getLength());
				if( Arrays.equals(hBuff, ddBuff)){
					ok = true;
				}
			}

			if (ok){
				outConn.send(new DatagramPacket(dBuff, dBuff.length, outAddress));
				// System.out.println("BRAVO");
			} else {
				System.out.println("ERRORE");
			}

			/*
			System.out.println(dBuff.length);
			System.out.println(inPacket.getLength());
			*/



          	System.out.print("*"); 	// Just for debug. Comment for final
	                         		// observations and statistics
	  

		// TODO: You must control/detect the end of a streamed movie to
		// call PrintStats to print the obtained statistics from
		// required instrumentation variables for experimental observations

		// PrintStats (......)
		}


	}
}

	

