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
import java.security.Security;

class Box {    
    
    public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  // Necessary to use BC algorithms

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
		String mackey;
		String iv;
		
		int BUFF_SIZE = 8192;

		UtilsBox.decConfig("./configs/config.properties.enc", "./configs/PBE-cryptoconfig");
		

		ArrayList<Properties> listAddr = UtilsBox.parserProperties("configs/config.properties.enc.dec");

		UtilsBox.deleteFile("configs/config.properties.enc.dec");

		ArrayList<DatagramSocket> inSocketSet = new ArrayList<DatagramSocket>();
		ArrayList<DatagramSocket> outSocketSet = new ArrayList<DatagramSocket>();	

		UtilsBox.getSetup(listAddr, inSocketSet, outSocketSet);

		byte[] buffer = new byte[BUFF_SIZE * 3];

		DatagramSocket inConn = null;
		DatagramSocket outConn = null;
		InetSocketAddress outAddress = null;
		DatagramSocket outConnData = null;

		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);


		MessageDigest digest = null;
		Mac hMac = null;
		byte[] dBuff = null;
		byte[] hBuff = null;
		byte[] data = null;
		byte[] ddBuff = null;
		String movie = null;


		while (true){

			UtilsBox.timeoutSock(inSocketSet, 100);

			Boolean start = false;
			while (!start){
				for(DatagramSocket inSock : inSocketSet){
					try{
						inSock.receive(inPacket);
						inConn = inSock;
						start = true;
					} catch (Exception e){
						continue;
					}
				}
			}

			start = true;

			outConnData = UtilsBox.findOutSocket(inConn, inSocketSet, outSocketSet);
			outAddress = new InetSocketAddress(outConnData.getLocalAddress(), outConnData.getLocalPort());
			outConn =  new DatagramSocket();
			outConnData.close();
			inConn.setSoTimeout(0);		// Don't care about timeout now
			
			UtilsBox.decConfig("./configs/box-cryptoconfig.enc", "./configs/PBE-cryptoconfig");

			Properties propStream = UtilsBox.parserCryptoConfig(inConn.getLocalAddress().toString().substring(1) + ":" + String.valueOf(inConn.getLocalPort()), 
																	"./configs/box-cryptoconfig.enc.dec");

			UtilsBox.deleteFile("./configs/box-cryptoconfig.enc.dec");

			csuite = propStream.getProperty("ciphersuite");
			k = propStream.getProperty("key");
			hic = propStream.getProperty("integrity");
			mackey = propStream.getProperty("Mackey");
			iv = propStream.getProperty("iv");

			Cipher c = UtilsBox.prepareCipher(csuite, k, iv);
			if (mackey.equals("NULL") && hic.equals("NULL") ){
				;	// Integrity already provided
			} else if(mackey.equals("NULL")){
				digest = UtilsBox.prepareHashFunc(hic);
			} else {
				hMac = UtilsBox.prepareMacFunc(hic, mackey);
			}


			long tStart = System.currentTimeMillis();
			int totCount = 0;
			int discarded = 0;
			int sizeC = 0;
			int sizeD = 0;
			int sizeTot = 0;

			while (true) {
				boolean ok = false;
				inConn.receive(inPacket);
				if (UtilsBox.isFinished(inPacket)){
					break;
				}

				totCount++;

				data = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
				sizeTot += inPacket.getLength();

				if (mackey.equals("NULL") && hic.equals("NULL") ){
					sizeC += inPacket.getLength();
					dBuff = c.doFinal(data);
					ok = true;
				} else if(mackey.equals("NULL")){
					sizeC += inPacket.getLength()-digest.getDigestLength();
					dBuff = c.doFinal(Arrays.copyOfRange(data, 0, inPacket.getLength()-digest.getDigestLength()));
					hBuff = digest.digest(dBuff);
					ddBuff = Arrays.copyOfRange(data, inPacket.getLength()-digest.getDigestLength(), inPacket.getLength());
					if( MessageDigest.isEqual(hBuff, ddBuff)){
						ok = true;
					}
				} else {
					sizeC += inPacket.getLength()-hMac.getMacLength();
					dBuff = c.doFinal(Arrays.copyOfRange(data, 0, inPacket.getLength()-hMac.getMacLength()));
					hBuff = hMac.doFinal(dBuff);
					ddBuff = Arrays.copyOfRange(data, inPacket.getLength()-hMac.getMacLength(), inPacket.getLength());
					if( Arrays.equals(hBuff, ddBuff)){
						ok = true;
					}
				}

				if (ok){
					sizeD += dBuff.length;
					outConn.send(new DatagramPacket(dBuff, dBuff.length, outAddress));
				} else {
					discarded++;
				}

				// System.out.print("*");

			}

			inConn.receive(inPacket);
			byte[] movieB = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
			movie = new String(movieB);

			outConn.close();
			long tEnd = System.currentTimeMillis();
			int time = (int) (tEnd - tStart)/1000;
		
			PrinStatsBox.print(movie, csuite, hic, k, totCount, sizeTot, sizeC, sizeD, time, discarded);
		}

	}
	
}

	

