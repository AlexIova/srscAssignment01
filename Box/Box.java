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
	
		/*
        InputStream inputStream = new FileInputStream("configs/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
		*/

		/* <PBE> */
		PBEencryption("configs/box-cryptoconfig", "password");
		PBEdecryption("configs/box-cryptoconfig.enc", "password");
		System.exit(-1);
		/* </PBE> */




		ArrayList<Properties> listAddr = parserProperties("configs/config.properties");

		ArrayList<Properties> listConfigServer = new ArrayList<Properties>();
		
		for (Properties propAddr : listAddr){
			listConfigServer.add(parserCryptoConfig(propAddr.getProperty("remote")));
		}

		for (Properties servSuite : listConfigServer){
			System.out.println(servSuite.toString());
		}

		System.out.println(listConfigServer.get(0).getProperty("ciphersuite"));

		System.exit(-1);
		
		// String remote = properties.getProperty("remote");
		// // System.out.println("REMOTE: " + remote);
        
		// String destinations = properties.getProperty("localdelivery");
		// // System.out.println("LOCALDELIVERY: " + destinations);
        
		// SocketAddress inSocketAddress = parseSocketAddress(remote);		// If receiveing unicast
		// // System.out.println("inSocketAddress: " + inSocketAddress.toString());
        
		// Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());
		// System.out.println("outSocketAddressSet: " + outSocketAddressSet.toString());

		// DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 
    	// DatagramSocket outSocket = new DatagramSocket();
        // byte[] buffer = new byte[BUFF_SIZE];
		// // probably you ned to use a larger buffer for the requirements of
		// // TP1 - remember that you will receive datagrams with encrtypted
		// // contents, so depending on the crypti configurations, the datagrams
		// // will be bigger than the plaintext data in the initial example.

		// // Not that this Box is always trying to receive streams
		// // You must modify this to contrl the end of one received
		// // movie) to obtain the related statistics (see PrintStats)

		// /* <Derypto> */
		// /*
        // byte[] iv  = new byte[]
		// {
		// 	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
		// 	0x0f, 0x0d, 0x0e, 0x0c, 0x0b, 0x0a, 0x09, 0x08 
		// };
		// IvParameterSpec dps = new IvParameterSpec(iv);
		// String stringKey = "b356198719e456a6";
		// Key key = new SecretKeySpec(stringKey.getBytes(), "AES");
        // Cipher c = Cipher.getInstance("AES/OFB/NoPadding");
		// c.init(Cipher.DECRYPT_MODE, key, dps);
        // byte[] dBuff = new byte[BUFF_SIZE];
		// */
        // /* <Derypto> */




        // while (buffer.length > 0 ) {
		// 	// System.out.println("Dopo while");
        //   	DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
		// 	// System.out.println("Taking packet");
 	  	// 	inSocket.receive(inPacket);  
		// 	// System.out.println("RECEIVED");

		// 	/* <RECEIVE DECRYPTION> */
		// 	/*
		// 	dBuff = c.doFinal(inPacket.getData());			// now should be decrypted
		// 	*/
		// 	/* </RECEIVE DECRYPTION> */


        //   	System.out.print("*"); 	// Just for debug. Comment for final
	    //                      		// observations and statistics
	  
        //   	for (SocketAddress outSocketAddress : outSocketAddressSet) 
        //     {
        //       // outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
		// 	  outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
	    // 	}


		// // TODO: You must control/detect the end of a streamed movie to
		// // call PrintStats to print the obtained statistics from
		// // required instrumentation variables for experimental observations

		// // PrintStats (......)
		// }
    }


	public static ArrayList<Properties> parserProperties(String path){
		ArrayList<Properties> listProp = new ArrayList<Properties>();

		try {
			BufferedReader br = new BufferedReader(new FileReader("./configs/config.properties"));
			StringBuilder sb = new StringBuilder();
			String currentLine;

			// find sections
			while ((currentLine = br.readLine()) != null){
				if (currentLine.contains("---")){
					Properties prop = new Properties();
					prop.load(new ByteArrayInputStream( sb.toString().getBytes()));
					listProp.add(prop);

					sb.setLength(0);
					continue;
				}		
				sb.append(currentLine + "\n");
			}
			Properties prop = new Properties();
			prop.load(new ByteArrayInputStream( sb.toString().getBytes()));
			listProp.add(prop);
			
			System.out.println("----- PARSED (config.properties):\n" + listProp.toString() + "\n\n");

			br.close();
		} 
		catch (Exception e) {
			System.out.println("config.properties file not found");
		}

		return listProp;
	}


	public static Properties parserCryptoConfig(String addr){
		Properties properties = new Properties();

		int colon = addr.indexOf(":");

		if(addr.substring(0 , colon).equals("localhost")){
			addr = addr.replace("localhost", "127.0.0.1");
		}
			
		System.out.println("addr: " + addr);
		

		String start = "<" + addr + ">";
		String finish = "</" + addr + ">";
		try {
			BufferedReader br = new BufferedReader(new FileReader("./configs/box-cryptoconfig"));
			StringBuilder sb = new StringBuilder();
			String currentLine;
	
			// find beginning
			while ((currentLine = br.readLine()) != null && !(currentLine.contains(start))) {
				System.out.println(currentLine);
			}

			// find end
			while ((currentLine = br.readLine()) != null && !(currentLine.contains(finish))) {
				if (currentLine.indexOf("//") != -1)	// remove comments
					currentLine = currentLine.substring(0, currentLine.indexOf("//"));
				sb.append(currentLine);
				sb.append("\n");
			}

			if(sb.length() == 0){
				System.out.println("Can't find address in box-cryptoconfig file");
				System.exit(-1);
			}
			
			properties.load(new ByteArrayInputStream( sb.toString().getBytes() ));

			System.out.println("----- PARSED (box-cryptoconfig):\n" + sb.toString() + "\n\n");

			br.close();
		} 
		catch (Exception e) {
			System.out.println("box-cryptoconfig file not found");
		}

		return properties;

	}


	public static void PBEencryption(String path, String password){
		try
		{
			FileInputStream inFile = new FileInputStream(path);
			FileOutputStream outFile = new FileOutputStream(path + ".enc");
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
			SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
			byte[] salt = new byte[8];
			Random random = new Random();
			random.nextBytes(salt);
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
			Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);

			outFile.write(salt);
			
			byte[] input = new byte[64];
			int bytesRead;
			while ((bytesRead = inFile.read(input)) != -1) {
				byte[] output = cipher.update(input, 0, bytesRead);
				if (output != null)
					outFile.write(output);
			}
			byte[] output = cipher.doFinal();
			if (output != null)
				outFile.write(output);

			inFile.close();
			outFile.flush();
			outFile.close();

		}
		catch (Exception e){
			System.out.println("Errror in encryption");
		}
		
	}


	public static void PBEdecryption(String path, String password){
		try
		{
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
			SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
			FileInputStream fis = new FileInputStream(path);
			byte[] salt = new byte[8];
			fis.read(salt);
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);

			Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");

			cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);

			FileOutputStream fos = new FileOutputStream(path + ".dec");
			byte[] in = new byte[64];
			int read;
			while ((read = fis.read(in)) != -1) {
				byte[] output = cipher.update(in, 0, read);
				if (output != null)
					fos.write(output);
			}
			byte[] output = cipher.doFinal();

			if (output != null)
				fos.write(output);

			fis.close();
			fos.flush();
			fos.close();

		}
		catch ( NoSuchAlgorithmException | BadPaddingException 
				| IllegalBlockSizeException | InvalidAlgorithmParameterException
				| InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException
				| IOException e){
			System.out.println("Errror in decryption: " + e);
		}
		
	}

}
