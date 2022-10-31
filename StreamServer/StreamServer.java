/*
 * 
 * hjStreamServer.java 
 * Implementatio of a Java-based Streaming Server allowing the
 * the real time streaming of movies encoded in local files
 * The Streaming Server transmits the video frames for real time streaming
 * based (carried in)  UDP packets.
 * Clients can play the streams in real time if they are able to
 * decode the content of the frames in the UDP packets (FFMPEG encoding)
 *
 * To start the Streaming Server use:
 * hjStreamServer <file> <ip address for dissemination> <port dissemination>
 * 
 * Example: hjStreamServer cars.dat localhost 9999
 * In this case the Streaming server will send the movie to localhost port 999
 * where "someone" - a user using a visualizaton tool such as VLC or a BOX
 * is waiting for.
 * There are some available movies in the directory movies. This is the
 * the directory where the server has the movies it can send.
*/

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.lang.model.type.NullType;
import java.security.Security;
import java.util.Arrays;
import java.util.Properties;
import java.nio.charset.StandardCharsets;




class StreamServer {

	public static void main( String []args ) throws Exception {
		if (args.length != 3)
		{
			System.out.println ("Use: hjSteramServer <movie> <ip-multicast-address> <port>");
			System.out.println("  or: hjStreamServer <movie> <ip-unicast-address> <port>");
			System.exit(-1);
		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
      
		int size=0;
		int count=0;
 		long time=0;

		int BUFF_SIZE = 8192;
		
		// Properties properties = UtilsServer.parseMoviesConfig(args[0]);


		/* <TestBoxCryptoConfig> */
		Properties BoxConfig = UtilsServer.parserCryptoConfig(args[1] + ":" + args[2]);
		System.out.println("BoxConfig properties");
		System.out.println(BoxConfig.toString() + "\n\n");
		// System.exit(-1);
		/* </TestBoxCryptoConfig> */

		String movie = args[1];
		String ciphersuite= BoxConfig.getProperty("ciphersuite"); //configured ciphersuite
		String hcheck=BoxConfig.getProperty("integrity"); //config. cryptographic hash function
		String key=BoxConfig.getProperty("key"); //configured key in hexadecimal representation
		int nf=0; // number of sent frames in the stream
		int afs=0; // average size of sent frames
		int ms=0; // total size of the stremed movie
		int etm=0; // total elapsed time of the sent movie
		int frate=0; // achieved frame rate in #frames/sec
		int tput=0;// achieved throughput in transmissoin in Kbytes/sec

		String iv = BoxConfig.getProperty("iv");
		String mackey = BoxConfig.getProperty("Mackey");

		System.out.println("----- PROPERTIES:");
		System.out.println("ciphersuite: " + ciphersuite);
		System.out.println("key: " + key);
		System.out.println("iv: " + iv);
		System.out.println("hcheck: " + hcheck);
		System.out.println("Mackey: " + mackey);
		System.out.println("\n\n");

		/* <Test Encryption movie> */
		/*
		String algorithm = ciphersuite.substring(0 , ciphersuite.indexOf("/"));
		UtilsServer.encryptMovie(args[0], algorithm, ciphersuite, key, iv, hcheck, integrity_check);
		*/
		// System.exit(-1);
		
		/* </Test Encryption movie> */


		/* <Test Decryption movie> */
		/*
		String algorithm = ciphersuite.substring(0 , ciphersuite.indexOf("/"));
		decryptMovie(args[0], algorithm, ciphersuite, key, iv, hcheck, integrity_check);
		String decName = args[0] + ".dec";
		*/
		// System.exit(-1);
		/* </Test Decryption movie> */



		/* <Test integrity> */
		// System.out.println("Check: " + hexStringToByteArray(integrity_check).toString());
		/*
		if(verifyMovie(hcheck, integrity_check, args[0], mackey)){
			System.out.println("OK! Verified.");
		} else {
			System.out.println("Something went wrong with integrity check...");
		}
		System.exit(-1);
		*/
		/* </Test integrity> */
		
		
		DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
		// The file with the movie-media content (encoded frames)
		
		byte[] buff = new byte[BUFF_SIZE * 3];
		// Probably you must use a bigger buff size for the
		// purpose of TP1, because in the TP1 you will use the
		// buffer to process encrypted streams together with
		// with hash-based integrity checks as required for
		// TP1 implementation

		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); //ref time for real-time stream
		long q0 = 0;
		long sizeSent = 0;


		// I'm sure this will be initialized if needed so I don't worry about it
		MessageDigest digest = null;
		Mac hMac = null;
		byte[] dBuff = null;
		byte[] wBuff = null;

		Cipher c = UtilsServer.prepareCipher(ciphersuite, key, iv);
		if (mackey.equals("NULL") && hcheck.equals("NULL") ){
			;	// Integrity already provided
		} else if(mackey.equals("NULL")){
			digest = UtilsServer.prepareHashFunc(hcheck);
			dBuff = new byte[BUFF_SIZE];
			wBuff = new byte[BUFF_SIZE * 3];
		} else {
			hMac = UtilsServer.prepareMacFunc(hcheck, mackey);
			dBuff = new byte[BUFF_SIZE];
			wBuff = new byte[BUFF_SIZE * 3];
		}
		byte[] cBuff = null;
		

		p.setSocketAddress( addr ); 
		s.send(p);

		long tBeginning = System.currentTimeMillis();

		while ( g.available() > 0 ) { //while I have segments to read
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; //real time stream control
			count += 1;
			g.readFully(buff, 0, size ); //read a segment

			ms += size;
							

			// System.out.println("size: " + size);
			// System.out.println("\n---data: " + Arrays.toString(Arrays.copyOfRange(buff, 0, size)) + "\n");
			cBuff = c.doFinal(Arrays.copyOfRange(buff, 0, size));
			// System.out.println("len cbuff: " + cBuff.length);

			if (mackey.equals("NULL") && hcheck.equals("NULL") ){
				;	// Integrity already provided
				p.setData(cBuff, 0, cBuff.length );
				// System.out.println("primo");
			} else if(mackey.equals("NULL")){
				dBuff = digest.digest(Arrays.copyOfRange(buff, 0, size));
				// System.out.println("------dbuff: \n" + Arrays.toString(dBuff) + "\n");
				// System.out.println("------cbuff: \n" + Arrays.toString(cBuff) + "\n");
				wBuff = UtilsServer.byteArrConcat(cBuff, dBuff);
				// System.out.println("len wbfuff: " + wBuff.length);
				p.setData(wBuff, 0, wBuff.length);
				// System.out.println("secondo");
			} else {
				dBuff = hMac.doFinal(Arrays.copyOfRange(buff, 0, size));
				wBuff = UtilsServer.byteArrConcat(cBuff, dBuff);
				p.setData(wBuff, 0, wBuff.length);
				// System.out.println("terzo");
			}
			
			p.setSocketAddress( addr ); 
			long t = System.nanoTime(); //take current time
			// and sync. the wait tome to dispatch the segment
			// correctly with the required real-time control
			// (as encoded in segment timestamps)
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
		    // send packet (with a frame payload)	
			

			s.send( p );
			nf += 1;	// counter sent frames
			sizeSent += p.getLength();

			// System.out.println("len after sent: " + p.getLength());
			
			System.out.print( "." ); // just for debug
			// take this last line off or any I/O or debug for
			// final observations in TP1

		}
			long tFinish = System.currentTimeMillis();
			etm = (int) (tFinish-tBeginning)/1000;


			byte[]  nullByte = new byte[] { 
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				};

			System.out.println("sent null");
			p.setData(nullByte, 0, nullByte.length);
			s.send(p);

			p.setData(args[0].getBytes(), 0, args[0].getBytes().length);
			s.send(p);

			// Note:
			// For TP1
			// YOU MUST IMPLEMENT THE REQUIRED SECURITY
			// SPECIFICATIONS and you MUST PROCESS THE
			// INSTRUMENTATION VARIABLES
			// REQUIRED TO USE FOR PrintStsts (see below)
			// to obtain the related
			// experimental anlysis and observations, as observed
			// in the StreamingServer side

            //to do this the idea is to support this in a
			//method you must implement, inspired in the
			// following PrintStats() calling it with the
			// obtained instrumentation variabes during the
			// stream
			
			PrintStatsServer.Print(args[0], BoxConfig.getProperty("ciphersuite"), 
								BoxConfig.getProperty("integrity"), 
								BoxConfig.getProperty("key"),
								nf, ms, count, etm);
			
	}

}






