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

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		// Necessary to use BC algorithms
      
		int size=0;
		int count=0;
 		long time=0;

		int BUFF_SIZE = 8192;
		
		Properties properties = UtilsServer.parseMoviesConfig(args[0]);

		String algorithm = properties.getProperty("ciphersuite").substring(0 , properties.getProperty("ciphersuite").indexOf("/"));
		UtilsServer.decryptMovieAndVerify(args[0], algorithm, properties.getProperty("ciphersuite"), 
									properties.getProperty("key"), properties.getProperty("iv"), 
									properties.getProperty("integrity"), properties.getProperty("integrity-check"),
									properties.getProperty("mackey"));
		String decName = args[0] + ".dec";



		UtilsServer.decConfig("./configs/box-cryptoconfig.enc", "./configs/PBE-cryptoconfig");
		Properties BoxConfig = UtilsServer.parserCryptoConfig(args[1] + ":" + args[2]);
		UtilsServer.deleteFile("./configs/box-cryptoconfig.enc.dec");
		System.out.println("BoxConfig properties");
		System.out.println(BoxConfig.toString() + "\n\n");

		String movie = decName;

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
		
		
		DataInputStream g = new DataInputStream( new FileInputStream(decName) );
		
		byte[] buff = new byte[BUFF_SIZE];

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
		} else {
			hMac = UtilsServer.prepareMacFunc(hcheck, mackey);
		}
		byte[] cBuff = null;
		

		p.setSocketAddress( addr ); 
		s.send(p);

		long tBeginning = System.currentTimeMillis();

		while ( g.available() > 0 ) { //while I have segments to read
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time;
			count += 1;
			g.readFully(buff, 0, size );

			ms += size;
							
			cBuff = c.doFinal(Arrays.copyOfRange(buff, 0, size));

			if (mackey.equals("NULL") && hcheck.equals("NULL") ){
				;	// Integrity already provided
				p.setData(cBuff, 0, cBuff.length );
			} else if(mackey.equals("NULL")){
				dBuff = digest.digest(Arrays.copyOfRange(buff, 0, size));
				wBuff = UtilsServer.byteArrConcat(cBuff, dBuff);
				p.setData(wBuff, 0, wBuff.length);
			} else {
				dBuff = hMac.doFinal(Arrays.copyOfRange(buff, 0, size));
				wBuff = UtilsServer.byteArrConcat(cBuff, dBuff);
				p.setData(wBuff, 0, wBuff.length);
			}
			
			p.setSocketAddress( addr ); 
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
			

			s.send( p );
			nf += 1;	// counter sent frames
			sizeSent += p.getLength();
			
			// System.out.print( "." );

		}
			long tFinish = System.currentTimeMillis();
			etm = (int) (tFinish-tBeginning)/1000;

			UtilsServer.sendNull(p, s);

			p.setData(args[0].getBytes(), 0, args[0].getBytes().length);
			s.send(p);
			
			PrintStatsServer.Print(args[0], BoxConfig.getProperty("ciphersuite"), 
								BoxConfig.getProperty("integrity"), 
								BoxConfig.getProperty("key"),
								nf, ms, count, etm);

			UtilsServer.deleteFile(decName);
			
	}

}






