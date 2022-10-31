import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Random;
import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.InvalidKeySpecException;
import java.net.SocketAddress;
import java.net.InetSocketAddress;

public class UtilsBox {
    
	// Found on stackOverflow
	private static byte[] hexStringToByteArray(String s) {
			byte[] b = new byte[s.length() / 2];
			for (int i = 0; i < b.length; i++) {
			  int index = i * 2;
			  int v = Integer.parseInt(s.substring(index, index + 2), 16);
			  b[i] = (byte) v;
			}
			return b;
		}
	

    public static ArrayList<Properties> parserProperties(String path){
		ArrayList<Properties> listProp = new ArrayList<Properties>();

		try {
			BufferedReader br = new BufferedReader(new FileReader(path));
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


	public static Properties parserCryptoConfig(String addr, String pathFile){
		Properties properties = new Properties();

		int colon = addr.indexOf(":");

		if(addr.substring(0 , colon).equals("localhost")){
			addr = addr.replace("localhost", "127.0.0.1");
		}

		String start = "<" + addr + ">";
		String finish = "</" + addr + ">";
		try {
			BufferedReader br = new BufferedReader(new FileReader(pathFile));
			StringBuilder sb = new StringBuilder();
			String currentLine;
	
			// find beginning
			while ((currentLine = br.readLine()) != null && !(currentLine.contains(start))) {
				;
			}

			// find end
			while ((currentLine = br.readLine()) != null && !(currentLine.contains(finish))) {
				if (currentLine.indexOf("//") != -1)	// remove comments
					currentLine = currentLine.substring(0, currentLine.indexOf("//"));
				sb.append(currentLine.replaceAll("\\s+",""));		// take out whitespace
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


	public static void PBEencryption(String path, String password, String algorithm){
		try
		{
			FileInputStream inFile = new FileInputStream(path);
			FileOutputStream outFile = new FileOutputStream(path + ".enc");
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
			SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
			byte[] salt = new byte[8];
			Random random = new Random();
			random.nextBytes(salt);
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
			Cipher cipher = Cipher.getInstance(algorithm);
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


	public static void PBEdecryption(String path, String password, String algorithm){
		try
		{
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
			SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
			FileInputStream fis = new FileInputStream(path);
			byte[] salt = new byte[8];
			fis.read(salt);
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);

			Cipher cipher = Cipher.getInstance(algorithm);

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

	
	public static Cipher prepareCipher(String ciphersuite, String key, String iv) throws CryptoException{
		String algorithm = ciphersuite.substring(0 , ciphersuite.indexOf("/"));

		try
		{
			IvParameterSpec ivSpec = new IvParameterSpec(hexStringToByteArray(iv));
			Key secretKey = new SecretKeySpec(hexStringToByteArray(key), algorithm);
			Cipher cipher = Cipher.getInstance(ciphersuite);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
			return cipher;
		}
		catch (NoSuchPaddingException | NoSuchAlgorithmException 
				| InvalidKeyException| InvalidAlgorithmParameterException ex) {
			throw new CryptoException("Error decrypting", ex);
		}

	}


	public static MessageDigest prepareHashFunc(String hCheck) throws CryptoException{
		try
		{
			return MessageDigest.getInstance(hCheck);
		}
		catch(NoSuchAlgorithmException ex){
			throw new CryptoException("Error verifying hash", ex);
		}
	}

	
	public static Mac prepareMacFunc(String hCheck, String macKey) throws CryptoException{
		try{
			Mac hMac = Mac.getInstance(hCheck);
			Key hMacKey = new SecretKeySpec(hexStringToByteArray(macKey), hCheck);
			hMac.init(hMacKey);
			return hMac;
		}
		catch(NoSuchAlgorithmException | InvalidKeyException ex){
			throw new CryptoException("Error verifying mac", ex);
		}
	}


	public static byte[] byteArrConcat(byte[] a, byte[] b){
		if (a == null || a.length == 0) return b;

		if (b == null || b.length == 0) return a;

		byte[] c = new byte[a.length + b.length];
		int ctr = 0;

		for (int i = 0; i < a.length; i++) 
			c[ctr++] = a[i];

		for (int i = 0; i < b.length; i++)
			c[ctr++] = b[i];

		return c;
	}


	public static DatagramSocket findOutSocket(DatagramSocket inConn, 
												ArrayList<DatagramSocket> inSocketSet, 
												ArrayList<DatagramSocket> outSocketSet){
		for(DatagramSocket inSock : inSocketSet){
			if (inSock.equals(inConn)){
				return outSocketSet.get(inSocketSet.indexOf(inSock));
			}
		}

		return null;
	}


	public static Boolean isFinished(DatagramPacket p){

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

		byte[] data = Arrays.copyOfRange(p.getData(), 0, p.getLength());

		return Arrays.equals(data, nullByte);
	}


	public static void getSetup(ArrayList<Properties> listAddr, 
								ArrayList<DatagramSocket> inSocketSet, 
								ArrayList<DatagramSocket> outSocketSet){

		ArrayList<SocketAddress> inSocketAdressSet = new ArrayList<SocketAddress>();
		ArrayList<SocketAddress> outSocketAddressSet = new ArrayList<SocketAddress>();

		for (Properties propAddr : listAddr){
			inSocketAdressSet.add(parseSocketAddress(propAddr.getProperty("remote")));				// get addr remote
			outSocketAddressSet.add(parseSocketAddress(propAddr.getProperty("localdelivery")));		// get addr local
		}	

		for (SocketAddress inAddr: inSocketAdressSet){
			try {
				inSocketSet.add(new DatagramSocket(inAddr));
			} catch (SocketException e) {
				System.out.println("Error insockets with" + inAddr.toString());
			}
		}

		for (SocketAddress outAddr: outSocketAddressSet){
			try {
				outSocketSet.add(new DatagramSocket(outAddr));
			} catch (SocketException e) {
				System.out.println("Error insockets with" + outAddr.toString());
			}
		}

		return;
	}


	private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }


	public static void timeoutSock(ArrayList<DatagramSocket> inSocketSet, int time){
		for(DatagramSocket inSock : inSocketSet){
			try {
				inSock.setSoTimeout(time);
			} catch (SocketException e) {
				System.out.println("Error setting timer with" + inSock.toString());
			}
		}
	}


	public static void decConfig(String path, String configPath){
		Properties properties = new Properties();
		try{
			InputStream inputStream = new FileInputStream(configPath);
			properties.load(inputStream);
			inputStream.close();
		} catch (IOException e) {
			System.out.println("Error opening PBE-cryptoconfig file" + e);
		}
        
		PBEdecryption(path, properties.getProperty("password"), properties.getProperty("algorithm"));
		return;
	}


	public static void encConfig(String path, String configPath){
		Properties properties = new Properties();
		try{
			InputStream inputStream = new FileInputStream(configPath);
			properties.load(inputStream);
			inputStream.close();
		} catch (IOException e) {
			System.out.println("Error opening PBE-cryptoconfig file" + e);
		}
        
		PBEencryption(path, properties.getProperty("password"), properties.getProperty("algorithm"));
		return;
	}

	public static void deleteFile(String path){
		File file = new File(path);
		if (file.exists() && file.delete() ) {
			System.out.println("File deleted successfully or already deleted");
		}
		else {
			System.out.println("Failed to delete the file");
		}
	}

}
