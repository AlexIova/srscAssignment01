import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Properties;
import java.nio.charset.StandardCharsets;




public class UtilsServer {

    public static Properties parseMoviesConfig(String moviePath){
		Properties properties = new Properties();

		String movie = moviePath.substring(moviePath.lastIndexOf('/') + 1).trim();

		String start = "<" + movie + ">";
		String finish = "</" + movie + ">";
		try {
			BufferedReader br = new BufferedReader(new FileReader("./configs/movies-cryptoconfig"));
			StringBuilder sb = new StringBuilder();
			String currentLine;
	
			// find beginning
			while ((currentLine = br.readLine()) != null && !(currentLine.contains(start))) {
				;
			}

			// find end
			while ((currentLine = br.readLine()) != null && !(currentLine.contains(finish))) {
				sb.append(currentLine);
				sb.append("\n");
			}

			if(sb.length() == 0){
				System.out.println("Can't find movie in movies-cryptoconfig file");
				System.exit(-1);
			}
			
			properties.load(new ByteArrayInputStream( sb.toString().getBytes() ));

			System.out.println("----- PARSED:\n" + sb.toString() + "\n\n");

			br.close();
		} 
		catch (Exception e) {
			System.out.println("movies-cryptoconfig file not found");
		}

		return properties;
	}


	public static void decryptMovie(String path, String algorithm , 
									String ciphersuite, String key, 
									String iv, String fIntegrity, 
									String integrity_check) throws CryptoException{
		try
		{
			String decMovie = path + ".dec";
			File encMovie = new File(path);
			IvParameterSpec ivSpec = new IvParameterSpec(hexStringToByteArray(iv));
			Key secretKey = new SecretKeySpec(hexStringToByteArray(key), algorithm);

			Cipher cipher = Cipher.getInstance(ciphersuite);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

			FileInputStream inputStream = new FileInputStream(encMovie);
			byte[] inputBytes = new byte[(int) encMovie.length()];
			inputStream.read(inputBytes);
			inputStream.close();
			

			byte[] outputBytes = cipher.doFinal(inputBytes);

			FileOutputStream outputStream = new FileOutputStream(decMovie);
			outputStream.write(outputBytes);
			outputStream.close();

		}
		catch (NoSuchPaddingException | NoSuchAlgorithmException 
				| InvalidKeyException | BadPaddingException
				| IllegalBlockSizeException
			 	| InvalidAlgorithmParameterException | IOException ex)
		{
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}
    

	public static void encryptMovie(String path, String algorithm, 
									String ciphersuite, String key, 
									String iv, String fIntegrity, 
									String integrity_check) throws CryptoException{
		try
		{
			String encMovie = path + ".encrypted";
			File plainMovie = new File(path);
			IvParameterSpec ivSpec = new IvParameterSpec(hexStringToByteArray(iv));
			Key secretKey = new SecretKeySpec(hexStringToByteArray(key), algorithm);

			Cipher cipher = Cipher.getInstance(ciphersuite);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			FileInputStream inputStream = new FileInputStream(plainMovie);
			byte[] inputBytes = new byte[(int) plainMovie.length()];
			inputStream.read(inputBytes);
			inputStream.close();
			

			byte[] outputBytes = cipher.doFinal(inputBytes);

			FileOutputStream outputStream = new FileOutputStream(encMovie);
			outputStream.write(outputBytes);
			outputStream.close();

		}
		catch (NoSuchPaddingException | NoSuchAlgorithmException 
				| InvalidKeyException | BadPaddingException
				| IllegalBlockSizeException
			 	| InvalidAlgorithmParameterException | IOException ex)
		{
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}
    
    
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
    

	// Found on stackOverflow
	private static String bytesToHex(byte[] bytes) {
		byte[] HEX_ARRAY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
		byte[] hexChars = new byte[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars, StandardCharsets.UTF_8);
	}


	private static boolean verifyHash(String hCheck, String integrity_check, String path) throws CryptoException{
		try
		{
			byte[] buffer= new byte[8192];
			int count;
			MessageDigest digest = MessageDigest.getInstance(hCheck);
			BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(path));


			while ((count = inputStream.read(buffer)) != -1) {
				digest.update(buffer, 0, count);
			}

			inputStream.close();
		
			byte[] plainDigest = digest.digest();

			System.out.println("----- INTEGRITY (HASH):");
			System.out.println("plainDigest: " + bytesToHex(plainDigest));
			System.out.println("integrity_check: " + integrity_check);
			System.out.println("\n\n");

			return Arrays.equals(plainDigest, hexStringToByteArray(integrity_check));
		}
		catch (NoSuchAlgorithmException | IOException ex ){
			throw new CryptoException("Error verifying hash", ex);
		}

	}


	private static boolean verifyMac(String hCheck, String integrity_check, String path, String macKey) throws CryptoException{
		try
		{
			byte[] buffer= new byte[8192];
			int count;
			BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(path));
			Mac hMac = Mac.getInstance(hCheck);
			Key hMacKey = new SecretKeySpec(hexStringToByteArray(macKey), hCheck);
			hMac.init(hMacKey);

			while ((count = inputStream.read(buffer)) != -1) {
				hMac.update(buffer, 0, count);
			}

			inputStream.close();

			byte[] plainDigest = hMac.doFinal();

			System.out.println("----- INTEGRITY (HMAC):");
			System.out.println("plainDigest: " + bytesToHex(plainDigest));
			System.out.println("integrity_check: " + integrity_check);
			System.out.println("\n\n");

			return Arrays.equals(plainDigest, hexStringToByteArray(integrity_check));
		} 
		catch (NoSuchAlgorithmException | InvalidKeyException | IOException ex){
			throw new CryptoException("Error verifying mac", ex);
		}
	}


	public static boolean verifyMovie(String hCheck, String integrity_check, String path, String macKey) throws CryptoException{
		if(macKey.equals("NULL")){
			return verifyHash(hCheck, integrity_check, path); 
		} else {
			return verifyMac(hCheck, integrity_check, path, macKey);
		}
	}


	public static Properties parserCryptoConfig(String addr){
		Properties properties = new Properties();

		int colon = addr.indexOf(":");

		if(addr.substring(0 , colon).equals("localhost")){
			addr = addr.replace("localhost", "127.0.0.1");
		}

		String start = "<" + addr + ">";
		String finish = "</" + addr + ">";
		try {
			BufferedReader br = new BufferedReader(new FileReader("./configs/box-cryptoconfig"));
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


	public static Cipher prepareCipher(String ciphersuite, String key, String iv) throws CryptoException{
		String algorithm = ciphersuite.substring(0 , ciphersuite.indexOf("/"));

		try
		{
			IvParameterSpec ivSpec = new IvParameterSpec(hexStringToByteArray(iv));
			Key secretKey = new SecretKeySpec(hexStringToByteArray(key), algorithm);
			Cipher cipher = Cipher.getInstance(ciphersuite);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
			return cipher;
		}
		catch (NoSuchPaddingException | NoSuchAlgorithmException 
				| InvalidKeyException| InvalidAlgorithmParameterException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
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


}