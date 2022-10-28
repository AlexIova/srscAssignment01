import java.io.*;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Random;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.InvalidKeySpecException;


public class UtilsBox {
    
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
