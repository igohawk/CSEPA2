package ProAssign;

import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerSecurity1v2 {

	private static String signedCertPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\server.crt";
	private static String privateKeyPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\privateServer.der";

	public static void main(String[] args) {

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		byte[] msg = new byte[128];

		try {
			System.out.println("Waiting for connection");
			welcomeSocket = new ServerSocket(8080);
			connectionSocket = welcomeSocket.accept();
			System.out.println("Connection established");

			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			PrintWriter printWriter = new PrintWriter(connectionSocket.getOutputStream(), true);
			//BufferedReader stringIn = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

			//System.out.println(stringIn.readLine());
			fromClient.read(msg);
			System.out.println(new String(msg));

			printWriter.println("Hello, this is SecStore!");
			printWriter.flush();

			// retrieve nonce from client

			byte[] nonce = new byte[fromClient.readInt()];
			readByte(nonce,fromClient);
			System.out.println("RECEIVED FROM CLIENT: nonce");

			// get private key
			PrivateKey privateKey = getPrivateKey();

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);

			// encrypt and transfer nonce
			byte[] encryptedNonce = cipher.doFinal(nonce);
			printWriter.println(Integer.toString(encryptedNonce.length));
			toClient.write(encryptedNonce, 0, encryptedNonce.length);
			toClient.flush();
			System.out.println(nonce);
			System.out.println("SENT TO CLIENT: encrypted nonce");

			// send signed cert
			//System.out.println(stringIn.readLine());
			fromClient.read(msg);
			System.out.println(new String(msg));
			File certFile = new File(signedCertPath);
			byte[] certByte = new byte[(int) certFile.length()];
			FileInputStream fis = new FileInputStream(certFile);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(certByte, 0, certByte.length);

			printWriter.println(certByte.length);
			//System.out.println(stringIn.readLine());
			fromClient.read(msg);
			System.out.println(new String(msg));
			toClient.write(certByte,0,certByte.length);
			toClient.flush();
			System.out.println("SENT TO CLIENT: cert");

			// if check fail, close connection
			//String fromc = stringIn.readLine();
			fromClient.read(msg);
			String fromc = new String(msg);
			System.out.println(fromc);
			if(fromc.equals("Bye")) {
				//stringIn.close();
				printWriter.close();
				toClient.close();
				fromClient.close();
				connectionSocket.close();
			}

			printWriter.println("Successful handshake");
			printWriter.flush();




			// if success, begin file transfer
			System.out.println("*** start to transfer file ***");
			Cipher decipher = Cipher.getInstance("RSA");
			decipher.init(Cipher.DECRYPT_MODE, privateKey);

			//String fileName = stringIn.readLine();
			//String encryptedFileLength  = stringIn.readLine();
			//printWriter.println("Server begin to receive file");
			//printWriter.flush();

			//byte[] encryptedFile = new byte[Integer.parseInt(encryptedFileLength)];
			//readByte(encryptedFile,fromClient);
			//System.out.println("RECEIVED FROM CLIENT: file");

			// decrypt file
			/*ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			int leng = encryptedFile.length;
			int MAX_ENCRYPT_BLOCK= 128;
			int offset = 0;
			//byte[] cache;
			while(leng- offset > 0 ) {
				byte[] cache;
				if(leng - offset>= MAX_ENCRYPT_BLOCK) {
					cache = decipher.doFinal(encryptedFile, offset, MAX_ENCRYPT_BLOCK);
				}
				else {
					cache = decipher.doFinal(encryptedFile, offset, leng- offset);
				}
				//byteArrayOutputStream.write(cache, 0, cache.length);
				byteArrayOutputStream.write(cache);
				offset+= MAX_ENCRYPT_BLOCK;
			}
			byte[] decryptBytes = byteArrayOutputStream.toByteArray();
			byteArrayOutputStream.close();
			// save to new file
			FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\res.jpg");
			fileOutputStream.write(decryptBytes, 0 , decryptBytes.length);
			fileOutputStream.close();
			System.out.println("decryption finish and saved");*/




			// close all connections
			/*stringIn.close();
			printWriter.close();
			toClient.close();
			fromClient.close();
			connectionSocket.close();*/


			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				//System.out.println(packetType);

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					fromClient.read(msg);
					System.out.println(new String(msg));

					printWriter.println("name received");
					printWriter.flush();

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {


					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					//System.out.println(numBytes);
					readByte(block,fromClient);
					//System.out.println(numBytes);

					byte[] cache = decryptFile(block, decipher);

					byteArrayOutputStream.write(cache);


				} else if (packetType == 2) {
					byte[] decryptBytes = byteArrayOutputStream.toByteArray();

					fileOutputStream = new FileOutputStream("C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\res.jpg");
					fileOutputStream.write(decryptBytes, 0 , decryptBytes.length);
					byteArrayOutputStream.close();
					// save to new file

					fileOutputStream.close();
					System.out.println("decryption finish and saved");

					System.out.println("Closing connection...");

					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}

			printWriter.println("FINISH!!");
			printWriter.flush();

		} catch (Exception e) {e.printStackTrace();}


	}

	public static PrivateKey getPrivateKey() throws Exception{
		File f = new File(privateKeyPath);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(keySpec);
	}

	private static void readByte(byte[] byteArray, InputStream byteIn) throws Exception{
		int offset = 0;
		int numRead;

		while (offset < byteArray.length && (numRead = byteIn.read(byteArray, offset, byteArray.length - offset)) >= 0){
			offset += numRead;
		}
		if (offset < byteArray.length) {
			System.out.println("File reception incomplete!");
		}
	}

	private static byte[] decryptFile(byte[] encryptedFile, Cipher decipher) throws Exception {
		//ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		int leng = encryptedFile.length;
		int MAX_ENCRYPT_BLOCK= 128;
		int offset = 0;
		//byte[] cache;
		while(leng- offset > 0 ) {
			byte[] cache;
			if(leng - offset>= MAX_ENCRYPT_BLOCK) {
				cache = decipher.doFinal(encryptedFile, offset, MAX_ENCRYPT_BLOCK);
			}
			else {
				cache = decipher.doFinal(encryptedFile, offset, leng- offset);
				System.out.println("get cache");
			}

			return cache;
		}
		//byte[] decryptBytes = byteArrayOutputStream.toByteArray();
		//byteArrayOutputStream.close();
		// save to new file
		//FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\res.jpg");
		//fileOutputStream.write(decryptBytes, 0 , decryptBytes.length);
		//fileOutputStream.close();
		//System.out.println("decryption finish and saved");
		 return null;
	}


}



