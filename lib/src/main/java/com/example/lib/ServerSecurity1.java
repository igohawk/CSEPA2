/*
package ProAssign;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;

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

public class ServerWithoutSecurity {

	private static String signedCertPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\server.crt";
	private static String privateKeyPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\privateServer.der";

	public static void main(String[] args) {

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		OutputStream toClient = null;
		InputStream fromClient = null;

		//FileOutputStream fileOutputStream = null;
		//BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(8080);
			connectionSocket = welcomeSocket.accept();
			System.out.println("Connection established");

			fromClient = connectionSocket.getInputStream();
			toClient = connectionSocket.getOutputStream();

			PrintWriter printWriter = new PrintWriter(connectionSocket.getOutputStream(), true);
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

			System.out.println(bufferedReader.readLine());

			printWriter.println("Hello, this is SecStore!");
			printWriter.flush();

			// get private key
			PrivateKey privateKey = getPrivateKey();

			//String nonce = stringIn.readLine();
			// retrieve nonce from client
			String nonceLength = bufferedReader.readLine();
			byte[] nonce = new byte[Integer.parseInt(nonceLength)];
			readByte(nonce,fromClient);
			System.out.println("RECEIVED FROM CLIENT: nonce");

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] encryptedNonce = cipher.doFinal(nonce);

			toClient.write(encryptedNonce, 0, encryptedNonce.length);
			toClient.flush();
			System.out.println(nonce);
			System.out.println("SENT TO CLIENT: encrypted nonce");

			// send signed cert
			System.out.println(bufferedReader.readLine());
			File certFile = new File(signedCertPath);
			byte[] certByte = new byte[(int) certFile.length()];
			FileInputStream fis = new FileInputStream(certFile);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(certByte, 0, certByte.length);

			printWriter.println(certByte.length);
			System.out.println(bufferedReader.readLine());
			toClient.write(certByte,0,certByte.length);
			toClient.flush();
			System.out.println("SENT TO CLIENT: cert");

			// if check fail, close connection
			String fromc = bufferedReader.readLine();
			System.out.println(fromc);
			if(fromc.equals("Bye")) {
				bufferedReader.close();
				printWriter.close();
				toClient.close();
				fromClient.close();
				connectionSocket.close();
			}

			printWriter.println("Successful handshake");
			printWriter.flush();





			// if success, begin file transfer
			*/
/*System.out.println("*** start to transfer file ***");
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, privateKey);

			String fileName = bufferedReader.readLine();
			String encryptedFileLength  = bufferedReader.readLine();
			printWriter.println("Server begin to receive file");
			printWriter.flush();

			byte[] encryptedFile = new byte[Integer.parseInt(encryptedFileLength)];
			readByte(encryptedFile,fromClient);
			System.out.println("RECEIVED FROM CLIENT: file");

			// decrypt file
			byte[] decryptBytes = decipher.doFinal(encryptedFile);
			FileOutputStream fileOutputStream = new FileOutputStream("result");
			fileOutputStream.write(decryptBytes, 0 , decryptBytes.length);
			System.out.println("decryption finish and saved");

			printWriter.println("FINISH!!");
			printWriter.flush();

			// close all connections
			bufferedReader.close();
			printWriter.close();
			toClient.close();
			fromClient.close();
			connectionSocket.close();*//*


			*/
/*
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					fromClient.read(filename);

					fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.read(block);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

				} else if (packetType == 2) {

					System.out.println("Closing connection...");

					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}*//*

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

}
*/
package com.example.lib;

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

public class ServerSecurity1 {

	private static String signedCertPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\server.crt";
	private static String privateKeyPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\privateServer.der";

	public static void main(String[] args) {

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		OutputStream toClient = null;
		InputStream fromClient = null;

		//FileOutputStream fileOutputStream = null;
		//BufferedOutputStream bufferedFileOutputStream = null;

		try {
			System.out.println("Waiting for connection");
			welcomeSocket = new ServerSocket(8080);
			connectionSocket = welcomeSocket.accept();
			System.out.println("Connection established");

			fromClient = connectionSocket.getInputStream();
			toClient = connectionSocket.getOutputStream();

			PrintWriter printWriter = new PrintWriter(connectionSocket.getOutputStream(), true);
			BufferedReader stringIn = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

			System.out.println(stringIn.readLine());

			printWriter.println("Hello, this is SecStore!");
			printWriter.flush();

			//String nonce = stringIn.readLine();
			// retrieve nonce from client
			String nonceLength = stringIn.readLine();
			byte[] nonce = new byte[Integer.parseInt(nonceLength)];
			readByte(nonce,fromClient);
			System.out.println("RECEIVED FROM CLIENT: nonce");

			// get private key
			PrivateKey privateKey = getPrivateKey();

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);


			//byte[] encryptedNonce = rsaCipherEncrypt.doFinal(nonce.getBytes());
			byte[] encryptedNonce = cipher.doFinal(nonce);
			printWriter.println(Integer.toString(encryptedNonce.length));
			toClient.write(encryptedNonce, 0, encryptedNonce.length);
			toClient.flush();
			System.out.println(nonce);
			System.out.println("SENT TO CLIENT: encrypted nonce");


			// send signed cert
			System.out.println(stringIn.readLine());
			File certFile = new File(signedCertPath);
			byte[] certByte = new byte[(int) certFile.length()];
			FileInputStream fis = new FileInputStream(certFile);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(certByte, 0, certByte.length);

			printWriter.println(certByte.length);
			System.out.println(stringIn.readLine());
			toClient.write(certByte,0,certByte.length);
			toClient.flush();
			System.out.println("SENT TO CLIENT: cert");

			// if check fail, close connection
			String fromc = stringIn.readLine();
			System.out.println(fromc);
			if(fromc.equals("Bye")) {
				stringIn.close();
				printWriter.close();
				toClient.close();
				fromClient.close();
				connectionSocket.close();
			}

			printWriter.println("Successful handshake");
			printWriter.flush();

			// if success, begin file transfer
			System.out.println("*** start to transfer file ***");
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, privateKey);

			String fileName = stringIn.readLine();
			String encryptedFileLength  = stringIn.readLine();
			printWriter.println("Server begin to receive file");
			printWriter.flush();

			byte[] encryptedFile = new byte[Integer.parseInt(encryptedFileLength)];
			readByte(encryptedFile,fromClient);
			System.out.println("RECEIVED FROM CLIENT: file");

			// decrypt file
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			int leng = encryptedFile.length;
			int MAX_ENCRYPT_BLOCK= 117;
			int offset = 0;
			byte[] cache;
			while(leng- offset > 0 ) {
				if(leng - offset> MAX_ENCRYPT_BLOCK) {
					cache = decipher.doFinal(encryptedFile, offset, MAX_ENCRYPT_BLOCK);
				}
				else {
					cache = decipher.doFinal(encryptedFile, offset, leng- offset);
				}
				byteArrayOutputStream.write(cache, 0, cache.length);
				offset+= MAX_ENCRYPT_BLOCK;
			}
			byte[] decryptBytes = decipher.doFinal(encryptedFile);
			byteArrayOutputStream.close();
			FileOutputStream fileOutputStream = new FileOutputStream("result");
			fileOutputStream.write(decryptBytes, 0 , decryptBytes.length);
			System.out.println("decryption finish and saved");


			printWriter.println("FINISH!!");
			printWriter.flush();

			// close all connections
			stringIn.close();
			printWriter.close();
			toClient.close();
			fromClient.close();
			connectionSocket.close();


			/*
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					fromClient.read(filename);

					fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.read(block);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

				} else if (packetType == 2) {

					System.out.println("Closing connection...");

					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}*/
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

}



