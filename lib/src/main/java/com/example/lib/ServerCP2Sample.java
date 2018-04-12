package com.example.lib;

/**
 * Created by Li Xueqing on 12/4/2018.
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServerCP2Sample {
    private static final int NTHREADS = 5;
    private static ExecutorService executorService = Executors.newFixedThreadPool(NTHREADS);
    private static ServerSocket serverSocket;
    private static final int PORT_NUMBER = 1234;
    private static final String privateKeyFile = "C:\\privateServer.der";
    private static final String signedCertificateFile = "C:\\Signed Certificate - 1001294.crt";

    public static void main(String[] args) {
        try {
            // create TCP ServerSocket to listen
            serverSocket = new ServerSocket(PORT_NUMBER);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // constantly listening for clients who want to connect
        while (true) {
            try {
                // then create TCP ClientSocket upon accepting incoming TCP request
                System.out.println("... expecting connection ...");
                final Socket clientSocket = serverSocket.accept();
                System.out.println("... connection established...");

                // create threads to handle multiple client uploads
                Runnable task = new Runnable() {
                    @Override
                    public void run() {
                        try {
                            handleClient(clientSocket);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                };
                executorService.execute(task);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void handleClient(Socket clientSocket) throws Exception {
        // channels for sending and receiving bytes
        OutputStream byteOut = clientSocket.getOutputStream();
        InputStream byteIn = clientSocket.getInputStream();

        // channels for sending and receiving plain text
        PrintWriter stringOut = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader stringIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        // wait for client to initiate conversation
        System.out.println(stringIn.readLine());

        // reply to client
        stringOut.println("SERVER>> Hello, this is SecStore!");
        stringOut.flush();
        System.out.println("Sent to client: Hello, this is SecStore!");

        // retrieve nonce from client
        String nonceLength = stringIn.readLine();
        byte[] nonce = new byte[Integer.parseInt(nonceLength)];
        readByte(nonce,byteIn);
        System.out.println("Received fresh nonce from client");

        // load private key from .der
        PrivateKey privateKey = loadPrivateKey();

        // Create cipher object and initialize is as encrypt mode, use PRIVATE key.
        Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, privateKey);

        // encrypt nonce
        byte[] encryptedNonce = rsaCipherEncrypt.doFinal(nonce);
        stringOut.println(Integer.toString(encryptedNonce.length));
        byteOut.write(encryptedNonce, 0, encryptedNonce.length);
        byteOut.flush();
        System.out.println("Sent to client encrypted nonce");

        // wait for client response
        System.out.println(stringIn.readLine());

        // send signed certificate
        File certificateFile = new File(signedCertificateFile);
        byte[] certByteArray = new byte[(int) certificateFile.length()];
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(certificateFile));
        bis.read(certByteArray, 0, certByteArray.length);

        stringOut.println(Integer.toString(certByteArray.length));
        System.out.println(stringIn.readLine());
        byteOut.write(certByteArray, 0, certByteArray.length);
        byteOut.flush();
        System.out.println("Sent to client certificate");

        // receive messages from client
        String clientResult = stringIn.readLine();
        System.out.println(clientResult);
        if (clientResult.contains("Bye!")) {
            closeConnections(byteOut, byteIn, stringOut, stringIn, clientSocket);
        }


        // **************** END OF AP ***************


        // start file transfer
        System.out.println("INITIALIZING FILE TRANSFER");

        // download and decrypt file - CP2
        downloadAndDecryptFileCP2(stringOut, stringIn, byteIn, privateKey);

        // send confirmation of successful upload to client
        stringOut.println("SERVER>> Upload file successful!");
        stringOut.flush();

        closeConnections(byteOut, byteIn, stringOut, stringIn, clientSocket);
    }

    private static PrivateKey loadPrivateKey() throws Exception {
        Path privateKeyPath = Paths.get(privateKeyFile);
        byte[] privateKeyByteArray = Files.readAllBytes(privateKeyPath);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }

    private static void closeConnections(OutputStream byteOut, InputStream byteIn, PrintWriter stringOut, BufferedReader stringIn, Socket socket) throws IOException {
        byteOut.close();
        byteIn.close();
        stringOut.close();
        stringIn.close();
        socket.close();
    }

    private static void readByte(byte[] byteArray, InputStream byteIn) throws Exception{
        int offset = 0;
        int numRead = 0;
        while (offset < byteArray.length && (numRead = byteIn.read(byteArray, offset, byteArray.length - offset)) >= 0){
            offset += numRead;
        }
        if (offset < byteArray.length) {
            System.out.println("File reception incomplete!");
        }
    }

    public static void downloadAndDecryptFileCP2(PrintWriter stringOut, BufferedReader stringIn, InputStream byteIn, PrivateKey privateKey) throws Exception{

        // get encrypted AES session key from client
        String encryptedAESKeyBytesLength = stringIn.readLine();
        stringOut.println("SERVER>> Ready to receive encrypted session key");
        stringOut.flush();
        byte[] encryptedAESKeyBytes = new byte[Integer.parseInt(encryptedAESKeyBytesLength)];
        readByte(encryptedAESKeyBytes,byteIn);
        System.out.println("Received encrypted session key from client");


        // get encrypted file from client
        String fileName = stringIn.readLine();
        String encryptedFileBytesLength = stringIn.readLine();
        stringOut.println("SERVER>> Ready to receive encrypted file");
        stringOut.flush();
        byte[] encryptedFileBytes = new byte[Integer.parseInt(encryptedFileBytesLength)];
        readByte(encryptedFileBytes,byteIn);
        System.out.println("Received encrypted file from client");


        // create cipher object for decryption of AES key
        Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, privateKey);

        // decrypt the encrypted AES to get AES key bytes
        byte[] aesKeyBytes = rsaCipherDecrypt.doFinal(encryptedAESKeyBytes);

        // recreate AES key from the byte array
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
        System.out.println("Acquired AES Key");

        // create cipher object for decryption of file
        Cipher aesDeCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesDeCipher.init(Cipher.DECRYPT_MODE, aesKey);

        // decrypt the AES encrypted file
        byte[] fileBytes = aesDeCipher.doFinal(encryptedFileBytes);
        System.out.println("File decrypted");

        // create new file and write to file
        FileOutputStream fileOut = new FileOutputStream(fileName);
        fileOut.write(fileBytes, 0, fileBytes.length);
        System.out.println("File registered into system.");

    }
}
