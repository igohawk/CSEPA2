package com.example.lib;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

/**
 * Created by Li Xueqing on 11/4/2018.
 */

public class ServerCP1 {
    private static final int NTHREADS = 5;
    private static ExecutorService executorService = Executors.newFixedThreadPool(NTHREADS);
    private static ServerSocket serverSocket;
    private static final int PORT_NUMBER = 8080;
    private static final String privateKeyFile = "privateServer.der";
    private static final String signedCertificateFile = "server.crt";

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
//        String nonceString = stringIn.readLine();
//        BigInteger nonce = new BigInteger(nonceString);
        System.out.println("Received fresh nonce from client");
        System.out.println(nonce);

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
}
