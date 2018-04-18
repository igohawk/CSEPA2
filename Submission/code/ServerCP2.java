package ProAssign;
/**
 * Authors : Zeng Yueran (1002207), Li Xueqing(1002182)
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.Context;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
public class ServerCP2 {

    private static String signedCertPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\server.crt";
    private static String privateKeyPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\privateServer.der";

    public static void main(String[] args) {
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        OutputStream toClient = null;
        InputStream fromClient = null;

        try{
            //******************** PART 1. AUTHENTICATION PROTOCOL **************************

            /**
             * STEP 0. initialization of socket
             */
            System.out.println("Waiting for connection");
            welcomeSocket = new ServerSocket(8080);
            connectionSocket = welcomeSocket.accept();
            System.out.println("Connection established");

            fromClient = connectionSocket.getInputStream();
            toClient = connectionSocket.getOutputStream();

            PrintWriter stringOut = new PrintWriter(connectionSocket.getOutputStream(), true);
            BufferedReader stringIn = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            // wait for client's response
            System.out.println(stringIn.readLine());

            // send hello message to client
            stringOut.println("Hello, this is SecStore!");
            stringOut.flush();
            /**
             * STEP 1. receive and encrypt nonce, send back to client
             */
            String nonceLength = stringIn.readLine();
            byte[] nonce = new byte[Integer.parseInt(nonceLength)];
            readByte(nonce,fromClient);
            System.out.println("RECEIVED FROM CLIENT: nonce");

            // get private key
            PrivateKey privateKey = getPrivateKey();

            // Create a Cipher by specifying the following parameters
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            // Initialize the Cipher for Encryption
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // encrypt nonce
            byte[] encryptedNonce = cipher.doFinal(nonce);
            stringOut.println(Integer.toString(encryptedNonce.length));
            // send encrypted nonce to client
            toClient.write(encryptedNonce, 0, encryptedNonce.length);
            toClient.flush();
            System.out.println(nonce);
            System.out.println("SENT TO CLIENT: encrypted nonce");
            /**
             * STEP 2. send signed certificate
             */
            // wait for client's response
            System.out.println(stringIn.readLine());
            // get signed certificate
            File certFile = new File(signedCertPath);
            byte[] certByte = new byte[(int) certFile.length()];
            FileInputStream fis = new FileInputStream(certFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            bis.read(certByte, 0, certByte.length);

            // get length
            stringOut.println(certByte.length);
            // wait for client's response
            System.out.println(stringIn.readLine());

            // send signed certificate to client
            toClient.write(certByte,0,certByte.length);
            toClient.flush();
            System.out.println("SENT TO CLIENT: cert");

            // if check fail, close connection
            String fromc = stringIn.readLine();
            System.out.println(fromc);
            if(fromc.equals("Bye")) {
                stringIn.close();
                stringOut.close();
                toClient.close();
                fromClient.close();
                connectionSocket.close();
            }

            stringOut.println("Successful handshake");
            stringOut.flush();

            //**************************** END OF PART 1 ************************************


            //******************** PART 2. CONFIDENTIALITY PROTOCOL *************************

            // if success, begin file transfer
            System.out.println("*** start to transfer file ***");

            // begin to receive encrypted AES session key
            System.out.println("begin to receive AES session key");
            String aesSessionKeyLength = stringIn.readLine();

            stringOut.println("Server begin to receive encrypted session key");
            stringOut.flush();
            // read encrypted AES session key from client
            byte[] aesSessionKey = new byte[Integer.parseInt(aesSessionKeyLength)];
            readByte(aesSessionKey, fromClient);

            System.out.println("RECEIVED FROM SERVER: AES encrypted session key");

            // receive encrypted file from client
            String fileName = stringIn.readLine();
            // receive length
            String encryptedFileLength  = stringIn.readLine();
            stringOut.println("Server begin to receive file");
            stringOut.flush();
            byte[] byteFile = new byte[Integer.parseInt(encryptedFileLength)];
            readByte(byteFile, fromClient);
            System.out.println("RECEIVE FROM CLIENT: file");

            // decrypt encrypted AES session key
            Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] byteDecryptedaesKey = decipher.doFinal(aesSessionKey);
            System.out.println("AES session key decryption finished");

            // generate AES key
            SecretKey aesKey = new SecretKeySpec(byteDecryptedaesKey, 0, byteDecryptedaesKey.length, "AES");
            System.out.println("AES key generated");

            // decrypt file
            // Create a Cipher by specifying the following parameters
            Cipher decipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
            // Initialize the Cipher for Decryption
            decipher2.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] byteOupFile = decipher2.doFinal(byteFile);

            // save file to the following path
            FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\mo.txt");
            fileOutputStream.write(byteOupFile, 0 , byteOupFile.length);
            fileOutputStream.close();

            System.out.println("decryption finish and saved");

            stringOut.println("FINISH!!");
            stringOut.flush();

            // close all connections
            stringIn.close();
            stringOut.close();
            toClient.close();
            fromClient.close();
            connectionSocket.close();

        }catch (Exception e) {}
    }

    // generate private key from private key path
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

    // read from cient
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