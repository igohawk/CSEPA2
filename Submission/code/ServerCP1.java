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

public class ServerCP1 {

    private static String signedCertPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\server.crt";
    private static String privateKeyPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\privateServer.der";

    public static void main(String[] args) {

        //******************** PART 1. AUTHENTICATION PROTOCOL **************************

        /**
         * STEP 0. initialization of socket
         */
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        // initialize a byte array for reading message sent by client
        byte[] msg = new byte[128];

        try {
            // wait for connection
            System.out.println("Waiting for connection");
            welcomeSocket = new ServerSocket(8080);
            // establish connection with client
            connectionSocket = welcomeSocket.accept();
            System.out.println("Connection established");

            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            PrintWriter printWriter = new PrintWriter(connectionSocket.getOutputStream(), true);

            // wait for client's response
            fromClient.read(msg);
            System.out.println(new String(msg));
            // send hello text to client
            printWriter.println("Hello, this is SecStore!");
            printWriter.flush();

            /**
            * STEP 1. receive and encrypt nonce, send back to client
            */
            // receive nonce from client
            byte[] nonce = new byte[fromClient.readInt()];
            readByte(nonce,fromClient);
            System.out.println("RECEIVED FROM CLIENT: nonce");

            // get private key
            PrivateKey privateKey = getPrivateKey();
            // Create a Cipher by specifying the following parameters
            Cipher cipher = Cipher.getInstance("RSA");
            // Initialize the Cipher for Encryption
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // encrypt and transfer nonce
            byte[] encryptedNonce = cipher.doFinal(nonce);
            printWriter.println(Integer.toString(encryptedNonce.length));
            toClient.write(encryptedNonce, 0, encryptedNonce.length);
            toClient.flush();
            System.out.println(nonce);
            System.out.println("SENT TO CLIENT: encrypted nonce");

            /**
             * STEP 2. send signed certificate
             */
            // wait for client's response
            fromClient.read(msg);
            System.out.println(new String(msg));

            // get signed certificate
            File certFile = new File(signedCertPath);
            byte[] certByte = new byte[(int) certFile.length()];
            FileInputStream fis = new FileInputStream(certFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            bis.read(certByte, 0, certByte.length);
            printWriter.println(certByte.length);

            // wait for client's response
            fromClient.read(msg);
            System.out.println(new String(msg));

            // send signed certificate to client
            toClient.write(certByte,0,certByte.length);
            toClient.flush();
            System.out.println("SENT TO CLIENT: cert");

            // if check fail, close connection
            fromClient.read(msg);
            String fromc = new String(msg);
            System.out.println(fromc);
            if(fromc.equals("Bye")) {
                printWriter.close();
                toClient.close();
                fromClient.close();
                connectionSocket.close();
            }

            printWriter.println("Successful handshake");
            printWriter.flush();

            //**************************** END OF PART 1 ************************************


            //******************** PART 2. CONFIDENTIALITY PROTOCOL *************************
            // if success, begin file transfer
            System.out.println("*** start to transfer file ***");
            // Create a Cipher by specifying the following parameters
            Cipher decipher = Cipher.getInstance("RSA");
            // Initialize the Cipher for Decryption
            decipher.init(Cipher.DECRYPT_MODE, privateKey);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // while the connection is still on
            while (!connectionSocket.isClosed()) {

                // read packet type from client
                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {
                    // receive file name
                    System.out.println("Receiving file...");

                    fromClient.read(msg);
                    System.out.println(new String(msg));

                    printWriter.println("name received");
                    printWriter.flush();

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    // read each block from client
                    int numBytes = fromClient.readInt();
                    byte [] block = new byte[numBytes];
                    readByte(block,fromClient);
                    // decrypt file
                    byte[] cache = decryptFile(block, decipher);
                    // write to cache
                    byteArrayOutputStream.write(cache);

                    // If finish transfer
                } else if (packetType == 2) {
                    byte[] decryptBytes = byteArrayOutputStream.toByteArray();
                    // save file to the following path
                    fileOutputStream = new FileOutputStream("C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\res.jpg");
                    fileOutputStream.write(decryptBytes, 0 , decryptBytes.length);
                    byteArrayOutputStream.close();

                    fileOutputStream.close();
                    System.out.println("decryption finish and saved");

                    System.out.println("Closing connection...");
                    // close connection
                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                }

            }

            printWriter.println("FINISH!!");
            printWriter.flush();

        } catch (Exception e) {e.printStackTrace();}


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
    // read from client
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
    // decrypt file
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
