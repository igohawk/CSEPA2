package ProAssign;

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
public class ServerSecurity2 {

    private static String signedCertPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\server.crt";
    private static String privateKeyPath = "C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\privateServer.der";

    public static void main(String[] args) {
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        OutputStream toClient = null;
        InputStream fromClient = null;

        //FileOutputStream fileOutputStream = null;
        //BufferedOutputStream bufferedFileOutputStream = null;

        try{
            System.out.println("Waiting for connection");
            welcomeSocket = new ServerSocket(8080);
            connectionSocket = welcomeSocket.accept();
            System.out.println("Connection established");

            fromClient = connectionSocket.getInputStream();
            toClient = connectionSocket.getOutputStream();

            PrintWriter stringOut = new PrintWriter(connectionSocket.getOutputStream(), true);
            BufferedReader stringIn = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

            System.out.println(stringIn.readLine());

            stringOut.println("Hello, this is SecStore!");
            stringOut.flush();

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
            stringOut.println(Integer.toString(encryptedNonce.length));
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

            stringOut.println(certByte.length);
            System.out.println(stringIn.readLine());
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

            // if success, begin file transfer
            System.out.println("*** start to transfer file ***");

            // receive encrypted AES session key
            System.out.println("begin to receive AES session key");
            String aesSessionKeyLength = stringIn.readLine();

            stringOut.println("SERVER>> Ready to receive encrypted session key");
            stringOut.flush();

            byte[] aesSessionKey = new byte[Integer.parseInt(aesSessionKeyLength)];
            readByte(aesSessionKey, fromClient);

            System.out.println("RECEIVED FROM SERVER: AES encrypted session key");
            //stringOut.println("Server receive session key");
            //stringOut.flush();

            // receive encrypted file from client
            String fileName = stringIn.readLine();
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
            Cipher decipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decipher2.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] byteOupFile = decipher2.doFinal(byteFile);
            FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\jessicasutd\\IdeaProjects\\Psets\\src\\ProAssign\\mo.jpg");
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
