package com.example.lib;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by Li Xueqing on 11/4/2018.
 */

public class ClientCP2_m {
    private static final String SERVER_NAME = "10.12.232.220";
    //private static final String SERVER_NAME = "localhost";
    private static final int SERVER_PORT = 8080;
    private static final String FileName = "fileupload/smallText.txt";
    private static final String CACert = "CA.crt";

    public static void main(String[] args) {


        try {

            //******************** PART 1. AUTHENTICATION PROTOCOL **************************

            /**
             * STEP 0. initialization of socket
             */

            // Connect to server and get the input and output streams
            Socket clientSocket = new Socket(SERVER_NAME, SERVER_PORT);

            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            InputStream byteIn = clientSocket.getInputStream();

            DataOutputStream toServer = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream fromServer = new DataInputStream(clientSocket.getInputStream());

            /**
             * STEP 1. send/receive nonce
             */

            // send a welcome message to request server's identity
            toServer.write("***FROM CLIENT***  Please prove your identity".getBytes());
            toServer.flush();
            System.out.println("Sent to server: Please state your name");

            // wait for server's response
            String identityResponse = in.readLine();
            System.out.println(identityResponse);

            // generate a one-time nonce
            byte[] nonce = generateNonce();

            // send the nonce to server
            System.out.println("nonce: " + nonce);

            if (identityResponse.contains("this is SecStore")) {
                toServer.writeInt(nonce.length);
                toServer.write(nonce);
                toServer.flush();
                System.out.println("Sent to server a fresh nonce");
            }

            // wait for the encrypted nonce sent back by server
            String encryptedNonceLength = in.readLine();
            byte[] encryptedNonce = new byte[Integer.parseInt(encryptedNonceLength)];
            readByte(encryptedNonce,byteIn);
            System.out.println("Received encrypted nonce from server");


            /*
             * STEP 2. verification for server's certificate
             */

            // request signed certificate from server
            toServer.write("***FROM CLIENT***  Please provide your certificate signed by CA".getBytes());
            toServer.flush();
            System.out.println("Sent to server: Please provide your certificate signed by CA");

            // receive signed certificate from server
            toServer.write("***FROM CLIENT***  Ready to get certificate".getBytes());
            toServer.flush();
            String serverCertByteArrayLength = in.readLine();
            int length = Integer.valueOf(serverCertByteArrayLength);
            byte[] serverCertByteArray = new byte[length];
            readByte(serverCertByteArray,byteIn);
            System.out.println("Received certificate from server");


            // extract public key from CA certificate
            InputStream CACertInputStream = new FileInputStream(CACert);
            //PublicKey CAPublicKey = pubKeyExtraction(CACertInputStream);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(CACertInputStream);
            PublicKey CAPublicKey = caCert.getPublicKey();
            System.out.println("CA public key extracted");

            // verify signed certificate from server using CA public key
            System.out.println("Verifying certification sent from server");
            InputStream serverCertInputStream = new ByteArrayInputStream(serverCertByteArray);
            //signedCertVerification(serverCertInputStream, CAPublicKey);
            X509Certificate signedCertificate = (X509Certificate) certificateFactory.generateCertificate(serverCertInputStream);

            signedCertificate.checkValidity();
            signedCertificate.verify(CAPublicKey);
            System.out.println("Signed certificate validity checked and verified");

            // extract public key from signed certificate
            //PublicKey serverPublicKey = pubKeyExtraction(serverCertInputStream);
            PublicKey serverPublicKey = signedCertificate.getPublicKey();


            /*
             * STEP 3.decryption of nonce, finish verification
             * end of AP
             */

            // decryption of nonce
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            byte[] decryptedNonce = dcipher.doFinal(encryptedNonce);

            // check identity
            if (Arrays.equals(nonce, decryptedNonce)) {
                System.out.println("Server's indentity verified");
                System.out.println("Ready to send file to server");
                toServer.write("***FORM CLIENT***  Ready to send file".getBytes());
                toServer.flush();
            } else {
                System.out.println("Identity verification failed");
                System.out.println("Closing connection...");
                toServer.write("***FROM CLIENT***  Bye!".getBytes());
                closeConnections(toServer, fromServer, clientSocket);
            }

            System.out.println(in.readLine());


            //**************************** END OF PART 1 ************************************



            //******************** PART 2. CONFIDENTIALITY PROTOCOL *************************

            // initialization for timing
            System.out.println("Starting file transfering...");
            long startTime = System.nanoTime();


            /**
             * STEP 1. generate AES secret key for file encryption/decryption
             */

            // create cipher object and initialize it using public key
            Cipher rsaEcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaEcipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            // Generate an AES key using KeyGenerator Initialize the keysize to 128 bits
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();

            // encrypt AES secret key
            byte[] secretKeyBytes = secretKey.getEncoded();
            byte[] encryptedSecretKeyBytes = rsaEcipher.doFinal(secretKeyBytes);

            // send encrypted AES secret key to server
            toServer.writeInt(encryptedSecretKeyBytes.length);
            System.out.println(in.readLine());
            toServer.write(encryptedSecretKeyBytes);
            toServer.flush();


            /**
             * STEP 2. send encrypted file to server
             */

            // encrypt file using AES secret key
            byte[] encryptedFileBytes = encryptFile(FileName, secretKey);

            // send encrypted file to server
            toServer.write(FileName.getBytes());
            toServer.writeInt(encryptedFileBytes.length);
            System.out.println(in.readLine());
            toServer.write(encryptedFileBytes);
            toServer.flush();
            System.out.println("Finish sending Encrypted file");


            /**
             * STEP 3. post-handling
             */

            System.out.println(in.readLine());

            // end of timing
            long endTime = System.nanoTime();
            System.out.println("The uploading time is "+(endTime-startTime)+" ns");

            closeConnections(toServer, fromServer, clientSocket);


        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private static byte[] encryptFile(String fileName, SecretKey secretKey){

        try {
            // Create a Cipher by specifying the following parameters
            Cipher ecipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");

            // Initialize the Cipher for Encryption
            ecipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // read the file
            File file = new File(fileName);
            byte [] fileBytes = new byte[(int) file.length()];
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
            bufferedInputStream.read(fileBytes, 0, fileBytes.length);

            // encrypt the file bytes with the AES secret key
            byte[] byteCipherText = ecipher.doFinal(fileBytes);
            return byteCipherText;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    private static byte[] generateNonce() throws NoSuchAlgorithmException {
//        SecureRandom secureRandom = new SecureRandom();
//        BigInteger nonce = new BigInteger(20, secureRandom);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] nonce = new byte[64];
        secureRandom.nextBytes(nonce);

        return nonce;
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

    private static void closeConnections
            (DataOutputStream toServer, DataInputStream fromServer, Socket clientSocket)throws IOException {
        toServer.close();
        fromServer.close();
        clientSocket.close();
    }
}
