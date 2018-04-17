package com.example.lib;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.BASE64Encoder;

/**
 * Created by Li Xueqing on 11/4/2018.
 */

public class ClientCP2 {
    private static final String SERVER_NAME = "10.12.232.220";
    //private static final String SERVER_NAME = "localhost";
    private static final int SERVER_PORT = 8080;
    private static final String FileName = "fileupload/largeJpg.jpeg";
    private static final String CACert = "CA.crt";

    public static void main(String[] args) {

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        try {

            //******************** PART 1. AUTHENTICATION PROTOCOL **************************

            /**
             * STEP 0. initialization of socket
             */

            // Connect to server and get the input and output streams
            Socket clientSocket = new Socket(SERVER_NAME, SERVER_PORT);
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            InputStream byteIn = clientSocket.getInputStream();
            OutputStream byteOut = clientSocket.getOutputStream();
            //DataOutputStream toServer = new DataOutputStream(clientSocket.getOutputStream());
            //DataInputStream fromServer = new DataInputStream(clientSocket.getInputStream());


            /**
             * STEP 1. send/receive nonce
             */

            // send a welcome message to request server's identity
            out.println("***FROM CLIENT***  Please prove your identity");
            out.flush();
            System.out.println("Sent to server: Please state your name");

            // wait for server's response
            String identityResponse = in.readLine();
            System.out.println(identityResponse);

            // generate a one-time nonce
            byte[] nonce = generateNonce();

            // send the nonce to server
            System.out.println("nonce: " + nonce);

            //TODO: explore whether the format of nonce could be BigInteger
            if (identityResponse.contains("this is SecStore")) {
                out.println(Integer.toString(nonce.length));
                byteOut.write(nonce);
                byteOut.flush();
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
            out.println("***FROM CLIENT***  Please provide your certificate signed by CA");
            out.flush();
            System.out.println("Sent to server: Please provide your certificate signed by CA");

            // receive signed certificate from server

            //String serverCert = in.readLine();
            //byte[] serverCertByteArray = serverCert.getBytes();
            //System.out.println("Received certificate from server");


            out.println("***FROM CLIENT***  Ready to get certificate");
            out.flush();
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
                out.println("***FORM CLIENT***  Ready to send file");
                out.flush();
            } else {
                System.out.println("Identity verification failed");
                System.out.println("Closing connection...");
                out.println("***FROM CLIENT***  Bye!");
                closeConnections(byteOut,byteIn,out,in,clientSocket);
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
            out.println(encryptedSecretKeyBytes.length);
            out.flush();
            System.out.println(in.readLine());
            byteOut.write(encryptedSecretKeyBytes, 0, encryptedSecretKeyBytes.length);


            /**
             * STEP 2. send encrypted file to server
             */

            // encrypt file using AES secret key
            byte[] encryptedFileBytes = encryptFile(FileName, secretKey);

            // send encrypted file to server
            out.println(FileName);
            out.println(encryptedFileBytes.length);
            out.flush();
            System.out.println(in.readLine());
            byteOut.write(encryptedFileBytes,0,encryptedFileBytes.length);
            byteOut.flush();
            System.out.println("Finish sending Encrypted file");


            /**
             * STEP 3. post-handling
             */

            System.out.println(in.readLine());

            // end of timing
            long endTime = System.nanoTime();
            System.out.println("The uploading time is "+(endTime-startTime)+" ns");

            closeConnections(byteOut,byteIn,out,in,clientSocket);


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

    private static void closeConnections(
            OutputStream byteOut, InputStream byteIn, PrintWriter out,BufferedReader in, Socket clientSocket
    )throws IOException {
        byteIn.close();
        byteOut.close();
        in.close();
        out.close();
        clientSocket.close();
    }
}
