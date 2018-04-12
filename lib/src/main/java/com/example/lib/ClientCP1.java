package com.example.lib;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * Created by Li Xueqing on 11/4/2018.
 */

public class ClientCP1 {
    private static final String SERVER_NAME = "10.12.232.220";
    //private static final String SERVER_NAME = "localhost";
    private static final int SERVER_PORT = 8080;
    private static final String FileName = "rr.txt";
    private static final String CACert = "CA.crt";

    public static void main(String[] args) {

        int numBytes = 0;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        try {

            /*
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

            /*
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



            /*
             * STEP 4. file encryption and transfer
             */

            // initialization for timing
            System.out.println("Starting file transfering...");
            long timeStarted = System.nanoTime();

            // create cipher object for encryption using public key
            Cipher ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // file encryption
            byte[] encryptedFile = encryptFile(FileName, ecipher);


        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private static byte[] encryptFile(String fileName, Cipher ecipher) {
        return null;
    }

    private static void closeConnections(
            OutputStream byteOut, InputStream byteIn, PrintWriter out, BufferedReader in, Socket clientSocket)
            throws IOException {
        byteIn.close();
        byteOut.close();
        in.close();
        out.close();
        clientSocket.close();
    }

    private static byte[] generateNonce() throws NoSuchAlgorithmException {
//        SecureRandom secureRandom = new SecureRandom();
//        BigInteger nonce = new BigInteger(20, secureRandom);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] nonce = new byte[64];
        secureRandom.nextBytes(nonce);

        return nonce;
    }

    private static PublicKey pubKeyExtraction(InputStream certInputStream) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
        return cert.getPublicKey();
    }

    private static void signedCertVerification(InputStream certInputStream, PublicKey publicKey) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate signedCert = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
            signedCert.checkValidity();
            signedCert.verify(publicKey);
            System.out.println("Yes! Signed certificate verified");
        } catch (Exception e) {
            e.printStackTrace();
        }
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
