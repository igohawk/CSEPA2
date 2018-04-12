package com.example.lib;

/**
 * Created by Li Xueqing on 12/4/2018.
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientCP2Sample {
    private static final String SERVER_NAME = "localhost";
    private static final int SERVER_PORT = 1234;
    private static final String uploadFilePath = "C:\\largeFile.txt";
    private static final String uploadFileName = "largeFile.txt";
    private static final String CACertFile = "C:\\CA.crt";

    public static void main(String[] args) {
        try {
            // create TCP socket for server at specified port
            Socket socket = new Socket(SERVER_NAME, SERVER_PORT);

            // channels for sending and receiving bytes
            OutputStream byteOut = socket.getOutputStream();
            InputStream byteIn = socket.getInputStream();

            // channels for sending and receiving plain text
            PrintWriter stringOut = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader stringIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // initiate conversation with server
            stringOut.println("CLIENT>> Hello SecStore, please prove your identity!");
            stringOut.flush();
            System.out.println("Sent to server: Hello SecStore, please prove your identity!");

            // wait for server to respond
            String firstResponse = stringIn.readLine();
            System.out.println(firstResponse);

            // send a nonce
            byte[] nonce = generateNonce();
            if (firstResponse.contains("this is SecStore")) {
                stringOut.println(Integer.toString(nonce.length));
                byteOut.write(nonce);
                byteOut.flush();
                System.out.println("Sent to server a fresh nonce");
            }

            // retrieve encrypted nonce from server
            String encryptedNonceLength = stringIn.readLine();
            byte[] encryptedNonce = new byte[Integer.parseInt(encryptedNonceLength)];
            readByte(encryptedNonce,byteIn);
            System.out.println("Received encrypted nonce from server");

            // ask for certificate
            stringOut.println("CLIENT>> Give me your certificate signed by CA");
            stringOut.flush();
            System.out.println("Sent to server: Give me your certificate signed by CA");

            // extract public key from CA certificate
            InputStream fis = new FileInputStream(CACertFile);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(fis);
            PublicKey caPublicKey = caCert.getPublicKey();
            System.out.println("CA public key extracted");

            // retrieve signed certificate from server
            String certByteArrayLength = stringIn.readLine();
            stringOut.println("CLIENT>> Ready to get certificate");
            stringOut.flush();
            byte[] certByteArray = new byte[Integer.parseInt(certByteArrayLength)];
            readByte(certByteArray,byteIn);
            System.out.println("Received certificate from server");

            // verifying signed certificate from server using CA public key
            System.out.println("Verifying certificate from server");
            InputStream certInputStream = new ByteArrayInputStream(certByteArray);
            X509Certificate signedCertificate = (X509Certificate) certificateFactory.generateCertificate(certInputStream);

            signedCertificate.checkValidity();
            signedCertificate.verify(caPublicKey);
            System.out.println("Signed certificate validity checked and verified");

            // extract public key from server's signed certificate
            PublicKey serverPublicKey = signedCertificate.getPublicKey();

            // create cipher object and initialize it as decrypt mode, using PUBLIC key.
            Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherDecrypt.init(Cipher.DECRYPT_MODE, serverPublicKey);

            // decrypt nonce
            byte[] decryptedNonce = cipherDecrypt.doFinal(encryptedNonce);

            // handles connection after decrypting nonce.
            if (Arrays.equals(nonce, decryptedNonce)) {
                System.out.println("Server's identity verified");
                stringOut.println("CLIENT>> Ready to upload file!");
                stringOut.flush();
            } else {
                System.out.println("Identity verification unsuccessful, closing all connections");
                stringOut.println("CLIENT>> Bye!");
                closeConnections(byteOut, byteIn, stringOut, stringIn, socket);
            }


            // **************** END OF AP ***************

            // start file transfer
            System.out.println("INITIALIZING FILE TRANSFER");

            // initial time mark
            Long startTime = System.currentTimeMillis();

            // encrypt and upload file - CP2
            encryptAndUploadFileCP2(stringOut, serverPublicKey, stringIn, byteOut);

            // confirmation of successful file upload
            System.out.println(stringIn.readLine());

            Long endTime = System.currentTimeMillis();
            System.out.println("Uploading time spent is: " + (endTime-startTime) + "ms");


            closeConnections(byteOut, byteIn, stringOut, stringIn, socket);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateNonce() throws NoSuchAlgorithmException {
        // create secure random number generator
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");

        // get 1024 random bytes
        byte[] nonce = new byte[64];
        secureRandom.nextBytes(nonce);
        return nonce;
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

    private static void encryptAndUploadFileCP2(PrintWriter stringOut, PublicKey serverPublicKey, BufferedReader stringIn, OutputStream byteOut) throws Exception{

        // create cipher object and initialize is as encrypt mode, use PUBLIC key.
        Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        // generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // convert secret key to byte array
        byte[] aesKeyBytes = aesKey.getEncoded();

        // encrypt AES key
        byte[] encryptedAESKeyBytes = rsaCipherEncrypt.doFinal(aesKeyBytes);

        // create cipher object for file encryption
        Cipher aesEnCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesEnCipher.init(Cipher.ENCRYPT_MODE, aesKey);

        // get bytes of file needed for transfer
        File file = new File(uploadFilePath);
        byte[] fileBytes = new byte[(int) file.length()];
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
        bis.read(fileBytes, 0, fileBytes.length);

        // encrypt file with AES key
        byte[] encryptedFileBytes = aesEnCipher.doFinal(fileBytes);

        // send encrypted AES session key
        stringOut.println(encryptedAESKeyBytes.length);
        stringOut.flush();
        System.out.println(stringIn.readLine());
        byteOut.write(encryptedAESKeyBytes, 0, encryptedAESKeyBytes.length);
        byteOut.flush();
        System.out.println("Sent to server encrypted session key");


        // upload encrypted file to server
        stringOut.println(uploadFileName);
        stringOut.println(encryptedFileBytes.length);
        stringOut.flush();
        System.out.println(stringIn.readLine());
        byteOut.write(encryptedFileBytes, 0, encryptedFileBytes.length);
        byteOut.flush();
        System.out.println("Sent to server encrypted file");

    }
}
