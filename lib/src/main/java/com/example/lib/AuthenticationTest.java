package com.example.lib;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class AuthenticationTest {

    public static void main(String[] args) throws FileNotFoundException, CertificateException {

        try {
            InputStream inp1 = new FileInputStream("server.crt");
            InputStream inp2 = new FileInputStream("CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate1 = (X509Certificate) cf.generateCertificate(inp1);
            X509Certificate x509Certificate2 = (X509Certificate) cf.generateCertificate(inp2);
            PublicKey key = x509Certificate2.getPublicKey();
            x509Certificate1.checkValidity();
            x509Certificate1.verify(key);
            System.out.println("Success!");
            
        } catch (FileNotFoundException e) {
            System.out.println("File not found");
        } catch (CertificateException e) {
            System.out.println("Certificate Exception");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No such algorithm");
        } catch (InvalidKeyException e) {
            System.out.println("invalid key");
        } catch (NoSuchProviderException e) {
            System.out.println("No such provider");
        } catch (SignatureException e) {
            System.out.println("signature exception");
            e.printStackTrace();
        }

    }


}


