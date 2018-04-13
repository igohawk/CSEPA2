import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;






public class ClientWithoutSecurity {

	public static void main(String[] args) {
	    Cipher cipher;
        int Nounce;
    	String filename = "Mao_Zedong_1963.jpg";

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket("localhost", 4321);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			//checking
            System.out.println("Asking for identity(with Nounce)...");
            toServer.writeInt(PacketType.ASK_IDENTITY);
            Nounce = (int)Math.floor(Math.random()*9999);
            toServer.writeInt(Nounce);
            toServer.flush();

            if (fromServer.readInt() != PacketType.ASK_IDENTITY) {
                System.out.println("Wrong Server Response in asking identity");
                return;
            }
            int length = fromServer.readInt();
            byte[] response = new byte[length];
            fromServer.read(response);

            System.out.println("Requesting for Cert...");
            toServer.writeInt(PacketType.REQUEST_CERT);
            toServer.flush();
            if (fromServer.readInt() != PacketType.FILE_HEAD) {
                System.out.println("Wrong server response in requesting certificate");
                return;
            }
            HelperClass.receiveFile("client/", fromServer);
            X509Certificate serverCert = getCert();
            if (!checkCert(serverCert)) {
                System.out.println("Wrong server certificate");
                return;
            }
            PublicKey serverPubKey = serverCert.getPublicKey();
            byte[] decryptedRes = decrypt(response, serverPubKey);
            if (!new String (decryptedRes).equals("SecStore;" + Nounce)) {
                System.out.println("Wrong sever verification");
                return;
            }
            System.out.println("Sending AES Key...");
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();

            byte[] en_key = encrypt(key.getEncoded(),serverPubKey);

            toServer.writeInt(PacketType.AES_KEY);
            toServer.writeInt(en_key.length);
            toServer.write(en_key);
            toServer.flush();

            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            HelperClass.sendFileEncrypt(toServer, filename, cipher);

			System.out.println("Closing connection...");
	        toServer.writeInt(PacketType.CLOSE);
	        toServer.flush();

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	public static X509Certificate getCert() throws Exception{
        InputStream fis = new FileInputStream("client/server.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
        return CAcert;
    }
    public static boolean checkCert(X509Certificate certificate) {
	    try {
            certificate.checkValidity();
            InputStream fis = new FileInputStream("CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);
            PublicKey key = CAcert.getPublicKey();
            certificate.verify(key);
        } catch (Exception e) {
	        return false;
        }
        return true;
    }

    public static byte[] decrypt(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }
    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }
}
