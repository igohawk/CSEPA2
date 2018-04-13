import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ServerWithoutSecurity {

	public static void main(String[] args) {
		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		SecretKey aesKey = null;

		try {
			welcomeSocket = new ServerSocket(4321);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			while (!connectionSocket.isClosed()) {
				int packetType = fromClient.readInt();
				System.out.println("server + " + packetType);
				if (packetType == PacketType.ASK_IDENTITY) {
					int Nounce = fromClient.readInt();
					System.out.println("Showing Identity");
                    String response = "SecStore;" + Nounce;
                    byte[] encryptedRes = encrypt(response.getBytes());
                    toClient.writeInt(PacketType.ASK_IDENTITY);
                    toClient.writeInt(encryptedRes.length);
                    toClient.write(encryptedRes);
                    toClient.flush();


                    // If the packet is for transferring the filename
                } else if (packetType == PacketType.REQUEST_CERT) {
					System.out.println("Sending Cert...");
					HelperClass.sendFile(toClient, "server.crt");
				} else if (packetType == PacketType.AES_KEY){
					System.out.println("Receiving AES key");
					int en_key_length = fromClient.readInt();
					byte[] en_key = new byte[en_key_length];
					fromClient.read(en_key);
					byte[] byte_key = decrypt(en_key);
					aesKey = new SecretKeySpec(byte_key, 0, byte_key.length, "AES");
				} else if (packetType == PacketType.FILE_HEAD) {

					System.out.println("Receiving file...");
					Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cipher.init(Cipher.DECRYPT_MODE, aesKey);
                    HelperClass.receiveFileDecrypt("server/", fromClient, cipher);

                    //If the packet is closing.
				} else if (packetType == PacketType.CLOSE) {

					System.out.println("Closing connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

	public static PrivateKey getPrivateKey() throws Exception{
        File f = new File("privateServer.der");
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    public static byte[] encrypt(byte[] content) throws Exception{
	    PrivateKey key = getPrivateKey();
	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    return cipher.doFinal(content);
    }
	public static byte[] decrypt(byte[] content) throws Exception{
		PrivateKey key = getPrivateKey();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(content);
	}

}
