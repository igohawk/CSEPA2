import javax.crypto.Cipher;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;

public class HelperClass {
    public static void sendFile(DataOutputStream toEntity, String filename) throws Exception{

        // Send the filename
        toEntity.writeInt(PacketType.FILE_HEAD);
        toEntity.writeInt(filename.getBytes().length);
        toEntity.write(filename.getBytes());
        toEntity.flush();

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(filename);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        byte [] fromFileBuffer = new byte[117];
        
        int numBytes;
        // Send the file
        while(true) {
            numBytes = bufferedFileInputStream.read(fromFileBuffer);
            boolean fileEnded = numBytes < fromFileBuffer.length;
            toEntity.writeInt(PacketType.FILE_CONTENT);
            toEntity.writeInt(fromFileBuffer.length);
            toEntity.write(fromFileBuffer);
            toEntity.flush();
            if (fileEnded == true) break;
        }
        toEntity.writeInt(PacketType.FILE_END);
        toEntity.flush();
        bufferedFileInputStream.close();
        fileInputStream.close();
        System.out.println("File sent successfully.");
    }
    
    public static void receiveFile(String folder, DataInputStream fromEntity) throws Exception{
        int numBytes = fromEntity.readInt();
        byte [] filename = new byte[numBytes];
        fromEntity.read(filename);
        FileOutputStream fileOutputStream = new FileOutputStream(folder+new String(filename, 0, numBytes));
        BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
        // If the packet is for transferring a chunk of the file
        while(true) {
            int packetType;
            packetType = fromEntity.readInt();
            if (packetType == PacketType.FILE_CONTENT) {
                numBytes = fromEntity.readInt();
                byte[] block = new byte[numBytes];
                fromEntity.read(block);

                if (numBytes > 0) bufferedFileOutputStream.write(block, 0, numBytes);

            } else if (packetType == PacketType.FILE_END) {
                System.out.println("File Received Successfully.");
                if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                if (bufferedFileOutputStream != null) fileOutputStream.close();
                break;
            }

        }
    }

    public static void sendFileEncrypt(DataOutputStream toEntity, String filename, Cipher cipher) throws Exception{
        // Send the filename

        byte[] en_filename = cipher.doFinal(filename.getBytes());
        toEntity.writeInt(PacketType.FILE_HEAD);
        toEntity.writeInt(en_filename.length);
        toEntity.write(en_filename);
        toEntity.flush();

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(filename);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        byte [] fromFileBuffer = new byte[117];

        int numBytes;
        // Send the file
        while(true) {
            numBytes = bufferedFileInputStream.read(fromFileBuffer);
            boolean fileEnded = numBytes < fromFileBuffer.length;

            byte[] en_fromFileBuffer = cipher.doFinal(fromFileBuffer);
            toEntity.writeInt(PacketType.FILE_CONTENT);
            toEntity.writeInt(en_fromFileBuffer.length);
            toEntity.write(en_fromFileBuffer);
            toEntity.flush();
            if (fileEnded == true) break;
        }
        toEntity.writeInt(PacketType.FILE_END);
        toEntity.flush();
        bufferedFileInputStream.close();
        fileInputStream.close();
        System.out.println("File sent successfully.");

    }
    public static void receiveFileDecrypt(String folder, DataInputStream fromEntity, Cipher cipher) throws Exception {
        // Send the filename

        int numBytes = fromEntity.readInt();
        byte[] en_filename = new byte[numBytes];
        fromEntity.read(en_filename);
        byte[] filename = cipher.doFinal(en_filename);
        FileOutputStream fileOutputStream = new FileOutputStream(folder + new String(filename));
        BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
        // If the packet is for transferring a chunk of the file
        while (true) {
            int packetType;
            packetType = fromEntity.readInt();
            if (packetType == PacketType.FILE_CONTENT) {
                numBytes = fromEntity.readInt();
                byte[] block = new byte[numBytes];
                fromEntity.read(block);
                byte[] de_block = cipher.doFinal(block);
                if (numBytes > 0) bufferedFileOutputStream.write(de_block, 0, de_block.length);

            } else if (packetType == PacketType.FILE_END) {
                System.out.println("File Received Successfully.");
                if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                if (bufferedFileOutputStream != null) fileOutputStream.close();
                break;
            }

        }
    }
}
