package ir.aut;

import java.io.*;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private static byte[] sessionKey = new byte[16];
    private static String privateKey = "1122334455667788";
    private static byte[] IV = new byte[16];
    private static byte[] sk = new byte[16];
    private static String physicalKey = "";


    public static void main(String[] args) throws Exception {

        //initialize IV
        for (int i = 0; i < 16; i++) {
            IV[i] = 0;
        }

        //create AES object
        AES aes = new AES();

        //defining IP and port
        InetAddress ip = InetAddress.getLocalHost();
        int port = 4444;

        //defining Socket
        Socket s = new Socket(ip, port);

        //dos and dis
        DataInputStream dis = new DataInputStream(s.getInputStream());
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        //sending Request
        sendRequest(dos);


        //encrypt key
        encryptKey(aes);

        readPhysicalKey(aes);


        //read session key bare avval
        dis.readFully(sessionKey);
        sk = (aes.decrypt(sessionKey, physicalKey.getBytes(), IV));

        // read length of incoming message
        int length = dis.readInt();

        FileOutputStream out = new FileOutputStream(new File("D:\\download\\1.jpg"), false);
        byte[] message = new byte[16];
        for (int i = 0; i < (length / 16 + 1); i++) {
            dis.read(message);
            String a = new String(message, "UTF-8");
            if (a.contains("session")) {
                System.out.println("session key changed ! ");
                dis.read(sessionKey);
                sk = aes.decrypt(sessionKey, physicalKey.getBytes(), IV);
                dis.read(message);
            }

            message = aes.decrypt(message, sk, IV);
            out.write(message);

        }
        byte[] nextPhysicalKey = new byte[16];
        dis.read(nextPhysicalKey);
        byte[] ss = aes.decrypt(nextPhysicalKey, physicalKey.getBytes(), IV);
        writeNextPhysical(nextPhysicalKey, ss);
        s.close();
    }

    public static void encryptKey(AES aes) throws Exception {
        File f = new File("key2.txt");
        BigDecimal bytes = new BigDecimal(f.length());
        int size = bytes.intValue();
        byte[] buffer = new byte[size];
        if (f.exists()) {
            FileInputStream inputStream = new FileInputStream(f);
            while (inputStream.read(buffer) != -1) {

                buffer = aes.encrypt(buffer, privateKey.getBytes(), IV);
            }
            FileOutputStream fos = new FileOutputStream("ClientEncryptedKey.txt");
            fos.write(buffer);

        }
    }

    public static void writeNextPhysical(byte[] buffer, byte[] ss) throws Exception {
        FileOutputStream fos = new FileOutputStream("nextPhysicalKey.txt");
        FileOutputStream fos1 = new FileOutputStream("encryptedNextPhysicalKey.txt");
        fos.write(buffer);
        fos1.write(ss);
    }


    public static void readPhysicalKey(AES aes) throws Exception {
        File f = new File("ClientEncryptedKey.txt");
        BigDecimal bytes = new BigDecimal(f.length());
        int size = bytes.intValue();
        byte[] buffer = new byte[size];
        if (f.exists()) {
            FileInputStream inputStream = new FileInputStream(f);
            while (inputStream.read(buffer) != -1) {
                physicalKey = new String(aes.decrypt(buffer, privateKey.getBytes(), IV), "UTF-8");
            }
        }
    }

    public static void sendRequest(DataOutputStream dos) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("please Enter your User Name : ");
        String userName = scanner.nextLine();
        System.out.println("we're sending your User Name ... ");
        dos.writeUTF(userName);

    }

} 