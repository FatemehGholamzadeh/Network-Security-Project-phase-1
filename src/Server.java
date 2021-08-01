package ir.aut;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigDecimal;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Timer;
import java.util.TimerTask;

public class Server {
    private static String privateKey = "8877665544332211";
    private static byte[] IV = new byte[16];
    private static byte[] sessionKey = new byte[16];
    private static byte[] pureSessionKey = new byte[16];
    private static AES aes = new AES();
    private static String physicalKey = "";
    private static byte[] newSessionKey = new byte[7];
    private static byte[] sendBytes = new byte[23];
    private static boolean aBoolean = false;

    public static void main(String[] args) throws Exception {
        //initialize IV
        for (int i = 0; i < 16; i++) {
            IV[i] = 0;
        }
        newSessionKey = "session".getBytes();

        //create Socket
        ServerSocket serverSocket = new ServerSocket(4444);
        Socket s = serverSocket.accept();

        //dis & dos
        DataInputStream dis = new DataInputStream(s.getInputStream());
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        //receiving Request
        String userName = receiveRequest(dis);

        //encrypting physicalKey
        encryptKey(aes);

        //extract user physical key from encrypted file
        findPhysicalKey(userName, aes);

        class Hello extends TimerTask {
            public void run() {
                aBoolean = true;
            }
        }
        Timer timer = new Timer();
        timer.schedule(new Hello(), 1000, 5000);//1 Min


        sessionKey = createSessionKey(physicalKey, aes);
        dos.write(sessionKey);


        File f = new File("1.jpg");
        BigDecimal bytes = new BigDecimal(f.length());
        int size = bytes.intValue();
        byte[] buffer = new byte[16];
        FileInputStream inputStream = new FileInputStream(f);
        dos.writeInt(size);


        for (int i = 0; i < (size / 16 + 1); i++) {

            if (aBoolean) {
                byte[] bytes1 = "session".getBytes();
                dos.write(bytes1);

                sessionKey = createSessionKey(physicalKey, aes);
                dos.write(sessionKey);
                aBoolean = false;
            }
            inputStream.read(buffer);
            buffer = aes.encrypt(buffer, pureSessionKey, IV);
            dos.write(buffer);


        }

        String nextPhysicalKey = randomString(16);
        byte[] array = aes.encrypt(nextPhysicalKey.getBytes(), physicalKey.getBytes(), IV);
        dos.write(array);
        System.out.println("last p key : " + nextPhysicalKey);
        writeNextPhysical(array,nextPhysicalKey.getBytes());


    }


    public static byte[] createSessionKey(String physicalKey, AES aes) throws Exception {

        //ciphering a random string with physical key
        String randomString = randomString(16);
        byte[] sessionKey = aes.encrypt(randomString.getBytes(), physicalKey.getBytes(), IV);
        pureSessionKey = randomString.getBytes();
        return sessionKey;

    }


    public static String randomString(int n) {
        {
            // chose a Character random from this String
            String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    + "0123456789"
                    + "abcdefghijklmnopqrstuvxyz";

            // create StringBuffer size of AlphaNumericString
            StringBuilder sb = new StringBuilder(n);

            for (int i = 0; i < n; i++) {

                // generate a random number between
                // 0 to AlphaNumericString variable length
                int index
                        = (int) (AlphaNumericString.length()
                        * Math.random());

                // add Character one by one in end of sb
                sb.append(AlphaNumericString
                        .charAt(index));
            }

            return sb.toString();
        }
    }


    public static String receiveRequest(DataInputStream dis) throws Exception {
        String userName = dis.readUTF();
        System.out.println("we have a Request from USer with this User Name : ");
        System.out.println(userName);
        return userName;
    }

    public static void findPhysicalKey(String userName, AES aes) throws Exception {
        File f = new File("encryptedKey.txt");
        BigDecimal bytes = new BigDecimal(f.length());
        int size = bytes.intValue();
        byte[] buffer = new byte[size];

        if (f.exists()) {
            FileInputStream inputStream = new FileInputStream(f);
            while (inputStream.read(buffer) != -1) {
                physicalKey = new String(aes.decrypt(buffer, privateKey.getBytes(), IV), "UTF-8");
            }
        }

        String[] lines = physicalKey.split("\\r?\\n");
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(userName)) {
                physicalKey = lines[i].substring(lines[i].indexOf(userName) + userName.length() + 3);
            }
        }
    }


    public static void encryptKey(AES aes) throws Exception {

        File f = new File("key.txt");
        BigDecimal bytes = new BigDecimal(f.length());
        int size = bytes.intValue();
        byte[] buffer = new byte[size];

        if (f.exists()) {
            FileInputStream inputStream = new FileInputStream(f);
            while (inputStream.read(buffer) != -1) {

                buffer = aes.encrypt(buffer, privateKey.getBytes(), IV);
            }
            FileOutputStream fos = new FileOutputStream("encryptedKey.txt");
            fos.write(buffer);
        }
    }

    public static void writeNextPhysical(byte[] buffer, byte[] ss) throws Exception {
        FileOutputStream fos = new FileOutputStream("ServerNextPhysicalKey.txt");
        FileOutputStream fos1 = new FileOutputStream("ServerEncryptedNextPhysicalKey.txt");
        fos.write(buffer);
        fos1.write(ss);
    }
} 