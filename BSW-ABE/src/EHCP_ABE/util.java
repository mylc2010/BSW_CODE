package EHCP_ABE;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class util {
    // 将字符串转换为密钥
//    public static SecretKey stringToKey(String keyStr) throws Exception {
//        // 使用SHA-256将任意长度字符串转换为固定长度的密钥
//        MessageDigest sha = MessageDigest.getInstance("SHA-256");
//        byte[] keyBytes = sha.digest(keyStr.getBytes(StandardCharsets.UTF_8));
//
//        // 使用前16字节生成128位AES密钥
//        return new SecretKeySpec(keyBytes, "AES");
//    }
//
//    // 加密
//    public static String encryptABE(String data, String secretString) {
//        try {
//            SecretKey secretKey = stringToKey(secretString);
//            Cipher cipher = Cipher.getInstance("AES");
//            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
//            return Base64.getEncoder().encodeToString(encryptedBytes);
//        }
//        catch (Exception e) {
//            return null;
//        }
//    }
//
//    // 解密
//    public static String decryptABE(String encryptedData, String secretString) {
//        try {
//            SecretKey secretKey = stringToKey(secretString);
//            Cipher cipher = Cipher.getInstance("AES");
//            cipher.init(Cipher.DECRYPT_MODE, secretKey);
//            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
//            return new String(decryptedBytes);
//        }
//        catch (Exception e) {
//            return null;
//        }
//    }
    // 使用SHA-256生成AES密钥
    public static SecretKey stringToKey(String keyStr) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(keyStr.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, 0, 16, "AES"); // 使用前16字节作为AES密钥
    }

    // 加密GT元素
    public static String encryptABE(Element gtElement, String secretString) {
        try {
            // 将GT元素序列化为字节数组
            byte[] elementBytes = gtElement.toBytes();

            // 生成AES密钥
            SecretKey secretKey = stringToKey(secretString);
            System.out.println("En secretKey:" + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            // 初始化AES加密器
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // 加密字节数组
            byte[] encryptedBytes = cipher.doFinal(elementBytes);

            // 转换为Base64字符串返回
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 解密并还原GT元素
    public static Element decryptABE(String encryptedData, String secretString, Pairing pairing) {
        try {
            // 生成AES密钥
            SecretKey secretKey = stringToKey(secretString);
            System.out.println("De secretKey:" + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            // 初始化AES解密器
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // 解密Base64字符串
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

            // 将字节数组反序列化为GT元素
            return pairing.getGT().newElementFromBytes(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        String pairingParametersFileName = "BSW-ABE/a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("原文: " + message);

        Scanner scanner = new Scanner(System.in);
        String secretKeyString = scanner.nextLine();

        // 加密
        String encryptedText = encryptABE(message, secretKeyString);
        System.out.println("加密后: " + encryptedText);

        // 解密
        Element decryptedText = decryptABE(encryptedText, secretKeyString, bp);
        System.out.println("解密后: " + decryptedText);
    }
}
