package com.chat.app;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

//Java code for password protection using the Advanced Encryption Standard (AES) algorithm:
public class SymetricPasswordProtection {

    private static final String KEY = "secretkehbhbnbjn";

    public static String encryptPassword(String password) {
        try {
            Key secretKey = new SecretKeySpec(KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(password.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptPassword(String encryptedPassword) {
        try {
            Key secretKey = new SecretKeySpec(KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String password = "mypassword123";
        String encryptedPassword = encryptPassword(password);
        System.out.println("Encrypted Password: " + encryptedPassword);
        
        String decryptedPassword = decryptPassword(encryptedPassword);
        System.out.println("Decrypted Password: " + decryptedPassword);
    }
}

