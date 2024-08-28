package com.chat.app;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;

//Java code for password protection using the RSA asymmetric encryption algorithm:
public class PasswordProtection {

	public static void main(String[] args) {
		try {
			// Generate key pair
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
			keyPairGen.initialize(2048, new SecureRandom());
			KeyPair keyPair = keyPairGen.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			// Encrypt password with public key
			String password = "password123";
			byte[] encryptedPassword = encrypt(password, publicKey);

			// Decrypt password with private key
			String decryptedPassword = decrypt(encryptedPassword, privateKey);

			System.out.println("Original password: " + password);
			System.out.println("Encrypted password: " + new String(encryptedPassword));
			System.out.println("Decrypted password: " + decryptedPassword);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static byte[] encrypt(String plaintext, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(plaintext.getBytes());
	}

	public static String decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return new String(cipher.doFinal(ciphertext));
	}

}
