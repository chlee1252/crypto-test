package com.example.cryptotest.encrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class Crypto {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ALGORITHM = "ARIA";
    private static final String TRANSFORMATION = "ARIA/CBC/PKCS7Padding";
    private static final String CHARSET = "UTF-8";


    public static String encryption(String plainText, String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(CHARSET));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryption(String cipherText, String key, String iv) throws UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(decrypted, CHARSET);
    }

    public static void main(String[] args) {
        String plainText = "test1234";
        String key = "";
        String iv = "";

        try {
            String encryptedText = encryption(plainText, key, iv);
            System.out.println("Encrypted == " + encryptedText);

            String decryptedText = decryption(encryptedText, key, iv);
            System.out.println("Decrypted == " + decryptedText);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
