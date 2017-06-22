package com.neeloy.networklibs;

/**
 * Created by NeeloyG on 02-02-2016.
 */


import android.util.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtils {

    /**
     * @param paramString
     * @return {@link Byte}
     */
    public static byte[] getSHA256(String paramString) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(paramString.getBytes("UTF-8"));
        byte[] digest = md.digest();
        return digest;
    }

    /**
     * @param data,key
     * @return {@link Byte}
     */

    public static byte[] encryptAES(byte[] data, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher acipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] arrayOfByte1;
        acipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        arrayOfByte1 = acipher.doFinal(data);
        return arrayOfByte1;
    }

    /**
     * @param data,key
     * @return {@link Byte}
     */
    public static byte[] decryptAES(byte[] data, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher acipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] arrayOfByte1;
        acipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        arrayOfByte1 = acipher.doFinal(data);
        return arrayOfByte1;
    }

    /**
     * @param privateKeyData
     * @return {@link PrivateKey}
     */

    public static PrivateKey getPrivateKeyFromString(String privateKeyData) throws InvalidKeySpecException,
            NoSuchAlgorithmException, IOException {
        byte[] keyBytes = Base64.decode(privateKeyData, Base64.NO_WRAP);
        // Get private Key
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = fact.generatePrivate(pkcs8EncodedKeySpec);
        return privateKey;
    }

    /**
     * @param encryptedData,privateKey
     * @return {@link String}
     */
    public static String decryptRSA(String encryptedData, PrivateKey privateKey) {
        try {
            byte[] encryptedDataBytes = Base64.decode(encryptedData, Base64.NO_WRAP);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(encryptedDataBytes);
            String palinTextDecryptedData = new String(decryptedData);
            return palinTextDecryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * @param s
     * @return {@link Byte}
     */
    public static byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    /**
     * @param a
     * @return {@link String}
     */
    public static String byteArrayToHexString(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    /**
     * @param data,issuerPublicKey
     * @return {@link String}
     */
    public static String encryptRSA(String data, PublicKey issuerPublicKey) {
        String _out = "";
        byte[] dataToEncrypt = data.getBytes();
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, issuerPublicKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
        _out = Base64.encodeToString(encryptedData, Base64.NO_WRAP);
        return _out;
    }

    /**
     * @param publicKeyData
     * @return {@link PublicKey}
     */
    public static PublicKey getPublicKeyFromString(String publicKeyData)
            throws InvalidKeySpecException,
            NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] keyBytes = Base64.decode(publicKeyData.getBytes("utf-8"),
                Base64.NO_WRAP);
        // Get Public Key
        X509EncodedKeySpec rsaPublicKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);

        return publicKey;
    }

    /**
     * @param
     * @return {@link String}
     */
    public static String generateRandomAes256Key() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytes = secretKey.getEncoded();
            return byteArrayToHexString(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

}