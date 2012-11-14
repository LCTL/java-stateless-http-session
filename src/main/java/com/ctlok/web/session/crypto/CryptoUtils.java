package com.ctlok.web.session.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * @author Lawrence Cheung
 * 
 */
public class CryptoUtils {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    public static String hmacSha1(final String key, final String data)
            throws InvalidKeyException {
        String result = null;

        try {
            final Key secretKey = new SecretKeySpec(key.getBytes(),
                    HMAC_SHA1_ALGORITHM);
            final Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(secretKey);
            result = bytesToHex(mac.doFinal(data.getBytes()));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        return result;
    }

    public static String encrypt(final String algorithm, final String key,
            final String data) throws IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, DecoderException {

        return encryptDecrypt(algorithm, true, key, data);

    }

    public static String decrypt(final String algorithm, final String key,
            final String data) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, DecoderException {

        return encryptDecrypt(algorithm, false, key, data);

    }

    public static String bytesToHex(final byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    public static byte[] hexStringToBytes(final String hexString) throws DecoderException {
        return Hex.decodeHex(hexString.toCharArray());
    }
    
    public static String encodeBase64(final byte[] bytes){
        return Base64.encodeBase64String(bytes);
    }
    
    public static byte[] decodeBase64(final String str){
        return Base64.decodeBase64(str);
    }

    private static String encryptDecrypt(final String algorithm,
            boolean encrypt, final String key, final String data)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException, DecoderException{

        final int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        final Key secretKey = new SecretKeySpec(key.getBytes(), algorithm);
        final Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(mode, secretKey);
        
        return encrypt ? 
                encodeBase64(cipher.doFinal(data.getBytes())) :
                    new String(cipher.doFinal(decodeBase64(data)));

    }

}
