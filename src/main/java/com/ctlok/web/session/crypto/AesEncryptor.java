package com.ctlok.web.session.crypto;

/**
 * @author Lawrence Cheung
 *
 */
public class AesEncryptor implements Encryptor {

    private static final String ALGORITHM = "AES";

    @Override
    public String encrypt(String key, String data) throws Exception {
        return CryptoUtils.encrypt(ALGORITHM, key, data);
    }

    @Override
    public String decrypt(String key, String data) throws Exception {
        return CryptoUtils.decrypt(ALGORITHM, key, data);
    }

}
