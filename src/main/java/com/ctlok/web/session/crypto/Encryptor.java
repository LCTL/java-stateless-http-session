package com.ctlok.web.session.crypto;

/**
 * @author Lawrence Cheung
 *
 */
public interface Encryptor {
    
    public String encrypt(String key, String data) throws Exception;
    public String decrypt(String key, String data) throws Exception;

}
