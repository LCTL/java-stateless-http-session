package com.ctlok.web.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ctlok.web.session.crypto.Encryptor;
import com.ctlok.web.session.impl.SessionMapImpl;
import com.ctlok.web.session.impl.StatelessSessionImpl;

public class Factory {

    public static SessionMap createSessionMap(String hmacSHA1Key) {
        return new SessionMapImpl(hmacSHA1Key);
    }
    
    public static SessionMap createSessionMap(String hmacSHA1Key, String cookieValue) {
        return new SessionMapImpl(hmacSHA1Key, cookieValue);
    }

    public static StatelessSession createStatelessSession(HttpServletRequest request,
            HttpServletResponse response, String hmacSHA1Key, String secretKey,
            Encryptor encryptor, String sessionName, int sessionMaxAge,
            String path, String domain) {
        try {
            return new StatelessSessionImpl(request, response, hmacSHA1Key,
                    secretKey, encryptor, sessionName, sessionMaxAge, path, domain);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

}
