package com.ctlok.web.session;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ctlok.web.session.crypto.Encryptor;

public class StatelessSessionConfig {

    private final ServletContext servletContext;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    
    private final String hmacSHA1Key;
    private final String secretKey;
    private final Encryptor encryptor;
    private final String sessionName;
    
    private final int sessionMaxAge;
    private final String path;
    private final String domain;
    
    public StatelessSessionConfig(ServletContext servletContext,
            HttpServletRequest request, HttpServletResponse response,
            String hmacSHA1Key, String secretKey, Encryptor encryptor,
            String sessionName, int sessionMaxAge, String path, String domain) {
        super();
        this.servletContext = servletContext;
        this.request = request;
        this.response = response;
        this.hmacSHA1Key = hmacSHA1Key;
        this.secretKey = secretKey;
        this.encryptor = encryptor;
        this.sessionName = sessionName;
        this.sessionMaxAge = sessionMaxAge;
        this.path = path;
        this.domain = domain;
    }
    
    public ServletContext getServletContext() {
        return servletContext;
    }
    public HttpServletRequest getRequest() {
        return request;
    }
    public HttpServletResponse getResponse() {
        return response;
    }
    public String getHmacSHA1Key() {
        return hmacSHA1Key;
    }
    public String getSecretKey() {
        return secretKey;
    }
    public Encryptor getEncryptor() {
        return encryptor;
    }
    public String getSessionName() {
        return sessionName;
    }
    public int getSessionMaxAge() {
        return sessionMaxAge;
    }
    public String getPath() {
        return path;
    }
    public String getDomain() {
        return domain;
    }
    
    
    
}
