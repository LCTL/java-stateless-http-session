package com.ctlok.web.session.impl;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ctlok.web.session.Factory;
import com.ctlok.web.session.StatelessSession;
import com.ctlok.web.session.SessionMap;
import com.ctlok.web.session.crypto.Encryptor;

/**
 * @author Lawrence Cheung
 *
 */
public class StatelessSessionImpl implements StatelessSession {

    private static final String ID_KEY = "__id";
    
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    
    private final String secretKey;
    private final Encryptor encryptor;
    
    private final String sessionName;
    private final int sessionMaxAge;
    private final String path;
    private final String domain;
    
    private SessionMap sessionMap;
    
    public StatelessSessionImpl(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final String hmacSHA1Key,
            final String secretKey,
            final Encryptor encryptor,
            final String sessionName,
            final int sessionMaxAge,
            final String path,
            final String domain) throws Exception{
        
        this.request = request;
        this.response = response;
        
        this.secretKey = secretKey;
        this.encryptor = encryptor;
        
        this.sessionName = sessionName;
        this.sessionMaxAge = sessionMaxAge;
        this.path = path;
        this.domain = domain;
        
        final Cookie[] cookies = this.request.getCookies();
        for (final Cookie cookie: cookies){
            if (sessionName.equals(cookie.getName())){
                
                try{
                    
                    final String cookieValue = this.secretKey == null ? 
                            cookie.getValue() :
                                encryptor.decrypt(this.secretKey, cookie.getValue());
                            
                    this.sessionMap = Factory.createSessionMap(hmacSHA1Key, cookieValue);
                    
                    if (!this.sessionMap.containsKey(ID_KEY)){
                        this.sessionMap.put(ID_KEY, this.generateSessionId());
                    }
                
                } catch (final Exception e){
                    
                    this.sessionMap = null;
                    
                }
                
                break;
                
            }
        }
        
        if (this.sessionMap == null){
            this.sessionMap = Factory.createSessionMap(hmacSHA1Key);
            this.sessionMap.put(ID_KEY, this.generateSessionId());
        }
    }
    
    public String getSessionId(){
        return this.sessionMap.get(ID_KEY);
    }
    
    public void flush(){
        try{
            this.response.addCookie(this.createCookie());
        } catch (final Exception e){
            throw new IllegalStateException(e);
        }
    }

    public int size() {
        return sessionMap.size();
    }

    public boolean isEmpty() {
        return sessionMap.isEmpty();
    }

    public boolean containsKey(String key) {
        return sessionMap.containsKey(key);
    }

    public boolean containsValue(String value) {
        return sessionMap.containsValue(value);
    }

    public String get(String key) {
        return sessionMap.get(key);
    }

    public String put(String key, String value) {
        final String result = sessionMap.put(key, value);
        this.flush();
        return result;
    }

    public String remove(String key) {
        final String result = sessionMap.remove(key);
        this.flush();
        return result;
    }

    public void putAll(Map<String, String> map) {
        sessionMap.putAll(map);
        this.flush();
    }

    public Set<String> keySet() {
        return sessionMap.keySet();
    }

    public Collection<String> values() {
        return sessionMap.values();
    }

    public void clear() {
        sessionMap.clear();
        this.flush();
    }
    
    protected Cookie createCookie() throws Exception{
        final String cookieValue = this.secretKey == null ? 
                this.sessionMap.toCookieValue() :
                    encryptor.encrypt(this.secretKey, this.sessionMap.toCookieValue());
        final Cookie cookie = new Cookie(sessionName, cookieValue);
        cookie.setMaxAge(sessionMaxAge);
        cookie.setPath(this.path);

        if (this.domain != null){
            cookie.setDomain(this.domain);
        }
        
        return cookie;
    }
    
    protected String generateSessionId(){
        final String uuid = UUID.randomUUID().toString();
        return new BigInteger(uuid.replaceAll("-", ""), 16).toString(32);
    }
    
}
