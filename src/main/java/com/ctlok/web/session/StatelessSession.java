package com.ctlok.web.session;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;

import com.ctlok.web.session.crypto.CryptoUtils;
import com.google.gson.Gson;

public class StatelessSession implements HttpSession {

    private static final String CHECKSUM_KEY = "__s";
    private static final String ID_KEY = "__id";
    private static final String CREATION_TIME_KEY = "__ct";
    
    private final Map<String, String> attributes = new TreeMap<String, String>();
    private final Gson gson = new Gson();
    
    private final StatelessSessionConfig config;
    private boolean newSession;
    
    private String sessionId;
    private long creationTime;
    
    public StatelessSession(final StatelessSessionConfig config){
        
        this.config = config;
        
        try{
            
            final Cookie sessionCookie = findSessionCookie();
            if (sessionCookie == null){
                this.initNewSession();
            }else{
                String cookieValue = sessionCookie.getValue();
                
                if (this.config.getSecretKey() != null){
                    
                    cookieValue = this.config.getEncryptor().decrypt(
                            this.config.getSecretKey(), cookieValue);
                        
                }

                if (this.isValidSessionCookieValue(cookieValue)){
                    this.attributes.putAll(this.jsonToMap(cookieValue));
                    this.sessionId = this.attributes.get(ID_KEY);
                    this.creationTime = Long.valueOf(this.attributes.get(CREATION_TIME_KEY));
                    
                    this.attributes.remove(CHECKSUM_KEY);
                    this.attributes.remove(ID_KEY);
                    this.attributes.remove(CREATION_TIME_KEY);
                }else{
                    this.initNewSession();
                }
            }
        
        } catch (Exception e){
            e.printStackTrace();
            this.initNewSession();
        }
    }
    
    private void initNewSession(){
        this.attributes.clear();
        this.sessionId = this.generateSessionId();
        this.creationTime = System.currentTimeMillis();
        this.newSession = true;
    }
    
    protected Cookie findSessionCookie(){
        Cookie sessionCookie = null;
        for (final Cookie cookie: this.config.getRequest().getCookies()){
            if (this.config.getSessionName().equals(cookie.getName())){
                sessionCookie = cookie;
            }
        }
        
        return sessionCookie;
    }
    
    protected boolean isValidSessionCookieValue(final String cookieValue){
        final Map<String, String> map = jsonToMap(cookieValue);
        
        if (map.containsKey(CHECKSUM_KEY) 
                && map.containsKey(ID_KEY) 
                && map.containsKey(CREATION_TIME_KEY)){
            
            final String checksum = map.get(CHECKSUM_KEY);
            map.remove(CHECKSUM_KEY);
            
            return checksum.equals(this.mapChecksum(map));
            
        }
        
        return false;
    }
    
    protected String mapToJson(final Map<String, String> map){
        return gson.toJson(map);
    }
    
    @SuppressWarnings("unchecked")
    protected Map<String, String> jsonToMap(final String json){
        return gson.fromJson(json, Map.class);
    }
    
    protected String mapChecksum(Map<String, String> map){
        try {
            return CryptoUtils.hmacSha1(this.config.getHmacSHA1Key(), this.mapToJson(map));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }
    
    protected String generateSessionId(){
        final String uuid = UUID.randomUUID().toString();
        return new BigInteger(uuid.replaceAll("-", ""), 16).toString(32);
    }
    
    protected Cookie createCookie() {
        try{
            final Map<String, String> map = new TreeMap<String, String>();
            map.putAll(this.attributes);
            map.put(ID_KEY, sessionId);
            map.put(CREATION_TIME_KEY, Long.toString(creationTime));
            
            final String checksum = mapChecksum(map);
            map.put(CHECKSUM_KEY, checksum);
            
            final String json = mapToJson(map);
            final String cookieValue = this.config.getSecretKey() == null ? json : 
                this.config.getEncryptor().encrypt(this.config.getSecretKey(), json);
            
            final Cookie cookie = new Cookie(this.config.getSessionName(), cookieValue);
            
            cookie.setMaxAge(this.config.getSessionMaxAge());
            cookie.setPath(this.config.getPath());
            cookie.setHttpOnly(this.config.isHttpOnly());
            
            if (this.config.getDomain() != null){
                cookie.setDomain(this.config.getDomain());
            }
            
            return cookie;
        } catch (final Exception e){
            throw new IllegalStateException(e);
        }
    }
    
    public void flush(){
        this.config.getResponse().addCookie(this.createCookie());
    }
    
    @Override
    public long getCreationTime() {
        return this.creationTime;
    }

    @Override
    public String getId() {
        return this.sessionId;
    }

    @Override
    public long getLastAccessedTime() {
        return 0;
    }

    @Override
    public ServletContext getServletContext() {
        return this.config.getServletContext();
    }

    @Override
    public void setMaxInactiveInterval(int interval) {
        
    }

    @Override
    public int getMaxInactiveInterval() {
        return 0;
    }

    @Override
    public HttpSessionContext getSessionContext() {
        return null;
    }

    @Override
    public Object getAttribute(String name) {
        return this.attributes.get(name);
    }

    @Override
    public Object getValue(String name) {
        return this.getAttribute(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return Collections.enumeration(this.attributes.values());
    }

    @Override
    public String[] getValueNames() {
        return this.attributes.keySet().toArray(new String[0]);
    }

    @Override
    public void setAttribute(String name, Object value) {
        if (value instanceof String){
            this.attributes.put(name, value.toString());
            this.flush();
        }else{
            throw new IllegalArgumentException("Stateless session only accept String value");
        }
    }

    @Override
    public void putValue(String name, Object value) {
        this.setAttribute(name, value);
    }

    @Override
    public void removeAttribute(String name) {
        this.attributes.remove(name);
        this.flush();
    }

    @Override
    public void removeValue(String name) {
        this.removeAttribute(name);
    }

    @Override
    public void invalidate() {
        final Cookie cookie = this.createCookie();
        cookie.setMaxAge(0);
        this.config.getResponse().addCookie(cookie);
    }

    @Override
    public boolean isNew() {
        return this.newSession;
    }

}
