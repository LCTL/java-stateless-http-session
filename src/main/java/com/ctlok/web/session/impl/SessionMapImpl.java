package com.ctlok.web.session.impl;

import java.security.InvalidKeyException;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.ctlok.web.session.SessionMap;
import com.ctlok.web.session.crypto.CryptoUtils;

/**
 * @author Lawrence Cheung
 *
 */
public class SessionMapImpl implements SessionMap {

    private static final String CHECKSUM_KEY = "__s";
    
    private final Map<String, String> parameters;
    private final String hmacSHA1Key;
    
    public SessionMapImpl(final String hmacSHA1Key){
        this.hmacSHA1Key = hmacSHA1Key;
        this.parameters = new HashMap<String, String>();
    }
    
    public SessionMapImpl(final String hmacSHA1Key, final String cookieValue){
        
        this.hmacSHA1Key = hmacSHA1Key;
        
        if (this.isValid(cookieValue)){
            this.parameters = this.convertCookieValueToParameter(cookieValue);
        }else{
            this.parameters = new HashMap<String, String>();
        }

    }
    
    public String toCookieValue(){
        parameters.remove(CHECKSUM_KEY);
        return this.parametersToStringWithCheckSum(this.parameters);
    }
    
    @Override
    public int size() {
        return parameters.size();
    }

    @Override
    public boolean isEmpty() {
        return parameters.isEmpty();
    }

    @Override
    public boolean containsKey(Object key) {
        return parameters.containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return parameters.containsValue(value);
    }

    @Override
    public String get(Object key) {
        return parameters.get(key);
    }

    @Override
    public String put(String key, String value) {
        return parameters.put(key, value);
    }

    @Override
    public String remove(Object key) {
        return parameters.remove(key);
    }

    @Override
    public void putAll(Map<? extends String, ? extends String> m) {
        parameters.putAll(m);
    }

    @Override
    public void clear() {
        parameters.clear();
    }

    @Override
    public Set<String> keySet() {
        return parameters.keySet();
    }

    @Override
    public Collection<String> values() {
        return parameters.values();
    }

    @Override
    public Set<Entry<String, String>> entrySet() {
        return parameters.entrySet();
    }

    @Override
    public boolean equals(Object o) {
        return parameters.equals(o);
    }

    @Override
    public int hashCode() {
        return parameters.hashCode();
    }

    protected String parametersToStringWithCheckSum(final Map<String, String> parameters){
        try {
            final String data = this.parametersToString(parameters);
            final String checksum = CryptoUtils.hmacSha1(this.hmacSHA1Key, data);
            
            parameters.put(CHECKSUM_KEY, checksum);
            return parametersToString(parameters);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("HMAC-SHA1 Key is not valid", e);
        }
    }
    
    protected String parametersToString(final Map<String, String> parameters){
        final StringBuilder builder = new StringBuilder();
        
        int i = 0;
        for (final Entry<String, String> entry: parameters.entrySet()){
            if (i > 0){
                builder.append(",");
            }
            
            final String key = this.encode(entry.getKey());
            final String value = this.encode(entry.getValue());
            
            builder.append(key);
            builder.append("=");
            builder.append(value);
            
            ++i;
        }
        
        return builder.toString();
    }
    
    protected Map<String, String> convertCookieValueToParameter(final String cookieValue){
        final Map<String, String> parameters = new TreeMap<String, String>();
        if (!(cookieValue == null && "".equals(cookieValue))){
            
            for (final String value : cookieValue.split(",")){
                final Entry<String, String> entry = this.createEntry(value);
                if (entry != null){
                    parameters.put(entry.getKey(), entry.getValue());
                }
            }
            
        }
        
        return parameters;
    }
    
    protected Entry<String, String> createEntry(final String str){
        final String[] keyValue = str.split("=");
        
        if (keyValue.length == 2 && !"".equals(keyValue[0]) && !"".equals(keyValue[1])){
            final String key = this.decode(keyValue[0]);
            final String value = this.decode(keyValue[1]);
            return new AbstractMap.SimpleEntry<String, String>(key, value);
        }
        
        return null;
    }
    
    protected String encode(final String str){
        return str.replaceAll(",", "&#44").replaceAll("=", "&#61");
    }
    
    protected String decode(final String str){
        return str.replaceAll("&#44", ",").replaceAll("&#61", "=");
    }

    protected boolean isValid(final String cookieValue){
        final Map<String, String> parameters = this.convertCookieValueToParameter(cookieValue);
        boolean valid = false;
        
        try{
            
            if (parameters.containsKey(CHECKSUM_KEY)){
                final String checksum = parameters.get(CHECKSUM_KEY);
                parameters.remove(CHECKSUM_KEY);
                
                String data = this.parametersToString(parameters);
                
                if (!(data == null && "".equals(data))){
                    valid = CryptoUtils.hmacSha1(this.hmacSHA1Key, data).equals(checksum);
                }
                
            }
        
        } catch (final InvalidKeyException  e){
            valid = false;
        }
        
        return valid;
    }

}
