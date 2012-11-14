package com.ctlok.web.session;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * @author Lawrence Cheung
 *
 */
public interface StatelessSession {

    public String getSessionId();
    public void flush();
    public int size();
    public boolean isEmpty();
    public boolean containsKey(String key);
    public boolean containsValue(String value);
    public String get(String key);
    public String put(String key, String value);
    public String remove(String key);
    public void putAll(Map<String, String> map);
    public Set<String> keySet();
    public Collection<String> values();
    public void clear();
    
}
