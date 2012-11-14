package com.ctlok.web.session;

import java.util.Map;

public interface SessionMap extends Map<String, String> {

    public String toCookieValue();
    
}
