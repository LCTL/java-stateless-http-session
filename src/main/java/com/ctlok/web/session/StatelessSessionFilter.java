package com.ctlok.web.session;

import java.io.IOException;
import java.security.InvalidKeyException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.ctlok.web.session.crypto.CryptoUtils;
import com.ctlok.web.session.crypto.Encryptor;

/**
 * @author Lawrence Cheung
 *
 */
public class StatelessSessionFilter implements Filter {

    private static final String PARAM_HMAC_SHA1_KEY = "HMAC_SHA1_KEY";
    private static final String PARAM_ENCRYPTION_SECRET_KEY = "ENCRYPTION_SECRET_KEY";
    private static final String PARAM_ENCRYPTION_IMPL_CLASS = "ENCRYPTION_IMPL_CLASS";
    
    private static final String PARAM_SESSION_NAME = "SESSION_NAME";
    private static final String PARAM_SESSION_MAX_AGE = "SESSION_MAX_AGE";
    private static final String PARAM_SESSION_PATH = "SESSION_PATH";
    private static final String PARAM_SESSION_DOMAIN = "SESSION_DOMAIN";
    private static final String PARAM_SESSION_HTTP_ONLY = "HTTP_ONLY";
    
    private static final String DEFAULT_ENCRYPTION_IMPL_CLASS = "com.ctlok.web.session.crypto.AesEncryptor";
    
    private static final String DEFAULT_SESSION_NAME = "SESSION";
    private static final String DEFAULT_SESSION_MAX_AGE = "-1";
    private static final String DEFAULT_SESSION_PATH = "/";
    private static final String DEFAULT_SESSION_DOMAIN = null;
    private static final String DEFAULT_SESSION_HTTP_ONLY = "true";
    
    private FilterConfig filterConfig;
    private String hmacSha1Key;
    private String secretkey;
    private Encryptor encryptor;
    
    private String sessionName;
    private int sessionMaxAge;
    private String sessionPath;
    private String sessionDomain;
    private boolean httpOnly;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
        
        this.hmacSha1Key = filterConfig.getInitParameter(PARAM_HMAC_SHA1_KEY);
        if (this.hmacSha1Key == null){
            throw new ServletException("HMAC_SHA1_KEY is mandatory value");
        }
        
        try {
            CryptoUtils.hmacSha1("test", this.hmacSha1Key);
        } catch (InvalidKeyException e) {
            throw new ServletException("Invalid HMAC_SHA1_KEY", e);
        }
        
        this.secretkey = filterConfig.getInitParameter(PARAM_ENCRYPTION_SECRET_KEY);
        
        if (this.secretkey != null){
            final String className = this.getConfig(filterConfig, PARAM_ENCRYPTION_IMPL_CLASS, DEFAULT_ENCRYPTION_IMPL_CLASS);
            try {
                this.encryptor = (Encryptor) Class.forName(className).newInstance();
                
                if (!isValidEncryptor()){
                    throw new IllegalStateException("Not a valid encryptor");
                }
            } catch (final Exception e) {
                throw new ServletException("Create encryptor occur problem", e);
            }
        }
        
        this.sessionName = this.getConfig(filterConfig, PARAM_SESSION_NAME, DEFAULT_SESSION_NAME);
        this.sessionMaxAge = Integer.valueOf(this.getConfig(filterConfig, PARAM_SESSION_MAX_AGE, DEFAULT_SESSION_MAX_AGE));
        this.sessionPath = this.getConfig(filterConfig, PARAM_SESSION_PATH, DEFAULT_SESSION_PATH);
        this.sessionDomain = this.getConfig(filterConfig, PARAM_SESSION_DOMAIN, DEFAULT_SESSION_DOMAIN);
        this.httpOnly = Boolean.valueOf(this.getConfig(filterConfig, PARAM_SESSION_HTTP_ONLY, DEFAULT_SESSION_HTTP_ONLY));
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp,
            FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) resp;
        
        final StatelessSessionConfig sessionConfig = createStatelessSessionConfig(request, response);
        final HttpServletRequest requestWrapper = new RequestWrapper(request, sessionConfig);

        chain.doFilter(requestWrapper, response);
        
    }
    
    protected StatelessSessionConfig createStatelessSessionConfig(
            final HttpServletRequest request,
            final HttpServletResponse response){
    
        return new StatelessSessionConfig(this.filterConfig.getServletContext(), 
                            request, response, this.hmacSha1Key,
                            this.secretkey, this.encryptor,
                            this.sessionName, this.sessionMaxAge,
                            this.sessionPath, this.sessionDomain,
                            this.httpOnly);
        
    }

    @Override
    public void destroy() {

    }

    protected String getConfig(final FilterConfig filterConfig, 
            final String name, final String defaultValue){
        
        String value = filterConfig.getInitParameter(name);
        
        if (value == null){
            value = defaultValue;
        }
        
        return value;
    }
    
    protected boolean isValidEncryptor() throws Exception{
        final String data = "test";
        final String encryptedString = this.encryptor.encrypt(this.secretkey, data);
        
        if (this.encryptor.decrypt(this.secretkey, encryptedString).equals(data)){
            return true;
        }else{
            return false;
        }
    }
    
    static class RequestWrapper extends HttpServletRequestWrapper{

        private final HttpServletRequest request;
        private final StatelessSessionConfig sessionConfig;
        
        private HttpSession session;
        
        public RequestWrapper(final HttpServletRequest request,
                final StatelessSessionConfig sessionConfig) {
            super(request);
            this.request = request;
            this.sessionConfig = sessionConfig;
            
            if (isSessionCookieExist(sessionConfig.getSessionName())){
                this.session = createStatelessSession(sessionConfig);
            }
        }

        @Override
        public HttpSession getSession(boolean create) {
            if (create && this.session == null){
                this.session = new StatelessSession(this.sessionConfig);
            }
            return session;
        }

        @Override
        public HttpSession getSession() {
            return this.session;
        }
        
        protected HttpSession createStatelessSession(final StatelessSessionConfig sessionConfig){
            return new StatelessSession(this.sessionConfig);
        }
        
        private boolean isSessionCookieExist(final String sessionName){
            boolean result = false;
            
            if (request.getCookies() != null){
            
                for (final Cookie cookie: request.getCookies()){
                    if (cookie.getName().equals(sessionName)){
                        result = true;
                        break;
                    }
                }
            
            }
            
            return result;
        }

    }

}
