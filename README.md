## HTTP Stateless Session for Java

HTTP Stateless Session help you to build stateless web application base on Java.
Stateless Session compliable with `HttpSession`.

What are the benefits of a stateless web application?

1. Reduces memory usage.
2. Easier to support server farms.
3. Reduce session expiration problems.

Reference: [http://stackoverflow.com/questions/5539823/what-are-the-benefits-of-a-stateless-web-application] (http://stackoverflow.com/questions/5539823/what-are-the-benefits-of-a-stateless-web-application)

### Limitation

1. Data total size cannot over 4KB, because all session data is storded in cookie. 
2. Data type must be String.

## Basic Usage

### Dependency: 

* commons-codec 1.7 or above
* gson 2.2.2 or above

### Basic Web.xml Config

```
<filter>
    <filter-name>statelessSessionFilter</filter-name>
    <filter-class>com.ctlok.web.session.StatelessSessionFilter</filter-class>
    <init-param>
        <param-name>HMAC_SHA1_KEY</param-name>
        <param-value>aDg3uE6t8X57bnFwcqRql8tvd</param-value>
    </init-param>
</filter>

<filter-mapping>
    <filter-name>statelessSessionFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

`HMAC_SHA1_KEY` is a mandatory field for check session data is it modified. 
If session data was modified by client, all session data will destroy and create a new session.

### Other Config

1. `ENCRYPTION_SECRET_KEY` is a secret key to encrypt session data. By default, session data is not encrypted.
2. `ENCRYPTION_IMPL_CLASS` is a class name implemented `com.ctlok.web.session.crypto.Encryptor`. Default: `com.ctlok.web.session.crypto.AesEncryptor`.
3. `SESSION_NAME` is a session cookie name. Default: `SESSION`.
4. `SESSION_MAX_AGE` is a session cookie max age. Default: `-1` expire when browser closed.
5. `SESSION_PATH` is a session cookie path on current domain. Default: `/`.
6. `SESSION_DOMAIN` is a session cookie domain. Default is null.

### Java Code Example

```
HttpSession session = request.getSession(true);
session.setAttribute("user", "lawrence");
session.getAttribute("user");
```