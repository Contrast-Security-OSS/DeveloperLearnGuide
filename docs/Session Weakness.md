---
layout: default
title: Session Weakness
nav_order: 12
---

# Session Weakness
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Session Cookie No HTTPOnly Flag


### Overview 

If your application does not specify the HTTPOnly flag for session cookies, it is vulnerable to attack. 

In most browsers, the HTTPOnly flag prevents a user's cookie from being accessed by various client side scripts, including malicious scripts inserted by Cross-Site Scripting (XSS) attacks. 

Setting this cookie attribute does not eliminate XSS vulnerabilities, but does reduce the likelihood that an XSS vulnerability can be used to extract valuable application based session and/or authentication cookies from the victim's browser.


### Impact 

This type of vulnerability is often used in a chain-attack, for example XSS. 
For more information, please visit our guide on: [Cross Site Scripting](/io/DeveloperLearnGuide/Cross Site Scripting (XSS)/Overview)


### Python  


Django is configured in application's ```settings.py``` file: 

```python
# settings.py
SESSION_COOKIE_HTTPONLY = True
``` 

**Flask** is configured using the application's ```config``` object:  

```python
app.config["SESSION_COOKIE_HTTPONLY"] = True
``` 

**Pyramid** is configured by the ```httponly``` parameter of the session cookie factory:  

```python
session = pyramid.session.SignedCookieSessionFactory(..., httponly=True)
``` 


**Pylons** is configured by the ```httponly``` parameter of the session constructor: 

```python
session = beaker.session.Session(..., httponly=True) 
``` 

### .NET  

Set the `HTTPOnly` flag on the session cookie when the cookie is generated. The `HTTPOnly` flag (e.g. `cookieName=cookieValue; httpOnly`) will prevent cookies from being accessed by scripts in modern browsers:
- Internet Explorer 6 SP 1+
- FireFox 2.0.0.6+
- Opera 9.5+
- Chrome 1.0+

In modern versions of ASP.NET, the `HTTPOnly` flag is set on `ASP.NET_SessionId` cookies by default.

If the flag is not enabled in your environment, `HTTPOnly` can be enabled by configuring all application cookies using  the [`system.web/httpCookies`](https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.httponlycookies) section in the `web.config`: 

```xml
<configuration>
  <system.web>
    <httpCookies httpOnlyCookies="true" />
  </system.web>
</configuration>
```

For custom cookies, `HttpOnly` should be enabled programmatically using the [HttpCookie](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie).[HttpOnly](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie.httponly) property: 

```csharp
HttpCookie customCookie = new HttpCookie("customCookie");
customCookie.HttpOnly = true;
```

### .NET Core 

By default, the session cookie used in ASP.NET Core (which defaults to `.AspNetCore.Session`), has the `HttpOnly` flag set. If this rule was triggered, consider ensuring that that the [CookieBuilder](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookiebuilder).[HttpOnly](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookiebuilder.httponly) property is set to `true` during service configuration.

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddSession(options =>
    {
        // options.Cookie.HttpOnly = false; // Vulnerable
        options.Cookie.HttpOnly = true; // Safe
    });
}
``` 

For custom cookies, `HttpOnly` should be enabled programmatically using the [CookieOptions](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions).[HttpOnly](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions.httponly) property: 


```csharp
CookieOptions option = new CookieOptions
{
    HttpOnly = true
};

Response.Cookies.Append("cookie-name", "cookie-value", option); 
```

### Ruby

Change the `HttpOnly` value to `true` or remove the attribute. 
By default, this setting is true and all cookies issued by the application will have the HTTPOnly flag. 

```ruby
Demo::Rack::Application.config.session_store :cookie_store,
                                              httponly: true
```

## Session Rewriting

### Overview 

If your application allows browsers that don't support cookies to rewrite session IDs into the URL, it is vulnerable to attack. 

The first, most basic problem is that the session ID, which is as good as a username and password, is logged in the following places, which log the complete URL: 
	- Browser history
	- Server logs
	- Proxy logs 

They'll also be sent in the "Referer" header to any off-site resources in pages. 
Normally, session IDs are a secret. If an attacker can steal a victim's session ID, they'll be recognized as the victim to the server. 

Many developers assume that some network control like IP restrictions, user-agent fingerprinting, or something else will prevent an attacker from using a session ID stolen from the victim. 

There is almost never such a compensating control, and thus session IDs must be protected. 

Although the overexposure in the various log files is undesirable, it may not appear to be a serious issue. The bigger problem with session rewriting is that it allows an attack called Session Fixation. 

**Session Fixation** is an umbrella term for any attack that can allow an attacker to cause a victim to use a session ID that they know. 
If the victim then authenticates under the attacker's chosen session ID, they can present the same session ID to the server and be recognized as the victim. 

Let's walkthrough a simple example:

- User A visits the site `http://demo.example.com/`
- Server responds with Set-Cookie: `SID=0F2571EFA941B2`
- User A sends User B a message: "Hey, take a look at this demo! http://demo.example.com/?SID=0F2571EFA941B2"
- User B clicks on link, and is now logged in with with fixated session identifier `SID=0F2571EFA941B2`


### Impact 

When successfully exploited, the risk can range from unauthorized access to sensitive data and privileges, ultimately ompromising the confidentiality, integrity, and availability of your application. 


### Java 

Until the Java Servlet Specification (JSS) 3.0, the disabling of URL rewriting were all container-specific. 
Our advice is arranged into two sections - recommendations for JSS 3.0 compatible applications, and recommendations for everyone else. 

**Disabling URL Rewriting in Java Servlet Specification 3.0 Compatible Container** 

1. You can disable session rewriting by adding this snippet to your web.xml: 

```xml
<session-config>
	<tracking-mode>COOKIE</tracking-mode>
</session-config>
``` 

2. You can also set this value programmatically:

```java
ServletContext sc = request.getSession().getServletContext();
	sc.setSessionTrackingModes(EnumSet.of(SessionTrackingMode.COOKIE));
``` 

**Disabling URL Rewriting in non-JSS 3.0 Containers** 

1. Use your container's specific method for preventing URL rewriting. Most major containers support this feature in one way or another. For example, here's how you do it in Tomcat 6: 

```xml
<?xml version='1.0' encoding='utf-8'?>
<Context docBase="/acme" path="/AcmeWidgets" disableURLRewriting="true">
  ...
</Context>{
``` 

2. Use your own HttpServletResponseWrapper subclass. Here's an [example](https://github.com/ESAPI/esapi-java) from the ESAPI project that prevents URLs from being rewritten by overriding `encodeURL()`: 

```java
 * Return the URL without any changes, to prevent disclosure of the
 * Session ID. The default implementation of this method can add the
 * Session ID to the URL if support for cookies is not detected. This
 * exposes the Session ID credential in bookmarks, referer headers, server
 * logs, and more.
 *
 * @param url
 * @return original url
 */
public String encodeURL(String url) {
	return url;
}
``` 

3. If using Spring, utilize the `disable-url-rewriting` attribute in your `http` bean definition: `<security:http auto-config="false" use-expressions="true" disable-url-rewriting="true">`

**Note:** 

It's also a good idea to rotate the user's session ID after they've logged in. That way, if an attacker has compromised or seeded the session in any way, only the user who just proved they are who they say they are (via authentication) will have continued access.  
This won't affect the user. Rotating the session ID in Java EE applications is fairly easy: 

```java
request.getSession().invalidate();
request.getSession(true);
``` 


### .NET 

The .NET framework implements session management via the `&lt;sessionState&gt;` directive in Web.config. 
Using the attribute `cookieless="true"`, the session token will be stored in the URL instead of a cookie. 
We recommend setting the `cookieless` option to `UseCookies`(.NET v2.0 or newer) to force all session management to be provided using cookies. 
For .NET's AJAX client libraries, the attribute must be set to `UseCookies`. 
Here is an example of Web.config set to use cookies: 

```csharp
<sessionState
	cookieName="MySiteToken"
	timeout="30"
	cookieless="UseCookies"
	...
	>

	<providers> ... </providers>
</sessionState>
``` 

**Note:** 

It's also a good idea to rotate the user's session ID after they've logged in. That way, if an attacker has compromised or seeded the session in any way, only the user who just proved they are who they say they are (via authentication) will have continued access. This won't affect the user. 

Unfortunately, rotating the session ID in ASP.NET applications is more difficult than it needs to be. You can't simply force .NET to create a new session. 

Instead you have to do two things as described in this [article](https://stackoverflow.com/questions/12148647/generating-new-sessionid-in-asp-net) on Generating New SessionIDs in ASP.NET, and these steps need to be done on the login page itself so when the user logs in, they won't have a session. 
With no session, a brand new session (and `sessionID`) will be created when the user actually completes the login process. 

```csharp
Session.Abandon();  // This destroys the existing session
Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", "")); // This erases the session cookie out of the browser.
``` 

**Note:** 

Without clearing the old session cookie out of the browser, the browser will present it to the server as part of the Login request and the server will create a new session, but adopt the old session ID presented by the cookie. 

This thwarts the whole point of rotating the session ID, which is why this second line is required. 

Also note that this simplistic solution completely loses all state during the rotatio process. If you need to retain user state across this session rotation, then you'll have to create a separate temporary cookie, and store the session state on the server in a place referenced by this cookie. 
Once the new session is created, copy the session state back from this temporary location into the new session. 


## Session Timeout

### Overview 
<br/>
If an application has specified a session timeout value greater than 30 minutes, it is vulnerable to attack. 
Most sensitive applications in banking, trading and other sensitive industries tend to specify session timeouts between 15 and 30 minutes. 
Longer session timeouts make it easier for cross-user web attacks like Cross-Site Request Forgery (CSRF) and Cross-Site Scripting (XSS) more likely to be successful, because users' sessions, which attackers require to be active for their exploits to work, are around longer. 

Your value should depend on how your users use the application. Consider the following questions when deciding your timeout value: 

- Do your users use this application from work, home or both? 
- Would a user use this application from a kiosk? A friend's computer?
- Is there financial incentive for a random person who stumbles upon a user's logged in session?
- How critical is this application to the business? To your users' life or well-being? 


### Impact
<br/>
This type of vulnerability is often used in a chain-attack, for example XSS. 
For more information, please visit our guide on: [Cross Site Scripting](/io/DeveloperLearnGuide/Cross Site Scripting (XSS)/Overview) or [Cross Site Request Forgery](/io/DeveloperLearnGuide/Cross Site Request Forgery/Overview)

### Java 

Decreasing your session timeout is easy. 
Simply specify a reasonable `session-timeout` value in your application's /WEB-INF/web.xml file, like in this example: 

```java
        <session-timeout>30</session-timeout>
</session-config>
```

### .NET 

Specify a reasonable `sessionState.timeout` value in your application's Web.config file, like in this example: 

```csharp
<sessionState timeout="30" cookieless="UseCookies" ... >
	<providers> ... </providers>
</sessionState>
``` 

If the session timeout is increased programmatically inside of a page, by using `Session.Timeout = 60` for example, then
ensure the timeout value is not excessive. 


### .NET Core 

Specify a reasonable `IdleTimeout` value in your application's `SessionOptions`, like in this example: 

```csharp
services.AddSession(options => {
	options.IdleTimeout = TimeSpan.FromMinutes(30);
});
``` 

### Node 

The node.js built-in http module is stateless and has no notion of sessions or session variables, however frameworks such as [express](https://www.npmjs.com/package/express) are built on top of http and provide useful abstractions such as sessions, and can allow you to set session timeout values similarly to this: 

```js
app.use(express.session({
    secret  : 'someSecretSessionKey',
    cookie  : { maxAge  : new Date(Date.now() + (60 * 1000 * 30)) },
    expires  : new Date(Date.now() + (60 * 1000 * 30))
}));
``` 

### Ruby 


Specify a reasonable value in your application's configuration, like in this example: 

```ruby
Demo::Rack::Application.config.session_store :cookie_store,
                                              expire_after: 1000 * 60 * 30
``` 


### Python 

Each framework provides a different way for configuring session timeout values. 
For the given framework, simply set the timeout to a value representing 30 minutes or less. 
In most cases, this will be a value representing seconds.

**Django** is configured in application's `settings.py` file:

```python
# settings.py
SESSION_COOKIE_AGE = 15 * 60  # value represents seconds
``` 
<br/>


**Flask** is configured using the application's `config` object: 

```python
app.config["PERMANENT_SESSION_LIFETIME"] = 15 * 60  # value represents seconds
# flask also allows the use of timedelta
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=15)
``` 
<br/>
**Pyramid** is configured by the `timeout` parameter of the session cookie factory: 

```python
session = pyramid.session.SignedCookieSessionFactory(..., timeout=15*60)
``` 
<br/>
- **Pylons** is configured by the `timeout` parameter of the session constructor: 

```python
session = beaker.session.Session(..., timeout=15*60)
``` 


## How can Contrast help? 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect these vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block these attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.


