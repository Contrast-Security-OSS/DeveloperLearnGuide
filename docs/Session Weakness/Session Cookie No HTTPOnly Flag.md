---
layout: page
title: Session Cookie No HTTPOnly Flag
permalink: /io/Session Weakness/Session Cookie No HTTPOnly Flag
parent: Session Weakness
nav_order: 1
---

## Session Cookie No HTTPOnly Flag


### What Is It?

If your application does not specify the HTTPOnly flag for session cookies, it is vulnerable to attack. 

In most browsers, the HTTPOnly flag prevents a user's cookie from being accessed by various client side scripts, including malicious scripts inserted by Cross-Site Scripting (XSS) attacks. 

Setting this cookie attribute does not eliminate XSS vulnerabilities, but does reduce the likelihood that an XSS vulnerability can be used to extract valuable application based session and/or authentication cookies from the victim's browser.


### Impact


This type of vulnerability is often used in a chain-attack, for example XSS. 
For more information, please visit our guide on: [Cross Site Scripting](/io/DeveloperLearnGuide/Cross Site Scripting (XSS)/Overview)



### Prevention 

### In Python 


Django is configured in application's ```settings.py``` file: 
```
# settings.py
SESSION_COOKIE_HTTPONLY = True
``` 

**Flask** is configured using the application's ```config``` object: 

```
app.config["SESSION_COOKIE_HTTPONLY"] = True
``` 

**Pyramid** is configured by the ```httponly``` parameter of the session cookie factory: 

```
session = pyramid.session.SignedCookieSessionFactory(..., httponly=True)
``` 


**Pylons** is configured by the ```httponly``` parameter of the session constructor: 

```
session = beaker.session.Session(..., httponly=True) 
``` 

### In .NET 

Set the `HTTPOnly` flag on the session cookie when the cookie is generated. The `HTTPOnly` flag (e.g. `cookieName=cookieValue; httpOnly`) will prevent cookies from being accessed by scripts in modern browsers:
- Internet Explorer 6 SP 1+
- FireFox 2.0.0.6+
- Opera 9.5+
- Chrome 1.0+

In modern versions of ASP.NET, the `HTTPOnly` flag is set on `ASP.NET_SessionId` cookies by default.

If the flag is not enabled in your environment, `HTTPOnly` can be enabled by configuring all application cookies using  the [`system.web/httpCookies`](https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.httponlycookies) section in the `web.config`:
```
<configuration>
  <system.web>
    <httpCookies httpOnlyCookies="true" />
  </system.web>
</configuration>
```

For custom cookies, `HttpOnly` should be enabled programmatically using the [HttpCookie](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie).[HttpOnly](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie.httponly) property:
```
HttpCookie customCookie = new HttpCookie("customCookie");
customCookie.HttpOnly = true;
```

### In .NET Core

By default, the session cookie used in ASP.NET Core (which defaults to `.AspNetCore.Session`), has the `HttpOnly` flag set. If this rule was triggered, consider ensuring that that the [CookieBuilder](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookiebuilder).[HttpOnly](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookiebuilder.httponly) property is set to `true` during service configuration.

```
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

```
CookieOptions option = new CookieOptions
{
    HttpOnly = true
};

Response.Cookies.Append("cookie-name", "cookie-value", option); 
```



### In Ruby

Change the `HttpOnly` value to `true` or remove the attribute. 
By default, this setting is true and all cookies issued by the application will have the HTTPOnly flag. 
```
Demo::Rack::Application.config.session_store :cookie_store,
                                              httponly: true
```




### How can Contrast help?

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect these vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block these attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.
