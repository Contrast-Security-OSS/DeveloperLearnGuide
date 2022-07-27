---
layout: default
title: Cookie Weakness
nav_order: 7
---

# Cookie Weakness
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Cookie Manipulation

### Overview
<br/>
The process of tampering with cookies with the goal of bypassing security measures or sending false information to the server, is called cookie manipulation.

A successful exploit can allow unauthorized access to the victim's account, either by poisioning the original cookie value, or tricking the server into accepting a new version of the initial cookie with modified values.


### Impact 
<br/>
- For cookies that control behaviour from user actions, a malicious actor may be able to manipulate the cookie's value in order to perform unintended actions on behalf of the user.
- For session tracking cookies, the attacker may be able to leverage a session fixation attack. 
This attack works by using a valid token within the cookie parameter, and hijacking the user's next interaction with the site. The risk of this can range from privacy concerns to takeover of user's account.



### Prevention
<br/>

- Ensure you restrict data from untrusted sources dynamically writing to cookies.

- Always apply appropriate sanitization to all incoming data to protect your application.


## Cookie Flags  
<br/>

Ensuring the `secure` and `httponly` flags are set in your Cookie headers prevents prevents the browser from sending them over a connection that isn't encrypted with SSL or TLS.  When code generates a cookie without setting the secure flag, this creates the possibility that an attacker could gain access to it on an unencrypted connection. 

If this cookie is used for authentication or session management, disclosing it could allow account hijacking. Other cookies may also be sensitive and should not be disclosed.  Note that an attack called sidejacking tricks browsers into using unencrypted connections even if your site generally uses encryption. 


### .NET 
<br/>

The `secure` and `httponly` flags can be enabled for all application cookies via the `web.config` using the [httpCookies](https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection?view=netframework-4.8) section. 

For example:

```xml
<configuration>
  <system.web>
    <httpCookies httpOnlyCookies="true" requireSSL="true" />
  </system.web>
</configuration>
```

For custom cookies under ASP.NET MVC, the  cookie flags can be set programmatically on the [class](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie?view=netframework-4.8):


```csharp
HttpCookie myCookie = new HttpCookie("myCookie")
{
    Secure = true,
    HttpOnly = true
}
Response.AppendCookie(myCookie);
```

Alternatively, under ASP.NET Web API 2, the cookie flags can be set programmatically on the [object](https://docs.microsoft.com/en-us/previous-versions/aspnet/hh944846(v%3Dvs.118)). 

For example:

```csharp
public HttpResponseMessage GetValue()
{
    var myCookie = new CookieHeaderValue("myCookie", "myCookieValue")
    {
        Secure = true,
        HttpOnly = true
    };

    var responseMessage = new HttpResponseMessage();
    responseMessage.Headers.AddCookies(new[] { myCookie });
    return responseMessage;
}
```

### .NET Core
<br/>

Under ASP.NET Core, the `secure` and `httponly` cookie flags may be set globally during the [method](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/startup?view=aspnetcore-6.0) of the `Startup` class using {{#link}}https://docs.microsoft.com/en-us/aspnet/core/fundamentals/startup$$LINK_DELIM$$Startup.ConfigureServices{{/link}} method of the 'Startup' class using the [CookiePolicyOptions](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.cookiepolicyoptions?view=aspnetcore-6.0) class. 

For example:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.Configure<CookiePolicyOptions>(options =>
    {
        options.HttpOnly = HttpOnlyPolicy.Always;
        options.Secure = CookieSecurePolicy.Always;
    });
}
```


These options can also be set programatically using [CookieOptions](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions?view=aspnetcore-6.0) class. 

For example:
<br/>

```csharp
var options = new CookieOptions
{
    HttpOnly = true,
    Secure = true
};
Response.Cookies.Append("myCookieName", "myCookieValue", options);
```

### Java 
<br/>
Remediating this issue in Java is simple.  

Ensure that the `javax.servlet.http.Cookie#setSecure()` method is called for this cookie with a parameter of "true". 