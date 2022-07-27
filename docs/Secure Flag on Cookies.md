---
layout: default
title: Missing Secure Flag on Cookies
nav_order: 14
---

# Missing Secure Flag on Cookies
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
# Overview 
<br/> 
The "secure" flag (e.g., "cookieName=cookieValue; secure") prevents cookies from being transmitted using standard HTTP in modern browsers. 

Set the secure flag on the session cookie when it is generated. This can frequently be done through a simple application 
server configuration change. 

## Set by Language 

### Java 
<br/> 
The "secure" flag can be enabled for all session cookies by editing the web.xml to include: 

```xml
<session-config>
 <cookie-config>
  <secure>true</secure>
 </cookie-config>
</session-config>
``` 

The "secure" flag can also be enabled for the session cookie or other cookies programmatically in Java like so:

```java
Cookie cookie = new Cookie("JSESSIONID", session.getId());

cookie.setSecure(true);
``` 

### .NET 
<br/> 
The "secure" flag can be enabled for all application cookies via the Web.config in the `system.web/httpCookies` element:

```xml
<httpCookies requireSSL="true"/>
``` 

For custom cookies, the "secure" flag can be enabled programmatically in C# like so: 

```csharp
HttpCookie myCookie = new HttpCookie("myCookie");
myCookie.Secure = true;
Response.AppendCookie(myCookie);
``` 

### Node 
<br/> 

If using the Express framework, the [cookie-session](https://www.npmjs.com/package/cookie-session) middleware can be used to enable the secure flag for session cookies:

```js
var session = require('cookie-session')
var express = require('express')
var app = express()

var expiryDate = new Date(Date.now() + 60 * 60 * 1000) // 1 hour
app.use(session({
  name: 'session',
  keys: ['key1', 'key2'],
  cookie: {
    secure: true,
    httpOnly: true,
    domain: 'example.com',
    path: 'foo/bar',
    expires: expiryDate
  }
}))
```

### Ruby 
<br/> 
If using Rails, the [SSL](https://edgeapi.rubyonrails.org/classes/ActionDispatch/SSL.html) config parameter can be used to enable the secure flag for session cookies: 

```ruby
config.force_ssl = true
```

### Python 
<br/> 
Django is configured in application's `settings.py` file:

```python
# settings.py
SESSION_COOKIE_SECURE = True
``` 

Flask is configured using the application's `config` object: 

```python
app.config["SESSION_COOKIE_SECURE"] = True
``` 

Pyramid is configured by the `secure` parameter of the session cookie factory: 

```python
session = pyramid.session.SignedCookieSessionFactory(..., secure=True)
``` 

Pylons is configured by the `secure` parameter of the session constructor: 

```python
session = beaker.session.Session(..., secure=True)
```