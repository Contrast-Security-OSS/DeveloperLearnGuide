---
layout: default
title: Open Redirection
nav_order: 14
---

# Open Redirection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
# Unvalidated Redirects 
<br/>
An unvalidated redirect occurs when a web application is manipulated into redirecting a user to a URL, under the control of an attacker, e.g. http://`examplesite.com/path?url=http://partner.com/`. 

This could be used to greatly increase the likelihood of success of a phishing campaign

If redirection is successful, it may be possible to escalate this vulnerability into a JavaScript injection.

It may even be possible to introduce XSS, depending on the circumstances (like if the victim's browser supports redirecting to [specified](https://code.google.com/archive/p/browsersec/wikis/Part2.wiki#Redirection_restrictions) protocols.

## How To Fix 
<br/>
There are a few good ways to address this issue:

- **Use maps to filter out invalid values**  
Instead of accepting input like `url=string`, accept `partner=int`. That `int` can be a key in a Map that points to an allowed value. 
If the map has no corresponding value for the key given, then throw an error. 
- **Strongly validate the URL**  
Ensure that the targeted URL belongs to an expected destination. Many naive implementations will do something similar to this unsafe pattern: 

### Java
<br/>

- Example  

```java
String url = request.getParameter("url");
if(!url.startsWith("http://expected-domain.com")) {
   response.sendRedirect(url);
}
```

An attacker can create their own subdomain at `expected-domain.com.attacker-website-here` and pass the validation. A stronger validation would be to create a `java.net.URL` of the given String, and validate that the URL's value returns exactly what's expected: 

```java
try {
    URL url = new URL(request.getParameter("url"));
    if(url.getHost().equals("expected-domain.com")) {
        response.sendRedirect(url.toString());
    }
} catch (MalformedURLException e) {
    logger.log("Bad URL given", e);
}
```

### .NET 
<br/>

- Example 

```csharp
// C#:
String url = Request.QueryString("url");
if (!url.startsWith("http://expected-domain.com")) {
	Response.Redirect(url);
}
```

An attacker can create their own subdomain at `expected-domain.com.attacker-website-here` and pass the validation. A stronger validation would be to create a `System.Uri` of the given String, and validate that the URL's `Host` value returns exactly what's expected: 

```csharp
// C#:
Uri uri = new Uri(Request.QueryString("url"));
if (uri.Host.Equals("expected-domain.com")) {
	Response.Redirect(uri);
}
```

### .NET Core
<br/>

- Example  

```csharp
String url = HttpContext.Request.Query("url");
if (!url.startsWith("http://expected-domain.com")) {
	Response.Redirect(url);
}
``` 


An attacker can create their own subdomain at `expected-domain.com.attacker-website-here` and pass the validation. A stronger validation would be to create a `System.Uri` of the given String, and validate that the URL's `Host` value returns exactly what's expected:

```csharp
// C#:
Uri uri = new Uri(HttpContext.Request.Query("url"));
if (uri.Host.Equals("expected-domain.com")) {
	Response.Redirect(uri);
}
```

### Node
<br/>

```js
app.get('/foo', function(req, res, next) {
    var url = req.query.url;
    if(!url.indexOf('http://expected-domain.com') === 0) {
        res.redirect(url);
    }
});
``` 

An attacker can create their own subdomain at `expected-domain.com.attacker-website-here` and pass the validation. A stronger validation would be to create a `url` of the given String, and validate that the URL's `hostname` value using the built-in [module](https://nodejs.org/api/url.html#url_url) to validate that it is what's expected: 

```js
var url = require('url');
app.get('/foo', function(req, res, next) {
var inputUrl = url.parse(req.query.url),
expectedHost = url.parse('http://expected-domain.com').hostname;

if(input.hostname === expectedHost) {
res.redirect(inputUrl);
}
});
```

### Ruby
<br/>

```ruby
url = params['url']
if url.start_with?('http://expected-domain.com')
  redirect_to url
```

An attacker can create their own subdomain at `expected-domain.com.attacker-website-here` and pass the validation. A stronger validation would be to create a `Uri` of the given String, and validate that the URL's value returns exactly what's expected: 

```ruby
url = params['url']
uri = Uri.new(url)
if url.host == 'expected-domain.com'
  redirect_to url
```

### Python
<br/>

```python
if url.startswith('http://expected-domain.com'):
    redirect(url)
```

An attacker can create their own subdomain at `expected-domain.com.attacker-website-here` and pass the validation. A stronger validation would be to create a `urllib.parse.ParseResult` object using `urllib.parse.urlparse` (just `urlparse.urlparse` in Python 2.7) of the given String, and validate that the URL's property returns exactly what's expected:
   
```python
parsed = urllib.parse.urlparse(url) # urlparse.urlparse(url) in Python 2.7
if parsed.netloc == 'expected-domain.com':
    redirect(url)
```



# Unvalidated Forwards 
<br/>

An unvalidated forward occurs when the application takes input from the user, and uses it to build a file path to which the user is forwarded. If a user 
controls a part of that path, they may be able to direct themselves to sensitive files, like `/WEB-INF/web.xml`, application code, or configuration files, which may contain passwords. 

## How To Fix 

### Java 
<br/>

Your Java application is at risk if it takes a value from the user and performs an internal forward using that value as a destination. 
As discussed in the summary, this can lead to sensitive data exposure. There's probably some code in your application that looks like this: 

```java
String target = request.getParameter("target");
request.getRequestDispatcher(target).forward(request, response);
```

If a user passes a querystring like the following, they may get access to important application details: `http://examplesite.com/app/vulnerable.do?target=/WEB-INF/web.xml` 

This can also lead to server-side code disclosure, too: 
`http://examplesite.com/app/vulnerable.do?target=/WEB-INF/classes/org/yoursite/app/YourClass.class`

Forwarding to internal resources is dangerous. It can be abused to get to files that should never be served, like `web.xml`. It can also bypass authentication and access controls enforced by 3rd party systems like SiteMinder or WebSEAL. If the functionality can't be abstracted away from the `RequestDispatcher`, the value that is user supplied should be thoroughly validated. For instance, if the user is only allowed to access XML files in /data/, your code could look like this: 

```java
Pattern p = Pattern.compile("^/data/[A-Za-z0-9]+\\.xml$");
String target = request.getParameter("target");
if( p.matcher(target).matches() ) {
    request.getRequestDispatcher(target).forward(request, response);
} else {
    response.sendError(404);
}
```


### .NET 
<br/>

Users may be able to bypass IIS and ASP.NET's authentication and authorization checks if a user controls a part of that path.  IIS and ASP.NET do not perform authorization checks for the target page of the [transfer](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpserverutility.transfer?view=netframework-4.8) and [execute](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpserverutility.execute?view=netframework-4.8) methods
That is, authorization modules (such as `FileAuthorizationModule` or `UrlAuthorizationModule`) that occur earlier in the ASP.NET pipeline are executed for the initial page but the `Transfer()` and `Execute()` methods pass execution to a new handler without re-executing steps earlier in the pipeline. 


Let's walkthrough a vulerable example:

```csharp
String target = Request.QueryString("target");
Server.Transfer(target);
```

If a user passed a querystring like the following, they may get access to sensitive parts of the application:
`http://examplesite.com/app/vulnerable.aspx?target=/admin/admin.aspx`

Transferring to internal resources is dangerous. It can also bypass authentication and access controls as `Transfer()` and `Execute()` do not trigger ASP.NET's authentication and authorization checks on the destination page. There are three primary ways to resolve this issue: 

- The functionality/application logic should be abstracted away from the use of `Transfer()` and `Execute()`.{
- IIS and ASP.NET authorization can be triggered by using Response.Redirect rather than the `Transfer()`or `Execute()` methods. 
Ideally the target of Response.Redirect should not include user data (in order to avoid unvalidated redirect vulnerabilities) or if they must include user data, then this data should be thoroughly validated.
- If the application functionality must use `Transfer()` or `Execute()`, the user-supplied value should be thoroughly validated. For instance, if the user is only allowed to access aspx files in /data/, your code could look like this: 

```csharp
// C#:
Regex p = new Regex("^/data/[A-Za-z0-9]+\\.aspx$");
String target = Request.QueryString("target");
if ( p.IsMatch(target) ) {
Server.Transfer(target);
} else {
// process error
}
```
