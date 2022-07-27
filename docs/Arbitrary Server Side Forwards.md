---
layout: default
title: Arbitrary Server Side Forwards
nav_order: 18
---

# Arbitrary Server Side Forwards
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-green }

## Arbitrary Server Side Forwards 

### Overview
<br/>
We categorize Arbritrary SSRF as a class of vulnerabilities that allow a web application to accept a modified input that could cause the web application to forward the request to as untrusted URL.

These type of attacks can act as a precursor, and as such, may be part of a chain attack.
Depending on the targeted user, the impact of this vulnerability can range from mild to severe. 

The malicious user may elevate this to other, more serious, attacks such as Cross Site Scripting (XSS),leading to sensitive data exposure.


## Arbitrary Server Side Forwards by Langugage

### Java 
<br/>
For applications running in Java, the application takes input from the user, and uses it to build a file path to which the user is forwarded. 
If a user controls a part of that path, they may be able to direct themselves to sensitive files, like ```/WEB-INF/web.xml```, application code, or configuration files, which may contain passwords. 


There's probably some code in your application that looks like this:

```java
String target = request.getParameter("target");
request.getRequestDispatcher(target).forward(request, response);
``` 

If a user passes a querystring like the following, they may get access to important application details:```http://yoursite.com/app/vulnerable.do?target=/WEB-INF/web.xml``` 

This can also lead to server-side code disclosure, too:```http://yoursite.com/app/vulnerable.do?target=/WEB-INF/classes/org/yoursite/app/YourClass.class``` 


Forwarding to internal resources is dangerous. It can be abused to get to files that should never be served, like ```web.xml```.
It can also bypass authentication and access controls enforced by 3rd party systems like SiteMinder 
or WebSEAL. 
If the functionality can't be abstracted away from the ```RequestDispatcher```, the value that is user 
supplied should be thoroughly validated. For instance, if the user is only allowed to access XML files in ```/data/```, your code 
could look like this:

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

For applications running in **.NET**, the application takes input from the user, and uses it to build a path to another page to which execution is transferred. Users can bypass IIS and ASP.NET's authentication and authorization checks if a user controls a part of that path. 
IIS and ASP.NET do not perform authorization checks for the target page of the Transfer() and Execute() methods. That is, authorization modules (such as ```FileAuthorizationModule``` or ```UrlAuthorizationModule```) that occur earlier in the ASP.NET pipeline are executed for the initial page but the ```Transfer()``` and ```Execute()``` methods pass execution to a new handler without re-executing steps earlier in the pipeline. 

For example, consider the following code: 

```csharp
String target = Request.QueryString("target");
Server.Transfer(target);
``` 

If a user passed a querystring like the following, they may get access to sensitive parts of the application: ```http://yoursite.com/app/vulnerable.aspx?target=/admin/admin.aspx``` 

Transferring to internal resources is dangerous 
It can also bypass authentication and access controls as ```Transfer()``` and ```Execute()``` do not trigger ASP.NET's authentication and authorization checks on the destination page. There are three primary ways to resolve this issue: 

- The functionality/application logic should be abstracted away from the use of ```Transfer()``` and ```Execute()```. 
- IIS and ASP.NET authorization can be triggered by using ```Response.Redirect``` rather than the ```Transfer()``` or ```Execute()``` methods. 
Ideally the target of Response.Redirect should not include user data (in order to avoid unvalidated redirect vulnerabilities) or if they must include user data, then this data should be thoroughly validated. 
- If the application functionality must use ```Transfer()``` or ```Execute()```, the user-supplied value should be thoroughly validated. 
For instance, if the user is only allowed to access aspx files in ```/data/```, your code could look like this:

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
<br/> 


```vb
' VB.NET:
Dim p As New Regex("^/data/[A-Za-z0-9]+\\.aspx$")
Dim target As String = Request.QueryString("target")
If ( p.IsMatch(target)) Then
Server.Transfer(target)
Else
' process error
End
``` 