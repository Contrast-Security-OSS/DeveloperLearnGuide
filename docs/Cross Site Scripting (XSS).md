---
layout: default
title: Cross Site Scripting (XSS)
nav_order: 3
---

# Cross Site Scripting (XSS)
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Cross Site Scripting (XSS)

### Vulnerability
<br/>
Cross Site Scripting (XSS) occurs when an application takes untrusted data from an HTTP request (URL, URL parameters, form fields, headers, cookies, body) and write it to a web page without escaping properly for the HTML context (body, attribute, script, style, etc...). 

The data flow that untrusted data follows from an untrusted source to the HTTP response can often be quite complex, with application frameworks, business logic, data layers, libraries, and other complicated code paths that make XSS difficult to see.

There are three types:

**Reflected XSS** 

Reflected XSS occurs when a malicious script is sent to a user (typically in a URL), the user's browser forwards that attack to the vulnerable application, and the application sends the attack to the victim's browser, where it executes.

**Stored XSS** 

Also known as "Persistent XSS", this variant is often more dangerous than other types. Stored XSS occurs when an attacker sends a malicous script to a vulnerable application, which stores that data (perhaps in a database). Later, the attack is sent back to the victim's browser in the course of regular browsing, where it executes.

**DOM-based XSS** 

DOM-based XSS occurs entirely in a user's browser and does not involve the server-side application. A DOM-based XSS attack is possible if the web application takes untrusted information, such as information from a URL, and writes it to the Document Object Model (DOM), where it executes. 


### Attacks 
<br/>
XSS attacks are extremely common. There are many automated tools that crawl websites and send XSS attacks to see if they end up in HTML.


### Impact 
<br/>
Cross-site scripting vulnerabilities typically allow an attacker to masquerade as a victim user in order to carry out any actions that the user is able to perform and access any of the user's data; capture the user’s login credentials; perform virtual defacement of the website, changing its messaging, look and feel; inject trojan functionality into the website, creating a backdoor that gives malicious users access to the user’s system.

XSS vulnerabilities are especially dangerous because an attacker exploiting an HTML or JavaScript vulnerability can gain the ability to do whatever the user can do, and to see whatever the user can see – including passwords, payments, sensitive financial information, and more. XSS is particulary dangerous because victims, both the user and the vulnerable application, often won’t be aware they've been exploited.


**Serious impact:** 
Attacker gains access to an application holding sensitive data, such as banking transactions, emails, or healthcare records. 

**Critical impact:** 
The compromised user has elevated privileges within the application, allowing the attacker to take full control of the vulnerable application and compromise all users and their data. 



### How to Fix 
<br/>
In general, preventing XSS vulnerabilities is likely to involve a combination of the following four measures:

- **Escaping data on output** Your primary defense should be escape user-controllable data immediately before writing to an HTTP response. Depending on the output context (body, attribute, script, style, etc...),  might require applying combinations of HTML, URL, JavaScript, and CSS encoding.
- **Use appropriate response header** You should also use Content-Type, X-Content-Type-Options, and charset headers to ensure that browsers interpret the content and character sets in the way you intend. In addition, CSP is somewhat controversial, but can help to prevent XSS.
- **Input validation** Finally, as a best practice, input validation can help. Even with validation, though, some fields must allow characters that can be used to introduce XSS. Therefore, it's best to encourage validation but *require* output escaping.

It may be obvious, but it doesn't hurt to mention...never accept JavaScript code from an untrusted source and add it to your web page.



## Cross Site Scripting by Language 

### In .NET 
<br/>

Using Microsoft's AntiXSSLibrary's `AntiXSSEncoder.HtmlEncode()` method:

```csharp
Response.Write(AntiXSSEncoder.HtmlEncode(user_supplied_value))
```

<br/>
If user input ends up in a JavaScript quoted string, safe output will require a function that is intended for that context, like the following:

Using `AntiXSSEncoder.JavaScriptStringEncode`:


```csharp
Response.Write(AntiXSSEncoder.JavaScriptStringEncode(user_supplied_value));
```

Our recommendation is to use Microsoft's AntiXSS Library's encoders rather than the built-in .NET ```HttpEncoder``` functions, as ```HttpEncoder``` is known to be weak.  
<br/>
Microsoft's AntiXSS Library significantly improves upon HttpEncoder. We strongly recommend using [AntiXssEncoder](http://msdn.microsoft.com/en-us/library/system.web.security.antixss.antixssencoder%28v=vs.110%29.aspx) over ```HttpEncoder```, including any of the classes that depend on ```HttpEncoder``` such as ```HttpUtility```, ```HttpServerUtility```, and ```HttpResponseHeader```. 

For versions of .NET prior to 4.5, the AntiXssEncoder class can be used by installing the [AntiXSS](https://www.nuget.org/packages/AntiXSS/) NuGet package.

If using .NET 4.0 or greater, we also recommend making AntiXSS your default encoder by registering it as your encoderType in Web.config like so:

```csharp
<httpRuntime encoderType="System.Web.Security.AntiXss.AntiXssEncoder" />
```

In addition to proper output encoding, you can also use the built-in XSS global validation feature called ASP.NET Request Validation to help provide a site-wide secondary line of defense against XSS. 
<br/>
ASP.NET Request Validation examines each HTTP request and determines whether it contains potentially dangerous content.
<br/><br/>
In this context, potentially dangerous content is any HTML markup or JavaScript code in the body, header, query string, or cookies of the request.

By default, request validation is enabled in the `machine.config`. Verify that request validation is currently enabled in the server's `machine.config` and that the application does not override this setting in its `web.config`. Check that `validateRequest` is set to `true` as shown in the following example:

```csharp
<system.web>
  <pages buffer="true" validateRequest="true" />
</system.web>
```

**Note:** 
<br/>
ASP.NET Request Validation performs negative validation, which is frequently bypassable. 
As such, we recommend that you explicitly defend against cross-site scripting with proper output encoding wherever user input is included in a response, and only consider this global XSS defense mechanism as a secondary defense-in-depth mechanism.



### In .NET Core
<br/>
The Razor view engine used in ASP.NET Core automatically encodes output from variables:

```js
@{ string rawValue = "<p>hello!</p>"; }

<!-- This will be written as "&lt;p&gt;hello!&lt;/p&gt;" -->
@rawValue
```

Note, that use of the ```HtmlString``` class (either directly or via the ```Html.Raw``` method) will prevent such encoding from being performed, and so should not be used to write user-supplied (or any other potentially-dangerous) content.

Outside of Razor, the ```HttpUtility``` can be used:

```js
Response.Write(HttpUtility.HtmlEncode(user_supplied_value));
```

Safely writing user input to a specific output context requires a method that is intended for that context. The `HttpUtility.JavaScriptStringEncode` method can be used when user input is inserted into a JavaScript quoted string. 
For example:

```js
Response.Write(HttpUtility.JavaScriptStringEncode(user_supplied_value));
```


If you'd like to safely put untrusted user input into other browser contexts besides HTML or JavaScript, you need to properly output encode for the different contexts as described by the OWASP XSS Prevention Cheat Sheet.

Input validation helps, but many times the characters used in XSS attacks are necessary for the application's purpose. 
So, while we always recommend input validation, we recognize that it's not always possible to use this as a defense against XSS.
<br/>


### In Java
<br/>
If the input or output of the parameter can be removed, it should. 
Otherwise, encode the parameter using the appropriate technique, based on where the parameter is rendered on the page:



| **Context**  | **Example**         | **Dangerous Characters** |     **Encoding**  |   **Notes**     |
|:-------------|:------------------|:------|:------|:------|
| HTML Entity  | ```<div>{untrusted}</div>``` | ```&<>”’/```  | ```&#xHH;```        |       |
| HTML Attribute | ```<input value="{untrusted}">```  | non alpha-numeric  | ```&#xHH;```      | This is not safe for complex attributes like ```href``` , ```src``` , ```style``` or event handlers like ```onclick``` . Strong allowlist validation must be performed to avoid unsafe URLs like ```javascript:``` or ```data:``` , along with and CSS expressions.      |
| URL Parameter          | ```<a href="/?name={untrusted}">```      | non alpha-numeric   | ```%HH```       |       |
| CSS           | ```	p { color : {untrusted} };``` | on alpha-numeric  | ```\HH```       | This is not safe for complex properties like ```url``` , ```behavior``` , and ```-moz-binding``` . Strong allowlist validation must be performed to avoid JavaScript URLs and CSS expressions.      |
| JavaScript        | ```var name = ‘{untrusted}’;``` | non alpha-numeric | ```\xHH;```       | Some JavaScript functions can never safely use untrusted data as input without allowlist validation.      |

<br/>

**Using JSP**
<br/>

```java
<c:out value=\"${userControlledValue}\"/>

... or ...

${fn:escapeXml(userControlledValue)}
```
<br/>
**Recommendations for Spring tag**
<br/>
Here's how you can output text safely with the Spring tag library:

```java
<div>
<spring:escapeBody htmlEscape=\"true\">${userControlledValue}</spring:escapeBody> // for data in HTML context</div>
<script>
<!--
var str = \"<spring:escapeBody javaScriptEscape=\"true\">${userControlledValue}</spring:escapeBody>\"; // for data in JavaScript context
-->
</script>
``` 

Input validation helps, but many times the characters used in XSS attacks are necessary for the application's purpose. 

So, while we always recommend allowlist input validation, we recognize that it's not always possible to use this as a defense against XSS.
