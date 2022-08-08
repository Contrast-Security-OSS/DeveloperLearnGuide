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

### Overview
<br/>
Cross Site Scripting (XSS) occurs when _________ is a web security vulnerability that allows attackers to compromise user interactions by inserting malicious scripts designed to hijack vulnerable applications.  

An XSS attack targets the scripts running behind a webpage which are being executed on the client-side (in the user’s web browser). 

Because the unsuspecting browser has no way of knowing that a script should not be trusted, it will go ahead and execute the XSS script, which can access cookies, session tokens, and other sensitive information retained by the browser and used with that site. 

In short, cross-site scripting (XSS) allows the attacker to “commandeer” HTML pages, deceive users, and steal sensitive data as it assumes control, redirects links, and rewrites content on that site.

Three main types of attacks can target an XSS vulnerability:

- **Reflected XSS** (non persistent), where the malicious script comes from the current HTTP request.
- **Stored XSS** (persistent), where the malicious script comes from the website's database.
- **DOM-based XSS** where the vulnerability exists in client-side code rather than server-side code.


**Reflected XSS attacks** 

Also known as non-persistent attacks, these occur when a malicious script is reflected off of a web application to the victim's browser. The script is activated through a link, which sends a request to a website with a security vulnerability that enables execution of malicious scripts. 

**Stored XSS** 

This vulnerability is a more devastating variant of a cross-site scripting flaw: it occurs when the data provided by the attacker is saved by the server, and then permanently displayed on "normal" pages returned to other users in the course of regular browsing, without proper HTML escaping. 

**DOM-based XSS** 

This is a type of XSS occurring entirely on the client-side. 
A DOM-based XSS attack is possible if the web application writes data to the Document Object Model without proper sanitization. 

The attacker can manipulate this data to include XSS content on the webpage, for example, malicious JavaScript code. 
The attacker embeds a malicious script in the URL; the browser finds the JavaScript code in the HTML body and executes it. 

JavaScript sources are functions or DOM properties that can be influenced by the user, but vulnerable JavaScript sources can be exploited for a DOM-based attack.


### How Does It Work? 
<br/>
By injecting a malicious client-side script into an otherwise trusted website, scripting XSS cross-site tricks an application into sending malicious code through the browser, which believes the script is coming from the trusted source.  
It then deceives users by manipulating scripts so that they execute in the manner desired by the attacker.

Cross-site scripting vulnerabilities typically allow an attacker to masquerade as a victim user in order to carry out any actions that the user is able to perform and access any of the user's data; capture the user’s login credentials; perform virtual defacement of the website, changing its messaging, look and feel; inject trojan functionality into the website, creating a backdoor that gives malicious users access to the user’s system.

The XSS attack works by manipulating a website vulnerability such that it returns malicious JavaScript code to users. 
When the malicious code executes inside a victim's browser, the attacker can fully compromise the user’s interaction with the application. 
If the victim user has privileged access within the application, the attacker might be able to gain full control over all of the application's functionality and data – a “worst case” application security scenario. 



### Impact 
<br/>
XSS vulnerabilities are especially dangerous because an attacker exploiting an HTML or JavaScript vulnerability can gain the ability to do whatever the user can do, and to see whatever the user can see – including passwords, payments, sensitive financial information, and more. 

What makes the XSS attack even worse is the fact that victims, both the user and the vulnerable application, often won’t be aware they’re being attacked.

**Serious impact:** 
Attacker gains access to an application holding sensitive data, such as banking transactions, emails, or healthcare records. 

**Critical impact:** 
The compromised user has elevated privileges within the application, allowing the attacker to take full control of the vulnerable application and compromise all users and their data. 



### Prevention 
<br/>
OWASP has published a cheat sheet that can be used to prevent XSS attacks. 
These guidelines focus on three prevention strategies – escaping, validating input, and sanitizing.

In general, preventing XSS vulnerabilities is likely to involve a combination of the following four measures:

- **Filter input on arrival** At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
- **Encode data on output** At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.
- **Use appropriate response header** To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.
- **Use Content Security Policy** As a last line of defense against attackers, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur. 

And most importantly, never accept JavaScript code from an untrusted source and execute.



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
