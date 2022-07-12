---
layout: page
title: Cross Site Scripting (XSS) in Dotnet
permalink: /io/Cross Site Scripting (XSS)/Cross Site Scripting (XSS) in Dotnet
parent: Cross Site Scripting (XSS)
nav_order: 2
---

## Cross Site Scripting (XSS) in Dotnet 
### How To Fix 

### Recommendations for .NET 

Using Microsoft's AntiXSSLibrary's `AntiXSSEncoder.HtmlEncode()` method:

```
Response.Write(AntiXSSEncoder.HtmlEncode(user_supplied_value))
```

If user input ends up in a JavaScript quoted string, safe output will require a function that is intended for that context, like the following:

Using `AntiXSSEncoder.JavaScriptStringEncode`:

```
Response.Write(AntiXSSEncoder.JavaScriptStringEncode(user_supplied_value));
```

Our recommendation is to use Microsoft's AntiXSS Library's encoders rather than the built-in .NET ```HttpEncoder``` functions, as ```HttpEncoder``` is known to be weak.  Microsoft's AntiXSS Library significantly improves upon HttpEncoder. We strongly recommend using [AntiXssEncoder](http://msdn.microsoft.com/en-us/library/system.web.security.antixss.antixssencoder%28v=vs.110%29.aspx) over ```HttpEncoder```, including any of the classes that depend on ```HttpEncoder``` such as ```HttpUtility```, ```HttpServerUtility```, and ```HttpResponseHeader```. 

For versions of .NET prior to 4.5, the AntiXssEncoder class can be used by installing the [AntiXSS](https://www.nuget.org/packages/AntiXSS/) NuGet package.

If using .NET 4.0 or greater, we also recommend making AntiXSS your default encoder by registering it as your encoderType in Web.config like so:

```
<httpRuntime encoderType="System.Web.Security.AntiXss.AntiXssEncoder" />
```

In addition to proper output encoding, you can also use the built-in XSS global validation feature called ASP.NET Request Validation to help provide a site-wide secondary line of defense against XSS. 
ASP.NET Request Validation examines each HTTP request and determines whether it contains potentially dangerous content. In this context, potentially dangerous content is any HTML markup or JavaScript code in the body, header, query string, or cookies of the request.

By default, request validation is enabled in the `machine.config`. Verify that request validation is currently enabled in the server's `machine.config` and that the application does not override this setting in its `web.config`. Check that `validateRequest` is set to `true` as shown in the following example:

```
<system.web>
  <pages buffer="true" validateRequest="true" />
</system.web>
```

**Note:** ASP.NET Request Validation performs negative validation, which is frequently bypassable. 
As such, we recommend that you explicitly defend against cross-site scripting with proper output encoding wherever user input is included in a response, and only consider this global XSS defense mechanism as a secondary defense-in-depth mechanism.



### Recommendations for .NET Core

The Razor view engine used in ASP.NET Core automatically encodes output from variables:

```
@{ string rawValue = "<p>hello!</p>"; }

<!-- This will be written as "&lt;p&gt;hello!&lt;/p&gt;" -->
@rawValue
```

Note, that use of the ```HtmlString``` class (either directly or via the ```Html.Raw``` method) will prevent such encoding from being performed, and so should not be used to write user-supplied (or any other potentially-dangerous) content.

Outside of Razor, the ```HttpUtility``` can be used: 

```
Response.Write(HttpUtility.HtmlEncode(user_supplied_value));
```

Safely writing user input to a specific output context requires a method that is intended for that context. The `HttpUtility.JavaScriptStringEncode` method can be used when user input is inserted into a JavaScript quoted string. 
For example:

```
Response.Write(HttpUtility.JavaScriptStringEncode(user_supplied_value));
```


If you'd like to safely put untrusted user input into other browser contexts besides HTML or JavaScript, you need to properly output encode for the different contexts as described by the OWASP XSS Prevention Cheat Sheet.

Input validation helps, but many times the characters used in XSS attacks are necessary for the application's purpose. 
So, while we always recommend input validation, we recognize that it's not always possible to use this as a defense against XSS.