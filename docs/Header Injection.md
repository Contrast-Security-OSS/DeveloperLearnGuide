---
layout: default
title: Header Injection
nav_order: 5
---

# Header Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Header Injection

### Overview
<br/>
This attack targets the HTTP header of the application, by injecting malicious input.
If the user provides a vulnerable input containing newline characters, they could effectively spoof new headers to the browser or intermediate proxies reading the response. 
<br/>

If the attacker can trick another end user into submitting a dangerous value  in a malicious link, they may be able to use the resulting corrupted headers to perform XSS, phishing, and other attacks. 
<br/>
<br/>
Without any victim involvement, this vulnerability may be used to perform an advanced attack called HTTP cache poisoning. This 
could be used to alter the site's HTML content for other users when they try and view the page, and affect defacement attacks,
credential theft, and other undesirable behavior.


### Impact
<br/>
This vulnerability can be used to send unsafe redirects, execute XSS attacks, and affect cache-poisoning. 


## How To Fix by Language 
<br/>
There are a few good general ways to address this issue:

- **Refactor the header** 
Remove all `\r` and `\n` characters. At a minimum, this prevents attackers from forging new headers.

- **Strip out newlines** 
It may be easier to just refactor the user input out of the header. For instance, if the vulnerability is in a `Content-Disposition` header, just deliver a hardcoded file name with the response instead of allowing the user to supply one.
<br/>

### Java 

<br/>

Here's an **unsafe** example of including user input in a header:

```java
// FileDownloadServlet.java
String fileName = request.getParameter("fileName");
response.setHeader("Content-Disposition", "attachment; filename=" + fileName);
```
<br/>

Now let's fix this query to make it **safe**:

```java
// FileDownloadServlet.java
String fileName = request.getParameter("fileName");
fileName = fileName.replace("\r","").replace("\n","");
response.setHeader("Content-Disposition", "attachment; filename=" + fileName);

...or...

response.setHeader("Content-Disposition", "attachment; filename=hardcoded.dat");
```

### .NET

First ensure you **enable header checking** in ASP.NET, as follows `&lt;httpRuntime enableHeaderChecking="true"/&gt;`

Here is an example `web.config` with `enabledHeaderChecking` explicitly set:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.web>
    <httpRuntime targetFramework="4.5" enableHeaderChecking="true" />
  </system.web>
</configuration>
```
<br/> 

### Node 

Let's walkthrough steps to remediate this issue when using Node. 

Class [name,value](https://nodejs.org/api/http.html#http_response_setheader_name_value) should be used in place of [statusMessage, headers](https://nodejs.org/api/http.html#http_response_writehead_statuscode_statusmessage_headers) whenever possible.
<br/>

If [name,value](https://nodejs.org/api/http.html#http_response_setheader_name_value) must be used, avoid putting user controlled data into the `statusMessage` argument, as this is not properly sanitized in older versions of Node. 
See the following [commit](https://github.com/nodejs/node/commit/c0f13e56a2) for details.
<br/>

Additionally, ensure that `response.statusMessage` is never set with user controlled data. 


## How can Contrast help? 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect Headeer Injection vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block Header Injection attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect Header Injection vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.