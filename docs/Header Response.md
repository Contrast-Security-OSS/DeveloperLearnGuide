---
layout: default
title: Header Response
nav_order: 12
---

# Header Response
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Response With Insecurely Configured Content-Security-Policy Header 

### Overview 

Content-Security-Policy is an opt-in site protection mechanism supported by current browsers. 
<br/> 

It can be used to tightly restrict the content and behavior of the page. 
Adding restrictions can greatly reduce the attack surface of the page. 
<br/> 

It is used to restrict from where various HTML elements can be sourced, to where the page can communicate, and how the page can identify itself.   
Not setting Content-Security-Policy header allows the browser to assume the application trusts content loaded from external domains. 
<br/> 

This means it will attempt to render elements and execute scripts from any source, including those which are unknown and potentially malicious. 

### How To Fix  

In order to properly restrict your application's behavior, a Content-Security-Policy (CSP) header should be created. 
At a minimum, this header should limit access to outside content by specifying a tightly constrained 'default-src' value. 
<br/> 
Unfortunately, there is no universal setting for this value because it must to be tailored to your application. 
It should be as restrictive as possible without disrupting the functionality of your application. 

The best way to determine this is to start with the Content-Security-Policy-Report-Only (CSPRO) header given a 'default-src' value of 'self'. 
This will report any time an external source is loaded by your application. 
<br/>  
Using this output, you will be able to tune the allowed default sources to include those which your application legitimately needs. 
<br/>  
Once the base sources have been determined, the header should be changed from CSPRO to CSP, thereby restricting external content from being rendered within your application.

## Response With Insecurely Configured Strict-Transport-Security Header 

### Overview 

HTTP Strict Transport Security (HSTS) is used by an application to indicate that an user-agent can only communicate with it over HTTPS. 
The Strict-Transport-Security header indicates that for the duration specified by the 'max-age' setting, only HTTPS should be used. 
<br/> 
By not passing this header or sending a value of {{#badParam}}0{{/badParam}} for 'max-age', the application could be left susceptible to down-grade attacks. 
<br/>  
In these attacks, in an attempt to be backwards compliant, the user-agent drops from HTTPS to the less secure HTTP connection, which could allow for 
man-in-the-middle attack

### How To Fix

In order to prevent down-grade attacks and the transition from HTTPS to HTTP, include the Strict-Transport-Security header with a value greater than ``0``. 

### How To Fix in Ruby 

The easiest way to prevent this issue from occurring in Rails applications is to add these
``default_headers`` calls to the application configuration: 

```ruby
config.action_dispatch.default_headers = {
  'Strict-Transport-Security' =>  'max-age=86400; includeSubDomains'
}
```
<br/> 

The approach for Sinatra is similar. Include the [rack-protections](https://github.com/sinatra/sinatra/tree/master/rack-protection) gem and add the following to the application configuration extending ``Sinatra::Base``:

```ruby
require 'rack/protection/strict_transport'
use Rack::Protection
use Rack::Protection::StrictTransport, :max_age => 86_400
```

**Note** that the '86400' above is an arbitrary value. Any non-0 entry is considered secure.



## Response With X-XSS-Protection Disabled 

### Overview 

Setting X-XSS-Protection to a value other than '1' disables the browser's default cross-site scripting (XSS) protection. 
This is a key protection against reflected XSS attacks. 

### How To Fix 

In order to prevent reflected XSS attacks, the X-XSS-Protection header should never be disabled. 
Specifically, the value should be left default (unset) or set to '1'.

### How To Fix in Ruby 

The easiest way to prevent this issue from occurring in Rails applications is to add this
``default_headers`` call to the application configuration:

```ruby
config.action_dispatch.default_headers = {
  'X-XSS-Protection' =>  1
}
``` 

The approach for Sinatra is similar. Include the [rack-protections](https://github.com/sinatra/sinatra/tree/master/rack-protection) gem and add the following to the application configuration extending ``Sinatra::Base``:

```ruby
require 'rack/protection'
use Rack::Protection::XSSHeader
```


## Response Without Content-Security-Policy Header 

### Overview 

Content-Security-Policy is an opt-in site protection mechanism supported by current browsers. 
It can be used to tightly restrict the content and behavior of the page. 
Adding restrictions can greatly reduce the attack surface of the page. 
<br/> 
It is used to restrict from where various HTML elements can be sourced, to where the page can communicate, and how the page can identify itself.   
Not setting Content-Security-Policy header allows the browser to assume the application trusts content loaded from external domains. 
<br/> 
This means it will attempt to render elements and execute scripts from any source, including those which are unknown and potentially malicious.  


### How To Fix 

In order to properly restrict your application's behavior, a Content-Security-Policy (CSP) header should be created. 
At a minimum, this header should limit access to outside content by specifying a tightly constrained 'default-src' value. 
<br/> 
Unfortunately, there is no universal setting for this value because it must to be tailored to your application. 
It should be as restrictive as possible without disrupting the functionality of your application. 
<br/>  
The best way to determine this is to start with the Content-Security-Policy-Report-Only (CSPRO) header given a 'default-src' value of 'self'. 
This will report any time an external source is loaded by your application. 
<br/> 

Using this output, you will be able to tune the allowed default sources to include those which your application legitimately needs. 
<br/> 

Once the base sources have been determined, the header should be changed from CSPRO to CSP, thereby restricting external content from being rendered within your application.


## Response Without X-Content-Type-Options Header 

### Overview 

User-agents employ a technique called MIME-sniffing to try and determine the **Content Type** of the page they are rendering. 
This is done by inspecting a byte-stream in an attempt to determine the file type it represents. 
<br/> 

This action can be dangerous if an attacker can trick the user-agent into incorrectly identifying the content type, thereby resulting in the attacker's input being rendered in a malicious manner.


### How To Fix 

In order to prevent improper identification of the Content-Type of a page, all requests should have an X-Content-Type-Options header set to a value of 'nosniff'.


### How To Fix in Ruby 

The easiest way to prevent this issue from occurring in Rails applications is to add this
``default_headers`` calls to the application configuration:

```ruby
config.action_dispatch.default_headers = {
  'X-Content-Type-Options' =>  'nosniff'
}
```

{{#paragraph}}The approach for Sinatra is similar. Include the [rack-protections](https://github.com/sinatra/sinatra/tree/master/rack-protection) gem and add the following to the application configuration extending ``Sinatra::Base``:

```ruby
require 'rack/protection'
use Rack::Protection::XSSHeader
```

## How can Contrast hekp? 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect these vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block these attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.