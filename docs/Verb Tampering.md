---
layout: default
title: Verb Tampering
nav_order: 16
---

# Verb Tampering
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Overview 
<br/> 

Attackers can manipulate the HTTP method to attempt to bypass security controls. 
The full list of HTTP methods is: 

- HEAD
- GET
- POST
- PUT
- DELETE
- TRACE
- OPTIONS
- CONNECT

The use of the HEAD method, for example, to access anything in the /admin/* space is the easiest attack. The PUT method can also be used to upload malicious scripts to the server. Often, like in the case of making requests directly to JSPs, one can send an arbitrary string such as "NONSENSE" for the method, and the JSP will render correctly.


## How To Fix   
<br/> 

The most complete fix for this issue is simple: remove any `<http-method>` entries from your `<security-constraint>`. 

If you want to selectively enable constraints per individual HTTP methods, you can setup multiple, overlapping constraints to make sure that if a method "falls through" a constraint, it is still handled by a more general constraint that puts some blanket protections across the entire authenticated portion of the site. 

Here's an example of an **unsafe** version: 

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <!-- Unsafe! -->
        <http-method>GET</http-method>
        <http-method>POST</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

Let's fix this to make it **safer** by removing the HTTP Methods:

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <!-- Safe! No <http-method> entries! -->
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```