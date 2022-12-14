---
layout: default
title: Expression Language Injection
nav_order: 5
---

# Expression Language Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Expression Language Injection

### Overview 
<br/>
Expression Language Injection (aka EL Injection) enables an attacker to view server-side data and other configuration details and variables, including sensitive code and data (passwords, database queries, etc.) 

The Expression Language Injection attack takes advantage of server-side code injection vulnerabilities which occur whenever an application incorporates user-controllable data into a string that is dynamically evaluated by a code interpreter. 

If the user data is not strictly validated, an attacker can substitute input that modifies the code that will be executed by the server.


When user data is evaluated by an Expression Language interpreter, it is likely the result of this evaluation will be returned to the user. If this is the case, users can provide variables in their data, like\"\${applicationScope}\", that will be evaluated, populated with sensitive server information, and returned to the user. 


### Impact 
<br/>
Expression Language Injections are very serious server-side vulnerabilities, as they can lead to complete compromise of the application's data and functionality, as well as the server that is hosting the application. 

Expression Language Injection attacks can also use the server as a platform for further attacks against other systems.


### Prevention 
<br/>
Ensure to perform data validation best practice against untruste input and to confirm 
that output encoding is applied when data arrives on the EL layer, so that
no metacharacter is found by the interpreter within the user content before evaluation. 

The most obvious patterns to detect include ```${``` and ```#{```, but it may be possible to encode or fragment
this data.