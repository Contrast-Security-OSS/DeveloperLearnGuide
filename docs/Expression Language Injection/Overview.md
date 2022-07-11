---
layout: page
title: Overview
permalink: /io/Expression Language Injection/Overview
parent: Expression Language Injection
nav_order: 1
---

In Progress

## Expression Language Injection

### What Is It?

Expression Language Injection (aka EL Injection) enables an attacker to view server-side data and other configuration details and variables, including sensitive code and data (passwords, database queries, etc.) The Expression Language Injection attack takes advantage of server-side code injection vulnerabilities which occur whenever an application incorporates user-controllable data into a string that is dynamically evaluated by a code interpreter. If the user data is not strictly validated, an attacker can substitute input that modifies the code that will be executed by the server.

Expression Language Injections are very serious server-side vulnerabilities, as they can lead to complete compromise of the application's data and functionality, as well as the server that is hosting the application. Expression Language Injection attacks can also use the server as a platform for further attacks against other systems.


When user data is evaluated by an Expression Language interpreter, it is likely the result of this evaluation will be returned to the user. If this is the case, users can provide variables in their data, like\"\${applicationScope}\", that will be evaluated, populated with sensitive server information, and returned to the user. 




### When Can It Affect My Application?




### Impact 

An injected expression can likely invoke static methods and control the application server completely.


### Prevention 

Ensure to perform data validation best practice against untruste input and to confirm 
that output encoding is applied when data arrives on the EL layer, so that
no metacharacter is found by the interpreter within the user content before evaluation. 

The most obvious patterns to detect include “${“ and “#{“, but it may be possible to encode or fragment
this data.