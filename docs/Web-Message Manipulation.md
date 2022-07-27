---
layout: default
title: Web-Message Manipulation
nav_order: 16
---

# Web-Message Manipulation
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-green }

## Overview 
<br/>
Sending web messages across an application is normal practice, however this process becomes exploitable once the application accepts data from an untrusted source. 

An attacker may be able to use the web message data as a source by constructing a web page that, if visited by a user, will cause the user's browser to send a web message containing data that is under the attacker's control. 

Take this simple scenario, which demonstrates how it is possible to use the web-message as the source for sending malicious data.

- Attacker hosts malicious iframe
- Using the vulnerable `postMessage()`method, the attacker sends web message data to event listener
- Payload is sent to sink on parent page 


An attacker may be able to use this flaw in order to process unintended actions on behalf of another user. Vulnerabilities like this can also lead to other dangerous attacks, such as Cross Site Scripting (XSS).


## How To Fix   
<br/>
The most effective method of preventing Web message manipulation is to avoid sending web messages containing data from any untrusted source. Additionally, always ensure to verify the origin of incoming messages, and restrict messages from untrusted domains. 
