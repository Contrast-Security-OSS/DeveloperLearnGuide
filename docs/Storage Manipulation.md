---
layout: default
title: Storage Manipulation
nav_order: 14
---

# Storage Manipulation
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

Storage manipulation occurs when the localStorage or SessionStorage of a web application is compromised by attacker-controllable script. 
One simple method of exploiting a weakness in this area is: 
- Attacker creates malicious URL and sends to victim
- Victim clicks on URL
- Victim's browser now has data in storage that enables the attacker to control behaviour  


This behavior does not in itself constitute a security vulnerability. However, if the application later reads data back from storage and processes it in an unsafe way, an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as cross-site scripting and JavaScript injection.

### Impact
<br/> 

This vulnerability is often used in a sequence of attacks, so risk can range from low to severe. 

An attacker may be able to use this flaw in order to exploit the storage vulnerability further by performing DOM-based attacks, such as Cross Site Scripting (XSS), and JavaScript Injection.


### Prevention
<br/> 

The most effective method of preventing storage manipulation is to verify the origin of the sender, and perform input validation on the data attribute to confirm it is in the desired format. 

Most importantly always restrict data from untrusted sources being placed in storage.