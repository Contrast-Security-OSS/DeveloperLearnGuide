---
layout: default
title: Link Manipulation
nav_order: 8
---

# Link Manipulation
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-green }

## Link Manipulation

### Overview  
<br/>
An attacker may be able to use this flaw to modify a URL to redirect to a malicious extneral URL, enabling a phishing attack. 
Modifying the file or query string associated with the clickable link may also cause the user to perform unintended actions. 
<br/> 
If the user form is successfully exploited, this could also result in sensitive data being submitted to the server, under the control of the attacker.

### How To Fix  
<br/>
The most effective method of preventing Link Manipulation is to restrict data from untrusted sources dynamically setting target URLs or forms.