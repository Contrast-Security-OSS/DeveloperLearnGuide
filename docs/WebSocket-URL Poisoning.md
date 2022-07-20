---
layout: default
title: WebSocket-URL Poisoning
nav_order: 16
---

# WebSocket-URL Poisoning
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Overview 


An attacker may be able to use this vulnerability to create a specific URL. If this is then visited by different user, the browser will open a WebSocket connection to a URL that is under the attacker's control.


The impact of such may lead to the attacker being able to capture sensitive data from the user’s browser.
The attacker also has the potential to conduct client-side attacks against the user. 

## How To Fix  

The most effective method of stopping WebSocket poisoning is to avoid allowing data from any untrusted source to dynamically set the target URL of a WebSocket connection. 

Additionally, always use `JSON.parse()` to safely parse JSON response data. 

## How can Contrast help? 

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
