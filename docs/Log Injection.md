---
layout: default
title: Log Injection
nav_order: 8
---

# Log Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Log Injection

### Overview


Log injection involves the tampering of application or system log files via untrusted input. 
As logs provide an audit trail of events, it can be utilized following a more severe attack, in order to obfuscate its traces. 

In a log injection, a malicious user could provide newline characters in input in order to spoof new log entries. 

It's unlikely that this could cause real harm to any of the application stakeholders on its own, but some regulations require log file integrity to be controlled.


### How To Fix 

Sanitize or validate all input that is going to be logged. Ensure users cannot provide newline characters that are written into log messages.


## How can Contrast help? 

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.