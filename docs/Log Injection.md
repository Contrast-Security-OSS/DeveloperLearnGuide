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

### What Is It? 

**In Progress**

In a log injection, a malicious user could provide newline characters in this input and spoof new log entries. 
 
It's unlikely that this could cause real harm to any of the application stakeholders, but some regulations require log file integrity to be controlled.



### How To Fix 

Sanitize or validate all input that is going to be logged. Make sure users can't provide newline characters that get into log messages.


## How can Contrast help? 

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.