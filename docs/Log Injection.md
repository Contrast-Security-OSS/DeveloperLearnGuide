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
<br/>

Log injection involves the tampering of application or system log files via untrusted input. 
As logs provide an audit trail of events, it can be utilized following a more severe attack, in order to obfuscate its traces. 

In a log injection, a malicious user could provide newline characters in input in order to spoof new log entries. 

It's unlikely that this could cause real harm to any of the application stakeholders on its own, but some regulations require log file integrity to be controlled.


### How To Fix 
<br/>
Sanitize or validate all input that is going to be logged. Ensure users cannot provide newline characters that are written into log messages.