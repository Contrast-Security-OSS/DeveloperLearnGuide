---
layout: default
title: Regular Expression DoS
nav_order: 5
---

# Regular Expression DoS
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Regular Expression DoS

### Overview 
<br/> 
Regular expressions can reside in every layer of the web. The Regular expression Denial of Service (ReDoS) produces one or more regular expressions or regex(s) that “run on and on” by design. 

Using an “evil regex,” the attacker is able to exploit a web browser on either computer or mobile device, hang up a Web Application Firewall (WAF), or attack a vulnerable database or web server.

With a ReDoS attack, carefully crafted inputs trick innocent but regular expressions to run indefinitely. ReDoS will either slow down the application or completely crash it, as the regex engine tries to find a match by running every possible combination of characters. When all permutations fail to find a match, the regular expression will run on forever until manually terminated.


### Impact 
<br/>
During exploit, While attempting to match the regex, application threads will become overconsumed. 
As the name suggests, this attack can result in lack of access to services. 


### Prevention 
<br/>
There are two ways to fix this vulnerability: prevent the untrusted input from running through the regular expression or fixing the regular expression
itself. 
Unfortunately, there is no generic solution for altering an "evil regex" to not allow abuse. There a few hints: 
- Wrapping patterns in an atomic group can prevent runaway backtracking
- Avoid detecting repetition of overlapping character groups
- Avoid using unbounded quantifiers -- i.e., use `a{15}` rather than `a+` 