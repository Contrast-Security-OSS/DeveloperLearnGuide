---
layout: default
title: Javascript Injection
nav_order: 8
---

# Javascript Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Javascript Injection

In Progress 


### What Is It? 
<br/>
Any time your website or application accepts and displays user input, you are at risk for ccode injectio. 
Thes can occur any time when poor data handling is exploited, and malicious code is accepted and executed.
Javascript injections occur in the following ways:
- Entering Javascript into URL bar
- Using Developer Console to inject scripts
- Expand into XSS attack, by entering scripts into user input fields (e.g. forms)


### Impact 

This vulnerability may enable the attacker to perform actions on behalf of a user. As such, it may be used in a chain or sequence of attacks such as Cross Site Scripting (XSS), making the impact more severe. It may also be possible for the victim's login credentials or session token being compromised. 



## How To Fix 


The most effective method of preventing JavaScript injection is to restrict data from untrusted sources being executed as JavaScript. 
<br/>
Ensure to apply all standard security measures such as validation of input, and appropriate escaping of output.




## How can Contrast help?

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
