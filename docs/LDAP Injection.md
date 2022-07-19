---
layout: default
title: LDAP Injection
nav_order: 8
---

# LDAP Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## LDAP Injection

### What Is It? 
<br/>
LDAP Injection occurs when remote attacker input can reach LDAP queries, changing the query to return different (or more) results. 

This attack occurs in applications that directly query LDAP systems, most often for user lookup or authentication. 
Attackers often look for signs of an LDAP query on input and add attitional characters to change records. 
<br/>
<br/> 

By crafting malicious inputs to this query, an attacker can enumerate the attributes of the available object classes. This may lead to the attacker obtaining, manipulating, or deleting information they are not authorized to access. It may also amount to a complete authentication bypass.



### How To Fix 


LDAP Injection is most often fixed by creating an allow-list of characters and ensuring proper escaping. Ideally, parameterized APIs for accessing LDAP should be used where possible. 
<br/>
Alternatively, user input should be **thoroughly** validated before being used to create dynamic LDAP queries. 


## How can Contrast help?

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect LDAP Injection vulnerabilities as they are tested. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
