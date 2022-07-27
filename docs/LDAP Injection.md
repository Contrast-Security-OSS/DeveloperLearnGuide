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
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## LDAP Injection

### Overview 
<br/>
LDAP Injection occurs when remote attacker input can reach LDAP queries, changing the query to return different (or more) results. 

This attack occurs in applications that directly query LDAP systems, most often for user lookup or authentication. 
Attackers often look for signs of an LDAP query on input and add attitional characters to change records. 
<br/>
<br/> 

By crafting malicious inputs to this query, an attacker can enumerate the attributes of the available object classes. This may lead to the attacker obtaining, manipulating, or deleting information they are not authorized to access. It may also amount to a complete authentication bypass.

### How To Fix  
<br/>
LDAP Injection is most often fixed by creating an allow-list of characters and ensuring proper escaping. Ideally, parameterized APIs for accessing LDAP should be used where possible. 
<br/> 
Alternatively, user input should be **thoroughly** validated before being used to create dynamic LDAP queries. 
