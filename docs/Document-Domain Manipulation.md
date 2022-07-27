---
layout: default
title: Document-Domain Manipulation
nav_order: 11
---

# Document-Domain Manipulation
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Document-Domain Manipulation

### Overview 
<br/>
The now [deprecated](https://developer.mozilla.org/en-US/docs/Web/API/Document/domain) Document.domain property sets or returns the domain name of the server from which the document originated. 

This results in the property defaulting to the domain name of the server where the document was retrieved, but can be changed to a suffix of this domain name. 

## Scenario 
<br/>
Uing this property opens up the application to a range of potential security issues. 

1. Alice has a unique subdomain on a shared hosting service:` https://alicecontrast.sharedhost.com`, malicious actor also owns a subdomain.
2. Alice sets document.domain on their page
3. Malicious actor's page from their own subdomain can set the same value as Alice.
4. Malicious actor can now modify content of Alice's page


As the target page is now compromised, the chain of attacks can potentially lead to Cross Site Scripting (XSS) vulnerabilities.


## Prevention 
<br/>
The most effective method of preventing Document Domain Manipulation is to restrict data from untrusted sources dynamically setting the document.domain property.