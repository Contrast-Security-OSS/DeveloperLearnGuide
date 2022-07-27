---
layout: default
title: Server-Side Request Forgery (SSRF)
nav_order: 6
---

# Server-Side Request Forgery (SSRF)
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Server-Side Request Forgery (SSRF)

### Overview 
<br/> 

SSRF vulnerabilities enable an attacker to trick the targeted application or application programming interface (API) into sending a crafted request to an unexpected destination—turning a vulnerable application into a sort of attack relay that gives an attacker access to internal systems. 

SSRF requires two conditions: 

- The application performs requests to the serve or localhost
- The attacker controls the server or localhost through the external app/user input 


### Impact 
<br/> 

Since the attacker controls the URL, they can trick the application into invoking internal URLs. 
This may lead to internal resource enumeration, abuse of internal-only APIs, or the exfiltration of local system resources using the ```file://``` protocol. 

Attackers can control a portion of the URL which the server makes a HTTP request to. 
If this portion is part of the hostname, attackers may be able to control where a HTTP request is sent. 

Depending on network configurations, this could be an HTTP request to external, internal, localhost, or local files using the```file://``` method (if the attacker can control that portion of the URL). 

Attackers could also use this vulnerability to enumerate and interact with internal servers or localhost, both of which would typically be unreachable to an attacker. 

Additionally, attackers could use this vulnerability to make a server reach out to an attacker-controlled server to reveal any data or secrets contained within the HTTP request that is not intended to be seen by the attacke. 


### How To Fix 
<br/> 

Where possible, do not accept user input to have full control of a URL that is requested by a server. Applications could provide users a list of options to select from, rather than a free-form text field. 

If user control of URL is required, verify the URL to-be-requested is acceptable. For example, use an allow-list to limit what domains, IPs, methods, or paths can be requested. Additionally, a deny-list could be used to exclude localhost, private network ranges, or etc.

### Further Reading
<br/> 

[SSRF Detection With IAST](https://www.contrastsecurity.com/security-influencers/iast-is-the-only-way-to-accurately-detect-ssrf?hsLang=en-us)