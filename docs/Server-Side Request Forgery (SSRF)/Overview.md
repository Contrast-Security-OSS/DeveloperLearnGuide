---
layout: page
title: Overview
permalink: /io/Server-Side Request Forgery (SSRF)/Overview
parent: Server-Side Request Forgery (SSRF)
nav_order: 1
---

## Server-Side Request Forgery (SSRF)

### What Is It?





### When Can It Affect My Application?





## Impact


Because the attacker controls the URL, they can trick the application into invoking internal URLs. This may lead to internal 
resource enumeration, abuse of internal-only APIs, or the exfiltration of local system resources using the ```file://``` protocol.

Attackers can control a portion of the URL which the server makes a HTTP request to. If this portion is part of the hostname, attackers may be able to control where a HTTP request is sent. Depending on network configurations, this could be an HTTP request to external, internal, localhost, or local files using the```file://``` method (if the attacker can control that portion of the URL). Attackers could use this vulnerability to enumerate and interact with internal servers or localhost, both of which would typically be unreachable to an attacker. Additionally, attackers could use this vulnerability to make a server reach out to an attacker-controlled server to reveal any data or secrets contained within the HTTP request that is not intended to be seen by the attacker.

### How can Contrast help?


### Further Reading

[SSRF Detection With IAST] https://www.contrastsecurity.com/security-influencers/iast-is-the-only-way-to-accurately-detect-ssrf?hsLang=en-us
