---
layout: page
title: How To Fix
permalink: /io/Server-Side Request Forgery (SSRF)/How To Fix
parent: Server-Side Request Forgery (SSRF)
nav_order: 3
---


## How To Fix 


Where possible, do not accept user input to have full control of a URL that is requested by a server. Applications could provide users a list of options to select from, rather than a free-form text field. 

If user control of URL is required, verify the URL to-be-requested is acceptable. For example, use an allow-list to limit what domains, IPs, methods, or paths can be requested. Additionally, a deny-list could be used to exclude localhost, private network ranges, or etc.
