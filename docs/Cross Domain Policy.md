---
layout: default
title: Cross Domain Policy
nav_order: 10
---

# Cross Domain Policy
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Overly Permissive Cross Domain Policy

### Overview 
<br/>
A Cross Domain Policy defines the list of permissions that a web client uses to access data across domains.
When your application has an **overly permissive cross domain policy**, it is open to attack.

This setting allows a malicious actor to steal your user data or forge actions on behalf of your users. 

Allowing any domain to have access to this site essentially turns off the browser's "same origin policy" for Flash, Silverlight, and other browser plugins. 

This means that if a malicious actor can trick someone into visiting their page on attacker-website-here, they can make requests on that user's behalf to your site and steal data or perform any other operation

### Prevention 
<br/>
Remove any leading wildcards from domain attributes of allow-access-from elements in your crossdomain.xml. 

Alternatively, since the access permissions granted by the cross domain policy are restricted to APIs at the same domain, 
APIs that could return sensitive data should be hosted at another domain. 

For example, if publicly available APIs and the crossdomain.xml are hosted at http://public.domain.com, APIs that could return sensitive data should be hosted at http://private.domain.com.

