---
layout: default
title: Authorization Weakness
nav_order: 16
---
# Authorization Weakness
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Authorization Missing 

### Vulnerability 
<br/>
An application could be at risk if it does not include a rule to deny access to all users or a rule to deny access to anonymous users. 
ASP.NET, for example, evaluates authorization rules in a top-down order until a rule is satisfied. The final rule must not be "allow all" as it will grant anyone full access to any resource not specifically covered by a rule.
<br/>

### Attacks
Attackers use automated tools to crawl and scan a website to attempt to access to unauthorized functions and resources.
<br/>


### Impact 
<br/>

The result of missing authorization is that an attacker can gain unauthorized access to sensitive functions or data. The impact can range from minor to highly critical.


### How To Fix 

Resolve this issue by adding a `deny` rule to deny access to anonymous users or all users as shown in the example below.  
This configuration grants access to users with the admin role and denies access to all other users: 

```xml 
<authorization>
	<allow roles="admin"/>
	<deny users="*"/>
</authorization>
```


## Authorization Misordered
### Overview  
<br/>
As mentioned above, ASP.NET evaluates authorization rules in a top-down order until a rule is satisfied. The allow all users rule allows `<users="*"/>` to be satisfied first, granting all users access. The following rules will never be evaluated and therefore the deny rule will never be satisfied.

The result of this is an attacker could potentially gain access to protected resources due to this misordered rule. 

### How To Fix 
<br/>

Resolve this issue by removing the allow all users rule or placing it after the deny rules as shown in the example below.  
This configuration denies access to users with the guest role, denies access to anonymous/unauthenticated users, and grants access to all other users: 

```xml
<authorization>
	<deny roles="guest"/>
	<deny users="?"/>
	<allow users="*"/>
</authorization>
```
