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

## Authorization Missing 
### Overview 
<br/>
An application could be at risk if it does not include a rule to deny access to all users nor a rule to deny access to anonymous users. 
ASP.NET, for example, evaluates authorization rules in a top-down order until a rule is satisfied. Authorization rules include a default allow all rule that is evaluated last.
<br/> 

The result of this is an attacker could potentially gain access to protected resources due to this missing rule.


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

## How can Contrast help? 
<br/>

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) observes the data flows in the source code and identifies if your custom code is vulnerable to this attack. 

- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
