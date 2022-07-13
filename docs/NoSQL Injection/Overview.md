---
layout: page
title: Overview
permalink: /io/NoSQL Injection/Overview
parent: NoSQL Injection
nav_order: 1
---

## NoSQL Injection

### What Is It?
<br/>
NoSQL injection occurs when developers hand-build NoSQL statements containing user-supplied data without validation or encoding. 



### Impact
<br/>
The goal of such attacks is to force the database to retrieve and output data to which the user would not otherwise have access. 

For example, an attacker could use NoSQL Injection on a vulnerable application in order to query the database for customer credit card numbers and other data, even if it wasn't part of the query the developer created. NoSQL injection also allows privilege escalation and account hijacking.


### How can Contrast help?

 - [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect NoSQLi vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block NoSQLi attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect NoSQLi vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.












