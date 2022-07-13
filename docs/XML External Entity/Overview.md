---
layout: page
title: Overview
permalink: /io/XML External Entity/Overview
parent: XML External Entity
nav_order: 1
---

## XML External Entity 


### What Is It? 

An XML External Entity (XXE) attack can occur when an application parses an XML document from an untrusted source, with a parser that doesn't disable resolution of external entities. 

Attackers can supply malicious XML to this interface, and trick the XML interpreter into leaking sensitive server side data back to the attacker.


### Scenario 


Let's look at an example attack. The following is a malicious document that an attacker would send. 
Notice the malicious ENTITY defined in the DOCTYPE: 

```
<?xml version="1.0"?>
<!DOCTYPE root
[
<!ENTITY attack SYSTEM "file:///etc/passwd">
]>
<status>&attack;</status>
``` 

To the XML interpreter, the "attack" entity is defined as the contents of the /etc/passwd file. 
Since the XML interpreter hasn't been instructed to ignore external entities, it will perform this resolution and replace the `&attack;` entity with that file. 

In our example scenario, when the attacker views the status code in the resulting web page, they see something like the following: 

```
    Thanks for your upload! The status of the document is:
    <!-- Print out the status code from the XML document -->
    root:*:0:0:System Administrator:/var/root:/bin/sh
    daemon:*:1:1:System Services:/var/root:/usr/bin/false
```

To fully exploit this vulnerability, an attacker must be able to supply the malicious XML to the XML interpreter and see any of the data after it has entered the application. 
In the majority of cases, attackers who meet the first condition almost always also meet the second.



### Impact

A successful exploit can result in local files containing sensitive data, such as passwords, being disclosed.
Additionally, it is also common to use this vulnerability to perform a Denial of Service (DoS) attack. 
Attackers can also utilize this flaw to laterally traverse to other internal systems, leading to a potential SSRF attack.



### How can Contrast help? 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect XXE vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block XXE attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect XXE vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.

