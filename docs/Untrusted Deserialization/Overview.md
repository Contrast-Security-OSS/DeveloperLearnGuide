---
layout: page
title: Overview
permalink: /io/Untrusted Deserialization/Overview
parent: Untrusted Deserialization
nav_order: 1
---



## What Is It?

nsecure deserialization, the unpacking and reconstitution of user-supplied data, represents an application vulnerability in which all serialized data structures are treated the same—that is, by default, data received from an unvalidated source is treated the same as data received from a validated one. If exploited, data deserialized insecurely can serve as an embarkation point for a cascading series of cyberattacks, including denial of service (DoS), authentication bypass, remote code execution attacks, and SQL injection.

To illustrate, an application attack can assail a web application by loading malicious code into a serialized object and pass it to the application. If the web application deserializes user-controlled input in the absence of any validation check, the malicious code is enabled to access more surface area of the application. Subsequently, this sets the table for the initiation of secondary application attacks that could potentially lead to sensitive data exposure.




https://github.com/Contrast-Security-Inc/rule-i18n-resources/tree/master/src/main/resources/i18n/rulepack/untrusted-deserialization/risk-mustache

## When Can It Affect My Application?





## Impact


## Prevention

There are only a few options for securing the deserialization of untrusted objects. The first, and most safe option, is to remove 
the deserializing of user input completely. Although the recommendations today appear to be totally effective, it's worth noting 
that attacks against serialization have been getting more effective for many years. 

The consensus amongst security researchers is that developers should be moving away from object serialization when possible.

For language specific fix details and deep dive, please visit the links below:

