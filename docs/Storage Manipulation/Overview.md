---
layout: page
title: Overview
permalink: /io/Storage Manipulation/Overview
parent: Storage Manipulation
nav_order: 1
---



## What Is It?





## When Can It Affect My Application?





### Impact


An attacker may be able to use this flaw in order to exploit the storage vulnerability further by performing DOM-based attacks, such as Cross Site Scripting (XSS), and JavaScript Injection.


### Prevention

The most effective method of preventing HTML5-Storage manipulation is to verify the origin of the sender, and perform input validation on the data attribute to confirm it is in the desired format.  

Most importantly always restrict data from untrusted sources being placed in HTML5 storage.

