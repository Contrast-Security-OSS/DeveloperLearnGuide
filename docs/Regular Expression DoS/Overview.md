---
layout: page
title: Overview
permalink: /io/Regular Expression DoS/Overview
parent: Regular Expression DoS
nav_order: 1
---

## Regular Expression DoS

## What Is It?


Regular expressions can reside in every layer of the web. The Regular expression Denial of Service (ReDoS) produces one or more regular expressions or regex(s) that “run on and on” by design. Using an “evil regex,” the attacker is able to exploit a web browser on either computer or mobile device, hang up a Web Application Firewall (WAF), or attack a vulnerable database or web server.

With a ReDoS attack, carefully crafted inputs trick innocent but regular expressions to run indefinitely. ReDoS will either slow down the application or completely crash it, as the regex engine tries to find a match by running every possible combination of characters. When all permutations fail to find a match, the regular expression will run on forever until manually terminated.


## When Can It Affect My Application?





## Impact


### How can Contrast help?
