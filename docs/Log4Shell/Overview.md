---
layout: page
title: Overview
permalink: /io/Log4Shell/Overview
parent: Log4Shell
nav_order: 1
---

## Log4Shell

### Log4j

First, let's talk about the affected package. Log4j is a programming library (ie. pre-written code) that appears in millions of computer applications globally. 
It is free, open-source, and has been widely-used since 2001.

Applications use Log4j to write short amounts of information into files/databases for “logging” purposes. 

### What is Log4Shell? 

<img
  src="/path/to/img.jpg"
  alt="Alt text"
  title="Optional title"
  style="display: inline-block; margin: 0 auto; max-width: 300px"> 

Log4Shell is the nickname provided to the Remote Code Execution (RCE) vulnerability that was disclosed in the Log4J utility managed by the Apache Foundation. 
Specifically, Log4Shell refers to [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and associated vulnerabilities. 

If an application is using a vulnerable version of Log4j, an attacker can trigger the application to reach out to an attacker-controlled host which then deploys malicious code on the application’s server and gives the attacker control over the application and the server it sits on. 

<img
  src="/assets/images/log4jcontrast.png"
  alt="Alt text"
  title="Optional title"
  style="display: inline-block; margin: 0 auto; max-width: 300px"> 

A single web request can be enough to initiate a Log4j hack. Often the request can occur even before a user
is authenticated. 
- Some 8.2 million programmers around the world currently use Java (ZDNet)
- 58% of Java apps contain vulnerable versions of Log4j

### Demo

<p><a href="https://www.contrastsecurity.com/security-influencers/contrast-vs-the-log4j2-cve-a-demonstration?wvideo=80y2qkb6aq"><img src="https://embed-ssl.wistia.com/deliveries/d996a1a71283e29ebd26b0d4bcf46f6b41a2e14e.jpg?image_play_button_size=2x&amp;image_crop_resized=960x540&amp;image_play_button=1&amp;image_play_button_color=ffffffe0" width="400" height="225" style="width: 400px; height: 225px;"></a></p><p><a href="https://www.contrastsecurity.com/security-influencers/contrast-vs-the-log4j2-cve-a-demonstration?wvideo=80y2qkb6aq">Log4j Contrast Demonstration</a></p>



### Impact 


Log4Shell is a critical vulnerability, and can allow attackers to execute malicious code remotely to a target.
If exploited, impact can range from theft of data, installation of malware, and full takeover of system. 





### How can Contrast help?



- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) defend the applications against the underlying vulnerability. 
This means, Contrast was protecting you against the log4j vulnerability long before it was disclosed as a CVE.

- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) & [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can identify that the application uses the vulnerable version of Log4j. 
Our runtime context also allows you to identify which applications use JMSAppender, the specific class that can be exploited using this CVE.

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) application security detects the underlying vulnerability in applications. 
This means, Contrast will find the next application vulnerability like this one, before it becomes a disclosed CVE or major incident. 

- [Contrast Serverless](https://www.contrastsecurity.com/contrast-serverless) can not only detect Lambda functions with vulnerable versions of this library but can also verify whether these functions are vulnerable to Log4Shell.


