---
layout: page
title: Overview
permalink: /io/Log4Shell/Overview
parent: Log4Shell
nav_order: 1
---

## Log4Shell


Log4shell is the nickname provided to the Remote Code Execution (RCE) vulnerability that was disclosed in the Log4J utility managed by the Apache Foundation. Specifically, log4shell refers to CVE-2021-44228 and associated vulnerabilities. 

If an application is using a vulnerable version of log4j, an attacker can trigger the application to reach out to an attacker-controlled host which then deploys malicious code on the application’s server and gives the attacker control over the application and the server it sits on. 


### Demo

<p><a href="https://www.contrastsecurity.com/security-influencers/contrast-vs-the-log4j2-cve-a-demonstration?wvideo=80y2qkb6aq"><img src="https://embed-ssl.wistia.com/deliveries/d996a1a71283e29ebd26b0d4bcf46f6b41a2e14e.jpg?image_play_button_size=2x&amp;image_crop_resized=960x540&amp;image_play_button=1&amp;image_play_button_color=ffffffe0" width="400" height="225" style="width: 400px; height: 225px;"></a></p><p><a href="https://www.contrastsecurity.com/security-influencers/contrast-vs-the-log4j2-cve-a-demonstration?wvideo=80y2qkb6aq">Log4j Contrast Demonstration</a></p>



### Impact 


Log4Shell is a critical vulnerability, and can allow attackers to execute malicious code remotely to a target.
If exploited, impact can range from theft of data, installation of malware, and full takeover of system.





### How can Contrast help?



- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) defend the applications against the underlying vulnerability. 
This means, Contrast was protecting you against the log4j vulnerability long before it was disclosed as a CVE.

- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) & [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can identify that the application uses the vulnerable version of log4j. 
Our runtime context also allows you to identify which applications use JMSAppender, the specific class that can be exploited using this CVE.

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) application security detects the underlying vulnerability in applications. 
This means, Contrast will find the next application vulnerability like this one, before it becomes a disclosed CVE or major incident.


