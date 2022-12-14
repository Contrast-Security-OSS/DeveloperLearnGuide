---
layout: default
title: Log4Shell
nav_order: 4
---

# Log4Shell
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Log4Shell

### log4j
<br/>
First, let's talk about the affected package. log4j is a programming library (ie. pre-written code) that appears in millions of computer applications globally. 
It is free, open-source, and has been widely-used since 2001.

Applications use Log4j to write short amounts of information into files/databases for “logging” purposes. 

### What is Log4Shell? 
<br/>
Log4Shell is the nickname provided to the Remote Code Execution (RCE) vulnerability that was disclosed in the log4J utility managed by the Apache Foundation. 
Specifically, Log4Shell refers to [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and associated vulnerabilities. 

If an application is using a vulnerable version of log4j, an attacker can trigger the application to reach out to an attacker-controlled host which then deploys malicious code on the application’s server and gives the attacker control over the application and the server it sits on. 
<br/><br/>

<img width="790" alt="log4jcontrast" src="https://user-images.githubusercontent.com/50103523/178735853-bfc0dfdf-6713-4eb1-b463-ce88a33e21a7.png"> 
<br/>

A single web request can be enough to initiate a log4j hack. Often the request can occur even before a user
is authenticated. 

### Demo
<br/>


<p><a href="https://www.contrastsecurity.com/security-influencers/contrast-vs-the-log4j2-cve-a-demonstration?wvideo=80y2qkb6aq"><img src="https://embed-ssl.wistia.com/deliveries/d996a1a71283e29ebd26b0d4bcf46f6b41a2e14e.jpg?image_play_button_size=2x&amp;image_crop_resized=960x540&amp;image_play_button=1&amp;image_play_button_color=ffffffe0" width="400" height="225" style="width: 400px; height: 225px;"></a></p><p><a href="https://www.contrastsecurity.com/security-influencers/contrast-vs-the-log4j2-cve-a-demonstration?wvideo=80y2qkb6aq">Log4j Contrast Demonstration</a></p> 


### Impact 
<br/>

Log4Shell is a critical vulnerability, and can allow attackers to execute malicious code remotely to a target.
If exploited, impact can range from theft of data, installation of malware, and full takeover of system. 


## How To Fix 

**log4j2**

For users of log4j2, please upgrade log4j-core to version 2.17.1. In versions that cannot be upgraded, remove the JNDI Lookup class from the class path via the following: 

```java
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class. 
``` 

For custom applications, we recommend that you update the library, rebuild, and redeploy the application

For vendor applications, obtain updated software from the vendor. 
If they do not have an update or you do not apply the update, your systems and their data are at high risk or remote exploitation. 

**log4j1**

Teams that locate log4j1 should follow recommendations to either upgrade to log4j v2.16 or to remove the JMSAppender and SocketServer classes from the library. To do this run the following (with your version of log4j in the path):

```
zip -d log4j-1.x.x.jar org/apache/log4j/net/JMSAppender.class
```

```
zip -d log4j-1.x.x.jar org/apache/log4j/net/SocketServer.class
``` 

Teams should leverage the [SBOM](https://www.contrastsecurity.com/security-influencerssecuring-the-software-supply-chain-starts-with-a-software-bill-of-materials-sbom) (Software Bill of Materials) that tools like Contrast produce, to locate log4j and other vulnerable libraries. 
These inventories provide immediate guidance on which applications are affected so that you can take action.

We recommend looking at other applications where you have not yet created an inventory. 
You can use a tool such as SafeLog4J to evaluate these applications. 

