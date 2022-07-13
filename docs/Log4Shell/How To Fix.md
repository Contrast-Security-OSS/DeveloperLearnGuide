---
layout: page
title: How To Fix
permalink: /io/Log4Shell/How To Fix
parent: Log4Shell
nav_order: 3
---

## How To Fix

Teams should leverage the [SBOM](https://www.contrastsecurity.com/security-influencers/securing-the-software-supply-chain-starts-with-a-software-bill-of-materials-sbom) (Software Bill of Materials) that tools like Contrast produce, to locate Log4J and other vulnerable libraries. 
These inventories provide immediate guidance on which applications are affected so that you can take action.

We recommend looking at other applications where you have not yet created an inventory. 
You can use a tool such as SafeLog4J to evaluate these applications. 

Alternatively, check out how we can help to detect and protect your application 



### Once You have located your Log4j, what should you do?


**Log4j2**

For users of log4j2, please upgrade log4j-core to version 2.17.1. In versions that cannot be upgraded, remove the JNDI Lookup class from the class path via the following: 

```
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class. 
```


For custom applications, we recommend that you update the library, rebuild, and redeploy the application

For vendor applications, obtain updated software from the vendor. 
If they do not have an update or you do not apply the update, your systems and their data are at high risk or remote exploitation.



**Log4j1**

Teams that locate Log4j1 should follow recommendations to either upgrade to log4j v2.16 or to remove the JMSAppender and SocketServer classes from the library. To do this run the following (with your version of log4j in the path):

```
zip -d log4j-1.x.x.jar org/apache/log4j/net/JMSAppender.class
```


```
zip -d log4j-1.x.x.jar org/apache/log4j/net/SocketServer.class
```

### How can Contrast help?



- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) defend the applications against the underlying vulnerability. 
This means, Contrast was protecting you against the log4j vulnerability long before it was disclosed as a CVE.

- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) & [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can identify that the application uses the vulnerable version of Log4j. 
Our runtime context also allows you to identify which applications use JMSAppender, the specific class that can be exploited using this CVE.

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) application security detects the underlying vulnerability in applications. 
This means, Contrast will find the next application vulnerability like this one, before it becomes a disclosed CVE or major incident.