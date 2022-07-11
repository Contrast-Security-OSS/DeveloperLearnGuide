---
layout: page
title: How To Fix
permalink: /io/Log4Shell/How To Fix
parent: Log4Shell
nav_order: 3
---

## How To Fix

Teams should leverage the Software Bill of Materials that tools like Contrast produce, to locate Log4J and other vulnerable libraries. 
These inventories provide immediate guidance on which applications are affected so that you can take action.

We recommend looking at other applications where you have not yet created an inventory. 
You can use a tool such as SafeLog4J to evaluate these applications.



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

