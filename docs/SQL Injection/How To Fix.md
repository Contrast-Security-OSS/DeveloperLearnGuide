---
layout: page
title: How To Fix
permalink: /io/SQL Injection/How To Fix
parent: SQL Injection
nav_order: 3
---

# SQL Injection Cheat Sheet 

Organizations need to compile a SQL injection cheat sheet to ensure they effectively prevent SQL injection attacks. 
Effective vulnerability detection and remediation during application development is a critical linchpin in preventing SQL injection attacks. 

This requires a comprehensive application security approach that shifts security testing to the left—which incurs significantly less time and cost to remediate—and embeds security within software using instrumentation. The latter creates continuous, real-time security testing versus legacy application security scanning approaches that are point in time and produce large volumes of false positives.

Securing applications in development is only one part of the SQL injection equation. Once code is released into production, the same continuous, accurate application security approach is required. 


In addition to the above, there are a few other security practices that organizations can enact as part of their SQL injection cheat sheet:

- **Parameterized queries** 

A parameterized query is a query in which parameters are used as placeholders and are supplied at execution time. 
In this type of query, the data types of the parameters are predefined, and in some cases, default values are also set. Doing so causes SQL injection queries to fail. 

- **Stored procedures** 

Stored procedures are the SQL statements defined and stored in the database, which are called from the application. 
Developers normally build SQL statements with parameters that are automatically parameterized. However, developers can generate dynamic SQL queries inside stored procedures that eliminate the risk.

- **Refrain from administrative privileges**  

Blocking connections with applications to their databases using an account having root access or administrative privilege is also an effective protection. This prevents bad actors from gaining access to the whole database. 
Regardless, a non-administrative account server can also be risky for an application, primarily if it is used in various databases and applications.

SQL injection attacks can pose serious risks, and organizations need to ensure they have the right application security solutions in place. 
It starts when application development commences and extends all of the way through production.

## How can Contrast Security secure your application against SQL Injection attacks? 


<iframe width="560" height="315" src="https://www.youtube.com/embed/qisfDONFgAU" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
