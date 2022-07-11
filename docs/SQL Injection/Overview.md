---
layout: page
title: Overview
permalink: /io/SQL Injection/Overview
parent: SQL Injection
nav_order: 1
---

# What Is It?


A SQL injection attack consists of an insertion or injection of a SQL query via the input data from the client to the application. SQL commands are injected into data-plane input that affect the execution of predefined SQL commands. This attack is possible when developers hand-build SQL statements containing user-supplied data without validation or encoding. The goal of such attacks is to force the database to retrieve and output data to which the user would not otherwise have access. Hackers use SQL injection attacks to access sensitive business or personally identifiable information (PII), which ultimately increases sensitive data exposure.

SQL injection attacks are one of the most prevalent among OWASP Top 10 vulnerabilities, and one of the oldest application vulnerabilities. One recent report lists it as the third most common serious vulnerability.


## Impact


A successful SQL injection exploit can read sensitive data from the database, modify database data (, insert, update, or delete), execute administrative operations on the database, recover the content of a file present in the database management system, and even issue commands to the operating system in some instances.

One example is an attacker could use SQL Injection on a vulnerable application in order to query the database for customer credit card numbers and other data, even if it wasn't part of the query the developer created. 

## When Can It Affect My Application?


If a web application or website uses SQL databases like Oracle, SQL Server, or MySQL, it is vulnerable to an SQL injection attack. 


## How Do People Attack Using This Flaw?


To perform an SQL injection attack, an attacker must locate a vulnerable input in a web application or webpage. When an application or webpage contains a SQL injection vulnerability, it uses user input in the form of an SQL query directly. The hacker can execute a specifically crafted SQL command as a malicious cyber intrusion. Then, leveraging malicious code, a hacker can acquire a response that provides a clear idea about the database construction and thereby access to all the information in the database.  

<iframe width="560" height="315" src="https://www.youtube.com/embed/Bo4Be7aV3Ik" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

An attacker may perform SQL injection with the following approaches: 

### SQL statement that is always true
A hacker executes an SQL injection with an SQL statement that is always true. For instance, 1=1; instead of just entering the “wrong” input, the hacker uses a statement that will always be true. 

Entering “100 OR 1=1” in the query input box will return a response with the details of a table.

### "OR ""="

This SQL injection approach is similar to the above. A bad actor needs to enter "OR ""=" into the query input box. These two signs serve as the malicious code to break into the application. Consider the following example. 

An attacker seeks to retrieve user data from an application and can simply type “OR=” in the user ID or password. As this SQL statement is valid and true, it will return the data of the user table in the database. 









