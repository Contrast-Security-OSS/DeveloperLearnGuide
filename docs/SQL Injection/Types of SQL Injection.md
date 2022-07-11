---
layout: page
title: Types of SQL Injection
permalink: /io/SQL Injection/Types of SQL Injection
parent: SQL Injection
nav_order: 1
---

# Types of SQL injection

SQL injection can be categorized into three categories: in-band, blind, and out-of-band.  

### In-band SQL injection 

In-band SQL injection is the most frequent and commonly used SQL injection attack. 
The transfer of data used in in-band attacks can either be done through error messages on the web or by using the UNION operator in SQL statements. 

There are two types of in-band SQL injection: union-based and error-based SQL injection.

- Union-based SQL injection. When an application is vulnerable to SQL injection and the application’s responses return the results for a query, attackers use the UNION keyword to retrieve data from other tables of the application database.

- Error-based SQL injection. The error-based SQL injection technique relies on error messages thrown by the application database servers. Here, attackers use the error message information to determine the entities of the database.


### Blind SQL injection 

In a blind SQL injection attack, after sending a data payload, the attacker observes the behavior and responses to determine the data structure of the database.

There are two types of blind or inferential SQL injection attacks: Boolean and time based.

- Boolean based. The Boolean-based technique sends SQL queries to the database to force the application to return a Boolean result—that is, either a TRUE or FALSE result. Attackers perform various queries blindly to determine the vulnerability.
- Time based. The time-based SQL injection attack is often used when an application returns generic error messages. 
This technique forces the database to wait for a specific time. The response time helps the attacker to identify the query returns as TRUE or FALSE. 

### Out-of-band SQL injection 

The out-of-band SQL injection attack requests that the application transmit data via any protocol—HTTP, DNS, or SMB. To perform this type of attack, the following functions can be used on Microsoft SQL and MySQL databases, respectively:

- MS SQL: master..xp _dirtree
- MySQL: LOAD_FILE()



