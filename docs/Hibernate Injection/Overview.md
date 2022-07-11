---
layout: page
title: Overview
permalink: /io/Hibernate Injection/Overview
parent: Hibernate Injection
nav_order: 1
---

## Hibernate Injection

### What Is It?


If data is not validated or encoded, it's possible that an attacker can craft a malicious piece of input that can allow Hibernate Query Language injection. 

Hibernate is an object-relational mapping (ORM) library for Java, providing a framework for mapping an object-oriented domain model to a traditional relational database. It provides an abstraction layer between application code and the underlying database.  

In the normal use of Hibernate, Java objects are mapped to the underlying database in such a manner that allows the developer to interact with just the Java object without the need to develop any custom SQL code to access the database table the object is mapped to. 

However, in certain circumstances, the developer may want to write their own custom SQL code to access the underlying database. Hibernate supports this use case by providing its own Hibernate Query Language (HQL), which is very similar to SQL, but abstracts away the type of underlying database that Hibernate is accessing.

When developing HQL queries, developers can introduce Hibernate Injection flaws, just like they can introduce SQL injection flaws, by appending user supplied data to an HQL query they are constructing. HQL queries are created using Hibernate's ```createQuery()``` method.  
You can also create native SQL queries in Hibernate using Hibernate's ```createSQLQuery()``` method. 

### When Can It Affect My Application?


Here is an example of an **unsafe** HQL Statement:
 
```
Query unsafeHQLQuery = session.createQuery("from Inventory inv where inv.productID = '" + userSuppliedParameter + "'");
```



### Impact


### How can Contrast help?







