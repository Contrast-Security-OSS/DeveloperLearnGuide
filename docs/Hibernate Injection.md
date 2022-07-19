---
layout: default
title: Hibernate Injection
nav_order: 13
---

# Hibernate Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

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
TODO

## How To Fix

There are several primary techniques for making the use of Hibernate safe from Hibernate Injection: 
1. Avoid the construction of dynamic HQL, and:
2. Use bind variables to make it safe to use unsafe data within an HQL query. 
3. This approach involves avoiding the use of old deprecated Hibernate methods that are subject to HQL injection. 


### Approach #1: Avoid Dynamic HQL

One of the beauties of Hibernate is that you usually don't have to write custom SQL code. If you need to remediate a Hibernate injection flaw, we recommend that you examine the query first to see if you can rewrite the code to eliminate the custom query entirely. 

If you can instead simply access the Java objects mapped to the database with Hibernate, this will eliminate the custom Hibernate query entirely. Hibernate ensures that the queries it generates when mapped Java objects are accessed are safe from SQL injection through the use of Prepared Statements

### Approach #2: Use Bind Variables 

If you can't eliminate the custom HQL, then modifying the query to use bind variables in place of doing direct string concatenations of dangerous input will also fix the problem. Consider the example unsafe query:

```
Query unsafeHQLQuery = session.createQuery("from Inventory inv where inv.productID = '" + userSuppliedParameter + "'");
``` 

There are numerous ways to use bind variables in Hibernate queries. For full details on all these methods and alternate method signatures for many of the methods used in the examples that follow see: [Hibernate Session class](https://docs.jboss.org/hibernate/orm/3.5/javadoc/org/hibernate/Session.html)


Here are a number of different approaches for using bind variables with Hibernate queries: 

**Binding Technique 1: Named Parameters**

```
Query safeHQLQuery = session.createQuery("from Inventory inv where inv.productID = :productid");
safeHQLQuery.setParameter("productid", userSuppliedParameter); // for named parameters, setParameter can be used regardless of the data type being set
```

Note: There are 4 different method signatures for ```setParameter()``` and there is also ```setParameters(Object[]``` values, ```Type[]``` types.

**Binding Technique 2: Bind Variables**  

```
Query safeHQLQuery2 = session.createSQLQuery("from Inventory where productID = ?");
safeHQLQuery2.setString(0, userSuppliedParameter);  // 0 is the position parameter, where the count starts with 0, then 1, etc.
``` 

With unnamed parameters, the proper set method has to be used based on the data type being set. Hibernate supports a rich set of data type specific methods for setting the values of bind variables. Some examples are: 

```
setString( position, value);
setInt( position, value);
setLong( position, value);
``` 

**Binding Technique #3: Named Parameters using setProperties** 
You can pass an object into the parameter binding. Hibernate will automatically check the object's properties and match a property with the same name as the named parameter. 

```
Stock stock = new Stock();
stock.setStockCode("1234");
Query query = session.createQuery("from Stock s where s.stockCode = :stockCode");
query.setProperties(stock);
``` 

Note: ```setProperties()``` can set multiple named parameters in a single call. 
It will set every named parameter in the query that has a matching property value in the object passed in. 

**Binding Technique #4: Named Parameter List** 

```
Query query = session.createQuery("from TABLENAME t where t.name in (:listOfNames)");
query.setParameterList("listOfNames", namesFromUser);
``` 

Note: There are 4 different method signatures for ```setParameterList()```. 

**Binding Technique #5: Use Named Queries** 
You can generate the equivalent of a Hibernate Stored Procedure by creating a named query. Such named queries are stored in Hibernate mapping files rather than in the database itself since they are not dependent on any particular database type. Here's an example: 

```
<query name="ByNameAndMaximumWeight"><![CDATA[
     from eg.animals as anim
     where anim.name = ?
     and anim.weight > ?
     ] ]></query>
``` 

Parameter binding and executing is done programmatically: 

```
Query query = session.getNamedQuery("ByNameAndMaximumWeight");
     query.setString(0, name);
     query.setInt(1, minWeight);
     List animals = query.list();
```

### Approach #3: Avoid Use of Old Deprecated Dangerous Hibernate Methods ###  

The Hibernate Session class originally implemented 5 different methods with various signatures for each (total of 14 method signatures) that were all subject to HQL injection. These methods are now deprecated but still available in the [Session class](https://docs.jboss.org/hibernate/orm/3.5/javadoc/org/hibernate/Session.html) through an alternate version of the [interface](https://docs.jboss.org/hibernate/orm/3.5/javadoc/org/hibernate/classic/Session.html), which extends the Session interface. 
If you are still using any code that calls the following methods in this interface:

```
createSQLQuery(String sql, String[] returnAliases, Class[] returnClasses)
createSQLQuery(String sql, String returnAlias, Class returnClass)
delete(String query)
delete(String query, Object[] values, Type[] types)
delete(String query, Object value, Type type)
filter (3 versions)
find (3 versions)
iterate (3 versions)
```
 

you should replace their use with the replacement method recommended in the [documentation](https://docs.jboss.org/hibernate/orm/3.5/javadoc/org/hibernate/classic/Session.html) for this deprecated interface{{/link}}, and then make sure your use of the replacement method is safe from Hibernate injection.

### How can Contrast help? 
- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect these vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block these attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.


