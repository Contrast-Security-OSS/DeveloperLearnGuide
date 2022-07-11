---
layout: page
title: Second Order SQL Injection
permalink: /io/SQL Injection/Second Order SQL Injection
parent: SQL Injection
nav_order: 
---

## Second Order SQL Injection 

With a maliciously crafted input, an end user could change the structure of the SQL query and perform a Second order SQL Injection attack, despite not executed **directly** at runtime. 

Second order SQL injection is possible when user supplied data is stored by the application, and **later triggered** and included in an unsafe SQL query. 

The goal of such attacks is to force the database to retrieve and output data to which the user would not otherwise have access. For example, an attacker could use Second order SQL Injection on a vulnerable web application by registering an unsafe username. 
This would then be stored in the User table, and executed at a later date to retrieve or manipulate data. 



### Attack Scenario

TODO.



### Impact


A successful Second Order SQL injection exploit can read sensitive data from the database. 
Aditioally it can also extend to privilege escalation, account hijacking, and in some cases, it may be possible for an attacker to gain shell access to the database server.


### Prevention

The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) like [Hibernate](https://hibernate.org/orm/) that safely handles database interaction. 
If you must execute queries manually, use [Callable Statements](https://docs.oracle.com/javase/6/docs/api/index.html)for stored procedures and [Prepared Statements](https://docs.oracle.com/javase/6/docs/api/index.html) for normal queries. 

Both of these APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 
You must still avoid concatenating user supplied input to queries and use the binding pattern to keep user input from being misinterpreted as SQL code.

- Take this unsafe query as an example:

```
String user = request.getParameter("user");
String pass = request.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
Statement statement = connection.createStatement( );
}
ResultSet results = statement.executeQuery( query ); // Unsafe!}
``` 

- Now, let's fix this using ```PreparedStatement``` 

```
String user = request.getParameter("user");
String pass = request.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = ? and user_password = ?";
try {
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, user );
.setString( 2, pass );
pstmt.execute(); // Safe!
}
``` 


There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity of variables 
is not predetermined. 

If you are unable to avoid building such a SQL call on the fly, then validation and escaping all user data is necessary. Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed. 

This is difficult to do by hand, but luckily the[ESAPI](https://owasp.org/www-project-enterprise-security-api/)library offers such functionality. 

Here's an example of safely encoding a dynamically built statement for an Oracle database using untrusted data: 

```
Codec ORACLE_CODEC = new OracleCodec();
String user = req.getParameter("user");
String pass = req.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + ESAPI.encoder().encodeForSQL( ORACLE_CODEC, **user**) + "' and user_password = '" + ESAPI.encoder().encodeForSQL( ORACLE_CODEC, **pass**) + "'";
```


### How can Contrast help?




