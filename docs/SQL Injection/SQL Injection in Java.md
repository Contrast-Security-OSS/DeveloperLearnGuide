---
layout: page
title: SQL Injection in Java
permalink: /io/SQL Injection/SQL Injection in Java
parent: SQL Injection
nav_order: 5
---

## SQL Injection in Java 
<br/>

The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) like [Hibernate](https://hibernate.org/orm/) that safely handles database interaction. 
<br/>
If you must execute queries manually, use [Callable Statements](https://docs.oracle.com/javase/6/docs/api/index.html) for stored procedures and [Prepared Statements](https://docs.oracle.com/javase/6/docs/api/index.html) for normal queries. 

Both of these APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 
You must still avoid concatenating user supplied input to queries and use the binding pattern to keep user input from being misinterpreted as SQL code.

- Take this unsafe query as an example: 

```
String user = request.getParameter("user");
String pass = request.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
  Statement statement = connection.createStatement( );
  ResultSet results = statement.executeQuery( query ); // Unsafe!
}
```

- Now let's use ```PreparedStatement``` to make the above query safe: 

```
String user = request.getParameter("user");
String pass = request.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = ? and user_password = ?";
try {
  PreparedStatement pstmt = connection.prepareStatement( query );
  pstmt.setString( 1, user );
  pstmt.setString( 2, pass );
  pstmt.execute(); // Safe!
}
``` 


There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity 
of variables is not predetermined. If you are unable to avoid building such a SQL call on the fly, then validation and escaping all 
user data is necessary.
<br/>
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed.  
This is difficult to do by hand, but luckily the [ESAPI](https://owasp.org/www-project-enterprise-security-api/) library offers such functionality. 

Here's an example of safely encoding a dynamically built statement for an Oracle database using untrusted data: 

```
Codec ORACLE_CODEC = new OracleCodec();
String user = req.getParameter("user");
String pass = req.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + 
     ESAPI.encoder().encodeForSQL( ORACLE_CODEC, **user**) + "' and user_password = '" +
     ESAPI.encoder().encodeForSQL( ORACLE_CODEC, **pass**) + "'";{{/javaBlock}}
```


### MyBatis Framework 
<br/>

MyBatis doesn't modify or escape the string when the ```${}``` syntax is used in dynamic SQL queries.  
This causes the mapped value to be directly inserted into the query, which can lead to SQL injection attacks. 

Applications using MyBatis should use the ```#{}``` syntax on untrusted data. 

This tells MyBatis to generate a [String Substitution](https://mybatis.org/mybatis-3/sqlmap-xml.html#String_Substitution) which are incomplete SQL queries with placeholders that, at run-time, are replaced by user input. 
This treats user input as parameter content instead of as part of an SQL command.  