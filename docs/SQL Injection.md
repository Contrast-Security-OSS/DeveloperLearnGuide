---
layout: default
title: SQL Injection
nav_order: 1
---

# SQL Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

### Overview 
<br/> 

A SQL injection attack consists of an insertion or injection of a SQL query via the input data from the client to the application. SQL commands are injected into data-plane input that affect the execution of predefined SQL commands. 

This attack is possible when developers hand-build SQL statements containing user-supplied data without validation or encoding. The goal of such attacks is to force the database to retrieve and output data to which the user would not otherwise have access. 
Hackers use SQL injection attacks to access sensitive business or personally identifiable information (PII), which ultimately increases sensitive data exposure.

SQL injection attacks are one of the most prevalent among OWASP Top 10 vulnerabilities, and one of the oldest application vulnerabilities. One recent report lists it as the third most common serious vulnerability. 

If a web application or website uses SQL databases like Oracle, SQL Server, or MySQL, it is vulnerable to an SQL injection attack. 



### Impact 
<br/> 

A successful SQL injection exploit can read sensitive data from the database, modify database data (insert, update, or delete), execute administrative operations on the database, recover the content of a file present in the database management system, and even issue commands to the operating system in some instances.

One example is an attacker could use SQL Injection on a vulnerable application in order to query the database for customer credit card numbers and other data, even if it wasn't part of the query the developer created. 


### How Is This Flaw Exploited?
<br/> 

To perform an SQL injection attack, an attacker must locate a vulnerable input in a web application or webpage. When an application or webpage contains a SQL injection vulnerability, it uses user input in the form of an SQL query directly. 
The hacker can execute a specifically crafted SQL command as a malicious cyber intrusion. 
Then, leveraging malicious code, a hacker can acquire a response that provides a clear idea about the database construction and thereby access to all the information in the database.   

<iframe width="560" height="315" src="https://www.youtube.com/embed/Bo4Be7aV3Ik" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<br/>
An attacker may perform SQL injection with the following approaches: 

- **SQL statement that is always true**
A hacker executes an SQL injection with an SQL statement that is always true. For instance, 1=1; instead of just entering the “wrong” input, the hacker uses a statement that will always be true. 

Entering “100 OR 1=1” in the query input box will return a response with the details of a table.

- **"OR ""="**

This SQL injection approach is similar to the above. A bad actor needs to enter "OR ""=" into the query input box. These two signs serve as the malicious code to break into the application. Consider the following example. 

An attacker seeks to retrieve user data from an application and can simply type “OR=” in the user ID or password. As this SQL statement is valid and true, it will return the data of the user table in the database. 


## Types of SQL injection 

SQL injection can be categorized into three categories: in-band, blind, and out-of-band.  

### In-band SQL injection 
<br/> 

In-band SQL injection is the most frequent and commonly used SQL injection attack. 
The transfer of data used in in-band attacks can either be done through error messages on the web or by using the UNION operator in SQL statements. 

There are two types of in-band SQL injection: union-based and error-based SQL injection.

- Union-based SQL injection. When an application is vulnerable to SQL injection and the application’s responses return the results for a query, attackers use the UNION keyword to retrieve data from other tables of the application database.

- Error-based SQL injection. The error-based SQL injection technique relies on error messages thrown by the application database servers. Here, attackers use the error message information to determine the entities of the database.


### Blind SQL injection 
<br/> 

In a blind SQL injection attack, after sending a data payload, the attacker observes the behavior and responses to determine the data structure of the database.

There are two types of blind or inferential SQL injection attacks: Boolean and time based.

- Boolean based. The Boolean-based technique sends SQL queries to the database to force the application to return a Boolean result—that is, either a TRUE or FALSE result. Attackers perform various queries blindly to determine the vulnerability.
- Time based. The time-based SQL injection attack is often used when an application returns generic error messages. 
This technique forces the database to wait for a specific time. The response time helps the attacker to identify the query returns as TRUE or FALSE. 

### Out-of-band SQL injection 
<br/> 

The out-of-band SQL injection attack requests that the application transmit data via any protocol—HTTP, DNS, or SMB. To perform this type of attack, the following functions can be used on Microsoft SQL and MySQL databases, respectively:

- MS SQL: master..xp _dirtree
- MySQL: LOAD_FILE() 



## SQL Injection in .NET 
<br/> 

The most effective method of stopping SQL injection attacks is to only use a [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) like [Entity Framework](https://docs.microsoft.com/en-us/ef/) that safely handles database interaction. 

If you must execute queries manually, use the [class](https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand?view=dotnet-plat-ext-6.0) with ```CommandType.StoredProcedure``` for stored procedures, and ```CommandType.Text``` for normal queries. 

Both of these APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 


You must still avoid concatenating user supplied input to queries and use the binding pattern to keep user input from being 
misinterpreted as SQL code.


### Recommendations for .NET Framework  


### Using Parameterization 
<br/> 

**C# Example** 

- Take this unsafe query as an example: 

```csharp
String user = Request.QueryString("user");
String pass = Request.QueryString("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
	SqlCommand command = new SqlCommand(query,connection);
	SqlDataReader reader = command.ExecuteReader(); // unsafe
	// ...
}
``` 
<br/>

- Now, let's fix this using parameterization: 

```csharp
String user = Request.QueryString("user");
String pass = Request.QueryString("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = @user and user_password = @pass";
try {
	SqlCommand command = new SqlCommand(query,connection);
	command.Parameters.AddWithValue("@user", user);
	command.Parameters.AddWithValue("@pass", pass);
	SqlDataReader reader = command.ExecuteReader();
	// ...
}

```


**VB.NET Example** 

- Unsafe query 

```vb
Dim user As String = Request.QueryString("user")
Dim pass As String = Request.QueryString("pass")
Dim query As String = _
	"SELECT user_id FROM user_data WHERE user_name = '" &amp; _
	user.Text &amp; "' AND user_password = '" &amp; pass.Text &amp; "'"
Try
	Dim command As New SqlCommand = new SqlConnection(query, connection)
	Dim reader As SqlDataReader = command.ExecuteReader()  'unsafe
	' ...
End Try
```

<br/>
- Now, let's fix this using parameterization:  

```vb
Dim user As String = Request.QueryString("user")
Dim pass As String = Request.QueryString("pass")
Dim query As String = _
	"SELECT user_id FROM user_data WHERE user_name = @user and user_password = @pass"
Try
	Dim command As New SqlCommand = new SqlConnection(query, connection)
	command.Parameters.AddWithValue("@user", user)
	command.Parameters.AddWithValue("@pass", pass)
	Dim reader As SqlDataReader = command.ExecuteReader()
	' ...
End Try
```


### Using Stored Procedures 
<br/> 

Now, let's see the same query in C# and VB made ```safe``` using Stored Procedures. 
First, create the stored procedure:

```
-- Database stored procedure:
CREATE PROCEDURE sp_getUserID
	@user varchar(20),
	@pass varchar(10)
AS BEGIN
	SELECT user_id FROM user_data WHERE user_name = @user AND
		user_password = @pass
END
```
<br/>

- Safely invoking Stored Procedure using C#: 

```csharp
String user = Request.QueryString("user");
String pass = Request.QueryString("pass");
try {
	SqlCommand command = new SqlCommand("sp_getUserID", connection);
	command.CommandType = CommandType.StoredProcedure;
	command.Parameters.AddWithValue("@user", user);
	command.Parameters.AddWithValue("@pass", pass);
	SqlDataReader reader = command.ExecuteReader();
	// ...
} catch (Exception ex) {
	// handle exception
}
```
<br/>

- Safely invoking Stored Procedure using VB.NET: 

```vb
Dim UserName As String = Request.QueryString("user")
Dim Password As String = Request.QueryString("pass")
Try
	Dim command As New SqlCommand("sp_getUserID", connection)
	command.CommandType = CommandType.StoredProcedure
	command.Parameters.AddWithValue("@user", user);
	command.Parameters.AddWithValue("@pass", pass);
	Dim reader As SqlDataReader = command.ExecuteReader()
	' ...
Catch ex As Exception
	' handle exception
End Try
``` 

## SQL Injection in .NET Core 

### Recommendations for .NET Core 

### Using Parameterization 
<br/>

**C# Example** 

- Take this unsafe query as an example: 

```csharp
String user = HttpContext.Request.Query("user");
String pass = HttpContext.Request.Query("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
	SqlCommand command = new SqlCommand(query,connection);
	SqlDataReader reader = command.ExecuteReader(); // unsafe
	// ...
}
```
<br/>

- Now, let's fix this using parameterization: 

```csharp
String user = HttpContext.Request.Query("user");
String pass = HttpContext.Request.Query("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = @user and user_password = @pass";
try {
	SqlCommand command = new SqlCommand(query,connection);
	command.Parameters.AddWithValue("@user", user);
	command.Parameters.AddWithValue("@pass", pass);
	SqlDataReader reader = command.ExecuteReader();
	// ...
}
``` 

### Using Stored Procedures 
<br/>
Now, let's see the same query made ```safe``` using Stored Procedures. 
First, create the stored procedure: 

```
-- Database stored procedure:
CREATE PROCEDURE sp_getUserID
	@user varchar(20),
	@pass varchar(10)
AS BEGIN
	SELECT user_id FROM user_data WHERE user_name = @user AND
		user_password = @pass
END
``` 
- Safely invoking Stored Procedure: 

```csharp
String user = HttpContext.Request.Query("user");
String pass = HttpContext.Request.Query("pass");
try {
	SqlCommand command = new SqlCommand("sp_getUserID", connection);
	command.CommandType = CommandType.StoredProcedure;
	command.Parameters.AddWithValue("@user", user);
	command.Parameters.AddWithValue("@pass", pass);
	SqlDataReader reader = command.ExecuteReader();
	// ...
} catch (Exception ex) {
	// handle exception
}
```  

There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity 
of variables is not predetermined. 

If you are unable to avoid building such a SQL call on the fly, then validation and escaping all user data is necessary. 
<br/> 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed.


## SQL Injection in Java 
<br/>

The most effective method of stopping SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) like [Hibernate](https://hibernate.org/orm/) that safely handles database interaction. 
<br/> 
If you must execute queries manually, use [Callable Statements](https://docs.oracle.com/javase/6/docs/api/index.html) for stored procedures and [Prepared Statements](https://docs.oracle.com/javase/6/docs/api/index.html) for normal queries. 

Both of these APIs utilize bind variables and both techniques completely stop the injection of code if used properly. 

You must still avoid concatenating user supplied input to queries and use the binding pattern to keep user input from being misinterpreted as SQL code.

- Take this unsafe query as an example: 

```java
String user = request.getParameter("user");
String pass = request.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
  Statement statement = connection.createStatement( );
  ResultSet results = statement.executeQuery( query ); // Unsafe!
}
```
<br/> 

- Now let's use ```PreparedStatement``` to make the above query safe: 

```java
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
of variables is not predetermined. 

If you are unable to avoid building such a SQL call on the fly, then validation and escaping all 
user data is necessary.
<br/> 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed.  
This is difficult to do by hand, but luckily the [ESAPI](https://owasp.org/www-project-enterprise-security-api/) library offers such functionality. 

Here's an example of safely encoding a dynamically built statement for an Oracle database using untrusted data: 


```java
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


## SQL Injection in Go 
<br/> 

The most effective method of stopping SQL injection attacks is to use a [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) to safely handle database interaction. 

Common ORMs for Go include [GORM](https://gorm.io/index.html) and [go-pg](https://github.com/go-pg/pg). 
If executing queries directly, never use string building to generate the queries, especially with untrusted user input.


- Take this unsafe query as an example: 

```Go
database/sql.DB.Exec(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))
``` 

<br/>
- Now, let's fix this using parameterized queries to pass arguments: 

```Go
database/sql.DB.Exec("SELECT * FROM users WHERE id = '?'", userID)
```


## SQL Injection in PHP 
<br/> 

The most effective method of stopping SQL injection attacks is to only use a [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) to safely handle database interaction. 


Laravel includes the [Eloquent](https://laravel.com/docs/9.x/eloquent) which is recommended.


When using an ORM, always avoid the use of functions that allow the execution of raw SQL queries since these bypass the safety mechanisms provided by the ORM.


If executing queries directly, never use string building to generate the
queries, especially with untrusted user input. 

- Take this unsafe query as an example: 

```PHP
$conn->exec("SELECT * FROM users WHERE id = '$userInput'");
``` 

- Now, let's fix this using parameterized queries to pass arguments: 
<br/>

```PHP
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userInput]);
```


## SQL Injection in Python 
<br/>
The most effective method of stopping SQL injection attacks is to only a [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) to safely handles database interaction. 

Common ORMs for Python include [Models](https://docs.djangoproject.com/en/4.0/topics/db/models) and [SQL Alchemy](https://www.sqlalchemy.org). 

If executing queries directly, never use string building to generate the queries, especially with untrusted user input. 

- Take this unsafe query as an example: 

```Python
cursor.execute("SELECT * FROM users WHERE id = '{}'".format(user_id))
```

- Now, let's fix this using parameterized queries to pass arguments: 
<br/> 

```Python
query_params = (user_id,)
cursor.execute("SELECT * FROM users WHERE id = ?", query_params)
```


## Second Order SQL Injection 

With a maliciously crafted input, an end user could change the structure of the SQL query and perform a Second order SQL Injection attack, despite not executed **directly** at runtime. 

Second order SQL injection is possible when user supplied data is stored by the application, and **later triggered** and included in an unsafe SQL query. 

The goal of such attacks is to force the database to retrieve and output data to which the user would not otherwise have access. For example, an attacker could use Second order SQL Injection on a vulnerable web application by registering an unsafe username. 
This would then be stored in the User table, and executed at a later date to retrieve or manipulate data. 


### Impact 

A successful Second Order SQL injection exploit can read sensitive data from the database. 
Aditioally it can also extend to privilege escalation, account hijacking, and in some cases, it may be possible for an attacker to gain shell access to the database server.


### Prevention
<br/>
The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) like [Hibernate](https://hibernate.org/orm/) that safely handles database interaction. 
<br/>
If you must execute queries manually, use [Callable Statements](https://docs.oracle.com/javase/6/docs/api/index.html)for stored procedures and [Prepared Statements](https://docs.oracle.com/javase/6/docs/api/index.html) for normal queries. 

Both of these APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 
You must still avoid concatenating user supplied input to queries and use the binding pattern to keep user input from being misinterpreted as SQL code.

- Take this unsafe query as an example:

```java
String user = request.getParameter("user");
String pass = request.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
Statement statement = connection.createStatement( );
}
ResultSet results = statement.executeQuery( query ); // Unsafe!}
``` 

- Now, let's fix this using **PreparedStatement**: 
<br/>

```java
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

If you are unable to avoid building such a SQL call on the fly, then validation and escaping all user data is necessary. 
<br/> 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed. 
This is difficult to do by hand, but luckily the [ESAPI](https://owasp.org/www-project-enterprise-security-api/) library offers such functionality. 

Here's an example of safely encoding a dynamically built statement for an Oracle database using untrusted data: 

```java
Codec ORACLE_CODEC = new OracleCodec();
String user = req.getParameter("user");
String pass = req.getParameter("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + ESAPI.encoder().encodeForSQL( ORACLE_CODEC, **user**) + "' and user_password = '" + ESAPI.encoder().encodeForSQL( ORACLE_CODEC, **pass**) + "'";
``` 

## How can Contrast help?
<br/> 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect SQLi vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block SQLi attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect SQLi vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
- [Contrast Serverless](https://www.contrastsecurity.com/contrast-serverless) can determine if you are vulnerable within your Cloud Native environment.
