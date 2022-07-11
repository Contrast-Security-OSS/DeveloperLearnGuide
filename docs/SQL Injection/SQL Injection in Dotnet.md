---
layout: page
title: SQL Injection in Dotnet
permalink: /io/SQL Injection/SQL Injection in Dotnet
parent: SQL Injection
nav_order: 4
---



## SQL Injection in Dotnet


### Recommendations for .NET Framework


The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) like [Entity Framework](https://docs.microsoft.com/en-us/ef/) that safely handles database interaction. 

If you must execute queries manually, use the [class](https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand?view=dotnet-plat-ext-6.0) with ```CommandType.StoredProcedure``` for stored procedures, and ```CommandType.Text``` for normal queries. 

Both of these APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 


You must still avoid concatenating user supplied input to queries and use the binding pattern to keep user input from being 
misinterpreted as SQL code.


### Using Stored Procedures 

**C# Example**


- Take this unsafe query as an example: 

```
String user = Request.QueryString("user");
String pass = Request.QueryString("pass");
String query = "SELECT user_id FROM user_data WHERE user_name = '" + user + "' and user_password = '" + pass +"'";
try {
	SqlCommand command = new SqlCommand(query,connection);
	SqlDataReader reader = command.ExecuteReader(); // unsafe
	// ...
}
```

- Now, let's fix this using parameterization: 

```
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

```
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

Safe query: 

```
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

- Safely invoking Stored Procedures using C#: 

```
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

- Safely invoking Stored Procedures using C#: 

```
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

There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity 
of variables is not predetermined. 

If you are unable to avoid building such a SQL call on the fly, then validation and escaping all user data is necessary. 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed.