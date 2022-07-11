---
layout: page
title: SQL Injection in PHP
permalink: /io/SQL Injection/SQL Injection in PHP
parent: SQL Injection
nav_order: 9
---

## SQL Injection in PHP 

The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) to safely handle database interaction. 


Laravel includes the [Eloquent](https://laravel.com/docs/9.x/eloquent) which is recommended.


When using an ORM, always avoid the use of functions that allow the execution of raw SQL queries since these bypass the safety mechanisms provided by the ORM.


If executing queries directly, never use string building to generate the
queries, especially with untrusted user input. 

- Take this unsafe query as an example: 

```
$conn->exec("SELECT * FROM users WHERE id = '$userInput'");
``` 

- Now, let's fix this using parameterized queries to pass arguments: 

```
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userInput]);
```