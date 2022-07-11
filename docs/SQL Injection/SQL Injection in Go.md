---
layout: page
title: SQL Injection in Go
permalink: /io/SQL Injection/SQL Injection in Go
parent: SQL Injection
nav_order: 7
---

## SQL Injection in Go 

The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) to safely handle database interaction. 

Common ORMs for Go include [GORM](https://gorm.io/index.html) and [go-pg](https://github.com/go-pg/pg). 
If executing queries directly, never use string building to generate the queries, especially with untrusted user input.


- Take this unsafe query as an example: 

```
database/sql.DB.Exec(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))
``` 

- Now, let's fix this using parameterized queries to pass arguments: 

```
database/sql.DB.Exec("SELECT * FROM users WHERE id = '?'", userID)
```
