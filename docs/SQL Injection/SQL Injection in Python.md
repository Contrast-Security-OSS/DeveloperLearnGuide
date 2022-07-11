---
layout: page
title: SQL Injection in Python
permalink: /io/SQL Injection/SQL Injection in Python
parent: SQL Injection
nav_order: 5
---

## SQL Injection in Python 

The most effective method of stopping Second Order SQL injection attacks is to only use [Mapping](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (ORM) to safely handles database interaction. 

Common ORMs for Python include [Models](https://docs.djangoproject.com/en/4.0/topics/db/models) and [SQL Alchemy](https://www.sqlalchemy.org). 

If executing queries directly, never use string building to generate the queries, especially with untrusted user input. 

- Take this unsafe query as an example: 
```
cursor.execute("SELECT * FROM users WHERE id = '{}'".format(user_id))
```

- Now, let's fix this using parameterized queries to pass arguments: 

```
query_params = (user_id,)
cursor.execute("SELECT * FROM users WHERE id = ?", query_params)
```