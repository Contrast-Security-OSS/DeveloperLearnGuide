---
layout: page
title: NoSQL Injection in Java
permalink: /io/NoSQL Injection/NoSQL Injection in Java
parent: NoSQL Injection
nav_order: 4
---

## NoSQL Injection in Java

### Prevention 

The most effective method of stopping NoSQL injection attacks is to only use a library like [Hibernate OGM](http://hibernate.org/ogm/) that safely handles database interaction. 

If you must execute queries manually, use


- For MongoDB: 
(normal queries) 

[`com.mongodb.client.MongoDatabase`](https://mongodb.github.io/mongo-java-driver/3.4/javadoc/?com/mongodb/client/MongoDatabase.html) 
[`com.mongodb.client.MongoCollection`](https://mongodb.github.io/mongo-java-driver/3.6/javadoc/?com/mongodb/client/MongoCollection.html 


(asynchronous queries) 
[`com.mongodb.async.client.MongoDatabase`](https://mongodb.github.io/mongo-java-driver/3.8/javadoc/com/mongodb/async/client/MongoDatabase.html) 
[com.mongodb.async.client.MongoCollection](https://mongodb.github.io/mongo-java-driver/3.8/javadoc/com/mongodb/async/client/MongoCollection.html) 

These APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 
You must still avoid concatenating user supplied input to queries and instead use the binding pattern to keep user input from being misinterpreted as NoSQL commands. 

- Here's an example of an **UNSAFE** query:

```
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");
	String unsafeFunction =  "function() {var result = db.myCollection.findOne( { user : " + user + ", password: " + pass + " } ); return doc;}"; //UNSAFE

	DB db = mongo.getDB(MONGO_DB_NAME);
	Object evalResult = db.doEval(unsafeFunction);
``` 

- Here's an example of the same query, made **SAFE**: 

```
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");
	String saferFunction =  "function(u,p) {var result = db.myCollection.findOne( { user : u, password: p} ); return doc;}"; //SAFE

	DB db = mongo.getDB(MONGO_DB_NAME);
	Object evalResult = db.doEval(saferFunction, user, pass);

``` 

And even **SAFER**: 

```
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");

	MongoDatabase mongoDatabase = mongo.getDatabase(MONGO_DB_NAME);
	MongoCollection<Document> myCollection = mongoDatabase.getCollection("myCollection");

	BasicDBObject findParams = new BasicDBObject();
	findParams.put("user", user);
	findParams.put("password", pass);

	FindIterable<Document> it = myCollection.find(findParams);
	Consumer<Document> consumer = new Consumer<Document>() { public void accept(Document queryResult) { ... } };
	it.forEach(consumer);
``` 

There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity of variables is not predetermined. If you are unable to avoid building such a NoSQL call on the fly, then validation and escaping all user data is necessary. 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed. 

This is difficult to do by hand, but luckily the ESAPI library offers such functionality. Here's an example of safely encoding a dynamically built JavaScript function for a MongoDB query using untrusted data: 

```
	String user = ESAPI.encoder.encodeForJavaScript(request.getParameter("user"));
	String pass = ESAPI.encoder.encodeForJavaScript(request.getParameter("pass"));
	String unsafeFunction =  "function() {var result = db.myCollection.findOne( { user : " + user + ", password: " + pass + " } ); return doc;}";

	DB db = mongo.getDB(MONGO_DB_NAME);
	Object evalResult = db.doEval(unsafeFunction);
```

