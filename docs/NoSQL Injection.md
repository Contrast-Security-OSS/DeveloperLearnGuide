---
layout: default
title: NoSQL Injection
nav_order: 5
---

# NoSQL Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## NoSQL Injection

### Overview 
<br/>
NoSQL injection occurs when developers hand-build NoSQL statements containing user-supplied data without validation or encoding. 

### Impact 
<br/>
The goal of such attacks is to force the database to retrieve and output data to which the user would not otherwise have access. 

For example, an attacker could use NoSQL Injection on a vulnerable application in order to query the database for customer credit card numbers and other data, even if it wasn't part of the query the developer created. NoSQL injection also allows privilege escalation and account hijacking.


## NoSQL Injection in Java

### Prevention 
<br/>
The most effective method of stopping NoSQL injection attacks is to only use a library like [Hibernate OGM](http://hibernate.org/ogm/) that safely handles database interaction. 

If you must execute queries manually, see below for guidance:


**MongoDB** 
<br/>
For Normal Queries: 

- [com.mongodb.client.MongoDatabase](https://mongodb.github.io/mongo-java-driver/3.4/javadoc/?com/mongodb/client/MongoDatabase.html) 
- [com.mongodb.client.MongoCollection](https://mongodb.github.io/mongo-java-driver/3.6/javadoc/?com/mongodb/client/MongoCollection.html)


For Asynchronous Queries:

- [com.mongodb.async.client.MongoDatabase](https://mongodb.github.io/mongo-java-driver/3.8/javadoc/com/mongodb/async/client/MongoDatabase.html) 
- [com.mongodb.async.client.MongoCollection](https://mongodb.github.io/mongo-java-driver/3.8/javadoc/com/mongodb/async/client/MongoCollection.html) 

These APIs utilize bind variables. Both techniques completely stop the injection of code if used properly. 
You must still avoid concatenating user supplied input to queries and instead use the binding pattern to keep user input from being misinterpreted as NoSQL commands. 

- Here's an example of an **unsafe** query:

```java
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");
	String unsafeFunction =  "function() {var result = db.myCollection.findOne( { user : " + user + ", password: " + pass + " } ); return doc;}"; //UNSAFE

	DB db = mongo.getDB(MONGO_DB_NAME);
	Object evalResult = db.doEval(unsafeFunction);
``` 
<br/> 

- Here's an example of the same query, made **safe**: 

```java
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");
	String saferFunction =  "function(u,p) {var result = db.myCollection.findOne( { user : u, password: p} ); return doc;}"; //SAFE

	DB db = mongo.getDB(MONGO_DB_NAME);
	Object evalResult = db.doEval(saferFunction, user, pass);

``` 

And even **safer**: 

```java
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
<br/>
There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity of variables is not predetermined. 
<br/> 
If you are unable to avoid building such a NoSQL call on the fly, then validation and escaping all user data is necessary. 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed. 

This is difficult to do by hand, but luckily the ESAPI library offers such functionality. Here's an example of safely encoding a dynamically built JavaScript function for a MongoDB query using untrusted data: 

```java
	String user = ESAPI.encoder.encodeForJavaScript(request.getParameter("user"));
	String pass = ESAPI.encoder.encodeForJavaScript(request.getParameter("pass"));
	String unsafeFunction =  "function() {var result = db.myCollection.findOne( { user : " + user + ", password: " + pass + " } ); return doc;}";

	DB db = mongo.getDB(MONGO_DB_NAME);
	Object evalResult = db.doEval(unsafeFunction);
```
<br/>

**DynamoDB** 
<br/>
The following [APIs](https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/dynamodbv2/AmazonDynamoDB.html) utilize bind variables. You must still avoid concatenating or using user supplied input to queries to keep user input from being misinterpreted as NoSQL injections.


Here are two examples of **unsafe** queries: 

```java 
// Scan Filter
DynamoDbClient client = DynamoDbClient.create();
String user = request.getParameter("user");

client.scan(TableName = 'users', Select = 'ALL_ATTRIBUTES',
ScanFilter = {'username': {"AttributeValueList": [{"S": user}],
"ComparisonOperator": "GT"}}) // UNSAFE
``` 

```java 
// Filter Expression
DynamoDbClient client = DynamoDbClient.create();
String user = request.getParameter("user");

HashMap<String, AttributeValue> attrValues = new HashMap<String, AttributeValue>();
attrValues.put(":username", AttributeValue.builder().s(user).build());

ScanRequest queryReq = ScanRequest.builder()
.filterExpression(type + " = :user")
.tableName("users")
.expressionAttributeValues(attrValues)
.build();

ScanResponse response = client.scan(queryReq);
```
<br/>
We recommend the validation and escaping of all user data prior to a database query execution. 
Creation of a validator depends on the database in use and the context into which the untrusted data is being placed. Custom validators can be created under Security Controls in the Contrast UI.
<br/>
Here's an example of safely validating a DynamoDB query using untrusted data:

```java
DynamoDbClient client = DynamoDbClient.create();
String user = CustomDynamoDB.validate(request.getParameter("user"));

client.scan(TableName = 'users', Select = 'ALL_ATTRIBUTES',
ScanFilter = {'username': {"AttributeValueList": [{"S": user}],
"ComparisonOperator": "GT"}})
``` 

## NoSQL Injection in Node 

### Prevention in MongoDB 
<br/>
The best way to remediate or avoid this type of attack is to simply not use the following $query string-based operators
or database methods since they have the ability to execute JavaScript: 

```js
	$where
	$reduce
	$keyf
	$finalize
	$accumulator
	db.eval()
``` 

Here's an example of an **unsafe** execution: 

```js
	app.get('/checkout/:checkoutId/view', (req, res) => {
	query = {$where: `this.checkoutId == '${req.params.checkoutId}'`}
		res.json = db.myCollection.find(query);
	});
``` 
<br/>
The preferred fix would be to not use a string-based `$where` clause at all and instead use the use the `$eq` method and with proper validation. 
The following is an example using the [npm module](https://www.npmjs.com/package/validator) supported by Contrast. 

```js
	app.get('/checkout/:checkoutId/view', (req, res) => {
	let checkoutId = req.params.checkoutId;
		if(validator.isUUID(req.params.checkoutId)) {
				query = {checkoutId: {$eq: checkoutId} }
				res.json = db.myCollection.find(query);
		}
		else{
			res.status(404).send('checkout session not found');
    }
	});
``` 

If the developers want to control what is flagged as vulnerable and what not they can achieve this by using Mongoose and custom validators. 
This form of sanitization is supported since `v4.*.*`. 

**Example 1** 

```js
	const mongoose = require('mongoose');
	const blogPostSchema = new mongoose.Schema({
    body: {
			type: String,
			validate: {
				validator: () => {
					// Some custom logic to make sure the user input is safe and return if that's true
				}
			}
    }
	}); 

	const BlogPost = mongoose.model("Blog-Post", blogPostSchema)

	app.post('/posts', (req, res) => {
    let blogPost = new BlogPost(req.body);

    blogPost.validateSync() // Here is where the actual validation happens

    res.send(await blogPost.save());
	});
``` 
<br/>

**Example 2** 

```js
	const mongoose = require('mongoose');
	const blogPostSchema = new mongoose.Schema({
    topic: {
			type: String,
			enum: [ 'Movies', 'Music' ]  // This will serve as validator, as the only accaptable values are controlled by the developers
    }
	}); 

	const BlogPost = mongoose.model("Blog-Post", blogPostSchema)

	app.post('/posts', (req, res) => {
    let blogPost = new BlogPost(req.body);

    blogPost.validateSync() // Here is where the actual validation happens

    res.send(await blogPost.save());
	});
``` 
<br/>
Keep in mind that these examples are focused on showing the custom validation and don't represent overal production grade code. 

Another type of noSQL injection can happen when part of the user input is “expandable” and then passed
without validation allowing the user to control the query operators passed to Mongo. 
<br/>
Expandable data can come from URL query parameters for example in Express:
A query with `?username=admin&password[$ne]=x`

Would parse the `request.query` to the object: 

```js
{
	username: admin,
	password: {$ne: 'x'}
}
``` 

Expandable data can also come from things like the Express `body-parser` with extended enabled or simply parsing user provided data with `JSON.parse`. 

Proper “type” or schema validation is needed to prevent this type of issue. 
See the following example using the [validation library](https://www.npmjs.com/package/joi) 

```js
	const Joi = require('joi');

	// create a schema that insures that values we are querying with are strings (and not objects)
	const schema = Joi.object({
    username: Joi.string().alphanum(),
    password: Joi.string()
	});

	const result = schema.validate({
    username: req.body.username,
    password: req.body.password
	});

	if(!result.error){
    let users = db.collection('users').find(result.value);
    res.status(200).json(users);
	}
``` 

### Prevention in RethinkDB 
<br/>

- [RethinkDB Docs](https://rethinkdb.com/api/javascript) 
- [RethinkDB .js method](https://rethinkdb.com/api/javascript/js) 
You must still avoid concatenating user supplied input to queries and instead use the binding pattern to keep user input from being misinterpreted as NoSQL commands.  It is strongly advised to not include any user supplied data to `rethinkdb.js`. 

- Here's an example of an **unsafe** execution: 

```js
	const user = req.user;
	const db = rethinkdb.connect({ db: RETHINK_DB_NAME });
	rethinkdb.table(RETHINK_DB_NAME).filter(
	rethinkdb.js('(function (row) { if (row.name ===' + user + ') { return row; })');
``` 

- Here's an example of the same query, made **safe**: 

```js
	const user = req.user;
	const db = rethinkdb.connect({ db: RETHINK_DB_NAME });
	rethinkdb.table(RETHINK_DB_NAME).getAll(user).run(db, callback);
``` 

There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity of variables is not predetermined. 

If you are unable to avoid building such a NoSQL call on the fly, then validation and escaping all user data is necessary. 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed. 


### Prevention in DynamoDB  
<br/>
Firstly, ensure to also comply with the official DynamoDB Security Best Practices from AWS: [DynamoDB Preventative Security Best Practices](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices-security-preventative.html) 

DynamoDB APIs utilize bind variables. You must still avoid concatenating user supplied input to queries to keep user input from being misinterpreted as NoSQL injections. If you are using aws-sdk v2.x, consider querying attribute values as a name-value pair where the data type is specified as a name.

**Example 1** 

- Here is an example of **unsafe** query: 

```js
// aws-sdk version 2.x
const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient();

docClient.scan({
  TableName: 'Movies',
  FilterExpression: 'title = :title',
  ExpressionAttributeValues: { ':title': req.query.title }
}, callback);
``` 

- Let's fix this query to make **safe** 

```js
// aws-sdk version 2.x
const AWS = require("aws-sdk");
const docClient = new AWS.DynamoDB.DocumentClient();

docClient.scan({
  TableName: 'Movies',
  FilterExpression: 'title = :title',
  ExpressionAttributeValues: { ':title': { S: req.query.title }}
}, callback);
```

**Example 2** 

**Unsafe** example with ScanCommand via string concatenation when the user input is not validated:  

```js
// aws-sdk version 3.x
const { DynamoDBClient, ScanCommand } = require("@aws-sdk/client-dynamodb");
const client = new DynamoDBClient(config);

// if FilterExpression (or part of) is user-controlled
client.send(new ScanCommand({
  TableName: 'Movies',
  FilterExpression: req.query.key + " = :title AND released_year = :released_year",
  ExpressionAttributeValues: {
    ":title": { "S": data.title },
    ":released_year": { "N": data.year }
  }
}));

// if ProjectionExpression (or part of) is user-controlled
client.send(new ScanCommand({
  TableName: 'Movies',
  FilterExpression: 'title = :title',
  ProjectionExpression: `released_year, ${req.query.key}`,
  ExpressionAttributeValues: {
    ":title": { "S": data.title }
  }
}));

// if ComparisonOperator is user-controlled
client.send(new ScanCommand({
  TableName: 'Movies',
  Select: 'ALL_ATTRIBUTES',
  ScanFilter: {
    'title': {
      'AttributeValueList': [{'S': data.title }],
      'ComparisonOperator': req.query.comp
    }
  }
}));
``` 

We recommend the validation and escaping of all user data prior to a database query execution. 
Creation of a validator depends on the libraries in use and the context into which the untrusted data is being placed. 

- Here's an example of **safely** validating a DynamoDB query using untrusted data: 

```js
// aws-sdk version 3.x
const { DynamoDBClient, ScanCommand } = require("@aws-sdk/client-dynamodb");

const Joi = require("joi");
const schema = Joi.string().valid('title', 'subtitle', 'season');
let key = schema.validate(req.query.key);
if (key.error) /* ... return validation error */

await client.send(new ScanCommand({
  TableName: 'Movies',
  FilterExpression: 'title = :title',
  ProjectionExpression: `released_year, ${key}`,
  ExpressionAttributeValues: {
    ":title": { "S": req.query.title }
  }
}));
``` 

If you are using [PartiQL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html) with DynamoDB, make sure to always use Prepared Statements. Do NOT concatenate user-supplied input with parameterized statements.

```js
// UNSAFE
let params = { Statement:`SELECT * from Movies WHERE title='${input}'` }

// SAFE
let params = {
  Statement:`SELECT * from Movies WHERE title= ?`,
  Parameters: [{ S: input }]
};

client.send(new ExecuteStatementCommand(params));
``` 


