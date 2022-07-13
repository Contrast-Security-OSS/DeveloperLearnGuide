---
layout: page
title: NoSQL Injection in Node
permalink: /io/NoSQL Injection/NoSQL Injection in Node
parent: NoSQL Injection
nav_order: 5
---

## NoSQL Injection in Node 

### Prevention 


- For MongoDB (String / JavaScript Injection):

The best way to remediate or avoid this type of attack is to simply not use the following $query string-based operators
or database methods since they have the ability to execute JavaScript: 

```
	$where
	$reduce
	$keyf
	$finalize
	$accumulator
	db.eval()
``` 

Here's an example of an **UNSAFE** execution: 

```
	app.get('/checkout/:checkoutId/view', (req, res) => {
	query = {$where: `this.checkoutId == '${req.params.checkoutId}'`}
		res.json = db.myCollection.find(query);
	});
``` 

The preferred fix would be to not use a string-based `$where` clause at all and instead use the use the `$eq` method and with proper validation. 
The following is an example using the [npm module](https://www.npmjs.com/package/validator) supported by Contrast. 

```
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

- **Example 1** 

```
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

- **Example 2** 

```
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

Keep in mind that these examples are focused on showing the custom validation and don't represent overal production grade code. 

Another type of noSQL injection can happen when part of the user input is “expandable” and then passed
without validation allowing the user to control the query operators passed to Mongo. 

Expandable data can come from URL query parameters for example in Express:
A query with `?username=admin&password[$ne]=x`

Would parse the `request.query` to the object: 
```
{
	username: admin,
	password: {$ne: 'x'}
}
``` 

Expandable data can also come from things like the Express `body-parser` with extended enabled or simply parsing user provided data with `JSON.parse`. 

Proper “type” or schema validation is needed to prevent this type of issue. 
See the following example using the [validation library](https://www.npmjs.com/package/joi) 
```
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

- For RethinkDB: 
[RethinkDB Docs](https://rethinkdb.com/api/javascript) 
[RethinkDB .js method](https://rethinkdb.com/api/javascript/js) 
You must still avoid concatenating user supplied input to queries and instead use the binding pattern to keep user input from being misinterpreted as NoSQL commands.  
It is strongly advised to not include any user supplied data to `rethinkdb.js`. 

- Here's an example of an **UNSAFE** execution: 
```
	const user = req.user;
	const db = rethinkdb.connect({ db: RETHINK_DB_NAME });
	rethinkdb.table(RETHINK_DB_NAME).filter(
	rethinkdb.js('(function (row) { if (row.name ===' + user + ') { return row; })');
``` 

- Here's an example of the same query, made **SAFE**: 
```
	const user = req.user;
	const db = rethinkdb.connect({ db: RETHINK_DB_NAME });
	rethinkdb.table(RETHINK_DB_NAME).getAll(user).run(db, callback);
``` 

There are some scenarios, like dynamic search, that make it difficult to use parameterized queries because the order and quantity of variables is not predetermined. 
If you are unable to avoid building such a NoSQL call on the fly, then validation and escaping all user data is necessary. 
Deciding which characters to escape depends on the database in use and the context into which the untrusted data is being placed. 

