---
layout: default
title: Parameter Pollution
nav_order: 13
---

# Parameter Pollution
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Parameter Pollution 
<br/>
When an application has a `form` tag that doesn't specify an `action` attribute, it is vulnerable to Parameter Pollution. 
In forms containing sensitive information, this can be a very dangerous pattern that can be exploited by users looking to attack other users. 


### Java 
<br/>
Consider the following statement from the Java Servlet Specification (Version 3, Section 3.1):

- Data from the query string and the post body are aggregated into the request parameter set. Query string data is presented before post body data. For example, if a request is made with a query string of a=hello and a post body of a=goodbye&a=world, the resulting parameter set would be ordered a=(hello, goodbye, world).


The short version of that is this: URL parameters come first in Java EE - and the first URL parameter comes first. 

Next, let's talk about `form` actions. If no `action` is specified, browsers assume that the form should submit to the current URL (the one in the address bar). 


Now, let's imagine a site that has a change password form, located at `/app/password/change:`:

```js
<form> method="POST"&gt;
	<input type="password" name="pass1">
	<input type="password" name="pass2">
	<input type="submit" value="Change Password!">
</form> 
```

An attacker could send a malicious link to this user, e.g. `app/password/change?pass1=hacked&pass2=hacked`. 
If the user clicks on this link and submits the form, the data will be submitted to the URL supplied by the attacker - with the attacker's chosen parameter values in the querystring. 


When the application receives the POST form submission, it will attempt to get the `pass1` and `pass2` parameters. Because the URL parameters will get preference over the POST parameters, the application will change the victim's password to `hacked`. 

The fix for this issue is easy: make sure every `form` tag has an `action` attribute specified! If you have a `form` tag that you always want to submit to the current URI, but don't want to be vulnerable, considering using a snippet of JSTL to hardcode the `action` to the current URI:

```js
<form method="POST" action="<c:out value="${pageContext.request.requestURI}"/>">
	<input type="password" name="pass1">
	<input type="password" name="pass2">
	<input type="submit" value="Change Password!">
</form>
```


### Node 
<br/>

In the Express framework, duplicate parameters are stored as arrays rather than strings:
`<uri>/search?name=Bob&name=Bob` will not return the string `'Bob'` but rather
`['Bob','Bob']`. This transformation is internal and thus can be exploited by an attacker to inject
an array where the server expects a string, allowing the attacker to crash the server or bypass input validation. 

Next, let's talk about `form` actions. If no `action` is specified, browsers assume that the form should submit to the current URL (the one in the address bar). 

Now, let's imagine a site that has a change password form, located at `/app/password/change`:

```js
<form> method="POST">;
	<input type="password" name="pass1">
	<input type="password" name="pass2">
	<input type="submit" value="Change Password!">
</form>
```


An attacker could send a malicious link to this user, e.g. `/app/password/change{?pass1=hacked&pass2=hacked`. 
If the user clicks on this link and submits the form, the data will be submitted to the URL supplied by the attacker - with the attacker's chosen parameter values in the querystring.


When the application receives the POST form submission, it will attempt to get the `pass1` and `}pass2` parameters. Because the URL parameters will get preference over the POST parameters, the application will change the victim's password to `hacked`. 


The fix for this issue is easy: make sure every <form> tag has an `action` attribute specified! If you have a <form> tag that you always want to submit to the current URI, but don't want to be vulnerable, considering using a snippet to hardcode the `action` to the current URI:

```js
<form method="POST" action="<%=Request.Url.AbsolutePath %>">
<input type="password" name="pass1">
<input type="password" name="pass2">
<input type="submit" value="Change Password!">
</form> 
```

If using the Express framework, be sure to check expected type (string vs. array) as part of
input validation and implement robust error handling to prevent an uncaught exception from bringing down your application. 

Additionally, the [middleware](https://www.npmjs.com/package/hpp) middleware can mitigate this issue by putting array parameters in `req.query` and/or `req.body`and selecting just the last parameter value. 


### .NET/.NET Core
<br/>

The fix for this issue is easy: make sure every `form` tag has an `action` attribute specified! If you have a `form` tag that you always want to submit to the current URI, but don't want to be vulnerable, considering using a snippet to hardcode the `action` to the current URI:

```js
<form method="POST" action="<%=Request.Url.AbsolutePath %>">
<input type="password" name="pass1">
<input type="password" name="pass2">
<input type="submit" value="Change Password!">
</form>
```


### Ruby
<br/>

The fix for this issue is easy: make sure every `form` tag has an `action` attribute specified! If you have a `form` tag that you always want to submit to the current URI, but don't want to be vulnerable, considering using a snippet to hardcode the `action` to the current URI:

```ruby
<%= form_tag(some_path, id: 'some_id', method: 'POST')do %>
<% end %>
``` 

### Python 
<br/>

The fix for this issue is easy: make sure every `form` tag has an `action` attribute specified! If you have a `form` tag that you always want to submit to the current URI, but don't want to be vulnerable, considering using a snippet to hardcode the `action` to the current URI:

```python
<form method="POST" action="<%=Request.Url.AbsolutePath %>">
<input type="password" name="pass1">
<input type="password" name="pass2">
<input type="submit" value="Change Password!">
</form>  
```