---
layout: default
title: Trust Boundary Violation
nav_order: 15
---

# Trust Boundary Violation
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-green }

## Overview 
<br/> 

Simply put, a Trust Boundary violation occurs when the application takes untrusted data that comes from the user and places it in trusted storage: for example within `HttpSession`. 
Developers are likely to assume that data stored in the session came from the application itself, and not the user, and may use the data 
in a way that's unsafe. 

For example, storing role information in the session that came from a request parameter is clearly unsafe. When estimating exploitability, consider that the application may use the same session variable key in different places.

All the application's storage of data in session should be done safely to make sure it doesn't expose any risk should a 
malicious user change a stored data value arbitrarily.


## How To Fix   
<br/> 

There are a few key ways to avoid running into session puzzling vulnerabilities or session race conditions as a result of this flaw:

- Ensure every distinct use of the session utilizes a unique key to avoid functionality stepping on each other and possibly opening up flaws.
- Always validate the data provided by the user before storing it in session to make sure its correct for the current user, in case some other code decides to use and trust this stored value.
- Use objects instead of Strings that more clearly indicate the purpose of the data to make it less likely to be repurposed by an attacker.


Let's go through a fictional example of an **unsafe** usage of the same session variable under different conditions: 

### Java 
<br/> 

```java
// Login.java
if(successfullyAuthenticated) {
#if($language =="Java")   session.setAttribute("user", userName);
#else   session.put("user", userName);
#end
}

// ForgotPasswordController.java
/**
 * The user forgot their password, so we'll kickoff the
 * wizard for them to recover it.
 */
#if($language =="Java") session.setAttribute("user", request.getParameter("user"));
#else session.put("user", request.queryString("user"));
#end
``` 


The "user" session key is holding the username of the person claimed to have forgotten their password. 

But another Java class uses that same key for another purpose: 

```java
// ShoppingCartCheckoutController.java
CreditCard[] userCreditCards = CCUtil.getCreditCards(session.getAttribute("user"));
``` 

In this scenario, an attacker could start the Forgot Password workflow and pass in a victim's username. Then they would navigate to the checkout page where they would see the victim's credit cards instead of their own because of the clobbered "user" key in the `HttpSession`. 

To fix our example, we'll make the two different uses for that variable have unique keys: 

```java
// Login.java
#if($language == "Java")
session.setAttribute("authenticated.user", userName);
#else
session.put("authenticated.user", userName);
#end

// ForgotPasswordController.java
#if($language == "Java")
session.setAttribute("forgotpw.user", request.getParameter("user"));
#else
session.put("forgotpw.user", request.queryString("user"));
#end

// ShoppingCartCheckoutController.java
CreditCard[] userCreditCards = CCUtil.getCreditCards(session.getAttribute("authenticated.user"));
```

### .NET  
<br/> 

```csharp
// Login.cs
if(successfullyAuthenticated) {
   Session["user"] = userName;
}

// ForgotPasswordController.cs
/**
 * The user forgot their password, so we'll kickoff the
 * wizard for them to recover it.
 */
Session["user"] = Request.QueryString("user"));
``` 

The "user" session key is holding the username of the person claimed to have forgotten their password. 
But another C# class uses that same key for another purpose: 

```csharp
// ShoppingCartCheckoutController.cs
CreditCard[] UserCreditCards = CCUtil.GetCreditCards(Session["user"]);
``` 

In this scenario, an attacker could start the Forgot Password workflow and pass in a victim's username. Then they would navigate to the checkout page where they would see the victim's credit cards instead of their own because of the clobbered "user" key in the `HttpSessionState`. 

To fix our example, we'll make the two different uses for that variable have unique keys: 

```csharp
// Login.cs
Session["authenticated.user"] = userName;

// ForgotPasswordController.cs
Session["forgotpw.user"] = Request.QueryString("user");

// ShoppingCartCheckoutController.cs
CreditCard[] UserCreditCards = CCUtil.GetCreditCards(Session["authenticated.user"]);
``` 


### Ruby 
<br/> 


```ruby
# Login.rb
request.session[:user] = user_name if successfullyAuthenticated?

# ForgotPasswordController.rb
<<-DOC
  The user forgot their password, so we'll kickoff the
  wizard for them to recover it.
DOC
request.session[:user] = request.params['user']
```

The "user" session key is holding the username of the person claimed to have forgotten their password. But another Ruby class uses that same key for another purpose: 

```
# ShoppingCartCheckoutController.rb
userCreditCards = CCUtil.getCreditCards(request.session[:user])
``` 

In this scenario, an attacker could start the Forgot Password workflow and pass in a victim's username. Then they would navigate to the checkout page where they would see the victim's credit cards instead of their own because of the clobbered "user" key in the `rack.session`. 

To fix our example, we'll make the two different uses for that variable have unique keys: 

```ruby
# Login.rb
request.session[:authenticated_user] = user_name

# ForgotPasswordController.rb
request.session[:forgotpw_user] = request.params['user']

# ShoppingCartCheckoutController.rb
userCreditCards = CCUtil.getCreditCards(request.session[:authenticated_user])
```

### Python  
<br/> 

```python
# login.py
if authenticated:
    request.session["user"] = user_name

# ForgotPasswordController.py
"""
The user forgot their password, so we'll kickoff the wizard for them to recover it.
"""
request.session["user"] = request.params["user"]
``` 

The "user" session key is holding the username of the person claimed to have forgotten their password. But another class uses that same key for another purpose:

```python
# ShoppingCartCheckoutController.py
userCreditCards = CCUtil.getCreditCards(request.session["user"])
``` 

In this scenario, an attacker could start the Forgot Password workflow and pass in a victim's username. Then they would navigate to the checkout page where they would see the victim's credit cards instead of their own because of the clobbered "user" key in the session instance. 

To fix our example, we'll make the two different uses for that variable have unique keys: 

```python
# login.py
request.session["authenticated_user"] = user_name

# ForgotPasswordController.py
request.session["forgotpw_user"] = request.params["user"]

# ShoppingCartCheckoutController.py
userCreditCards = CCUtil.getCreditCards(request.session["authenticated_user"])
```