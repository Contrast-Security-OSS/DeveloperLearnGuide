---
layout: default
title: Reflection Injection
nav_order: 14
---

# Reflection Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Overview
<br/> 

Reflection Injection occurs when an application attempts to load classes whose names are controlled by the end user. 
This pattern, although suspicious, may not be meaningfully exploitable depending on how the loaded class is used.

The attacker may be able to find classes in the container or runtime environment whose static initializers or no-argument constructors have dangerous effects when used unexpectedly or repeatedly.


## Reflection Injection by Language


### Java 
<br/>

Let'ss look at an unsafe example, where the application takes untrusted data to load a class with `Class.forName()`: 

```java
// YourController.java
String action = request.getParameter("action");
Class c = Class.forName(action);
((SomeAction)c.newInstance()).execute(request, response);
``` 


The exploitability of these situations is difficult to diagnose.  
Although it's obvious that users shouldn't be allowed to load arbitrary classes on the server's JVM, it's been a long-standing challenge to the security community to find generic, impactful exploits. 

Here are a few choices for an attacker:
- Load a class that not intended to be executed which has a slow static initializer or constructor.
- Load a class that's required at compile-time, but not available at runtime. This may cause trickle-down effects in class loading and prevent legitimate classes from being loaded. The target functionality could be fuzzed, which could have interesting results.
- Use the functionality as a [classpath](https://en.wikipedia.org/wiki/Oracle_machine). 
If you give the functionality class `org.acme.foo.Bar`, and it errors, you can be reasonably certain the class is not available. 
Classes which are available will likely not fail or fail in a different way. This difference in behavior could be used to fingerprint technologies on the system.

The rules change considerably if an attacker can change class members or pass parameters to the class constructor. If that's the case, an attacker could do at least some of the following:
- Create a `FileOutputStream` with the constructor argument being a `String` of a filename the attacker would like to truncate.
- Create a `JFrame` with a `defaultCloseOperation` value of 3, which will [cause the JVM to exit](https://wouter.coekaerts.be/2011/amf-arbitrary-code-execution) when closed. 

These are just a few of the things available in all JRE's. However, it's very likely that common code in the libraries used in the application could pose more definitive risk. 
An easy way to limit what classes are available is to force the user to provide a key to a `Map` of allowed classes: 

```java
// YourController.java
static {
ALLOWED_CLASSES = new HashMap<String,Class>();
ALLOWED_CLASSES.put("allowedClass1", GetCafeteriaMenuAction.class);
ALLOWED_CLASSES.put("allowedClass2", ViewPeerProfileAction.class);
ALLOWED_CLASSES.put("allowedClass3", LogoutAction.class);
...
String requestedAction = request.getParameter("action");
Class c = ALLOWED_CLASSES.get(requestedAction);
if(c != null) {
((SomeAction)c.newInstance()).execute(request, response);
}
```

Although it provides less assurance, it's also possible to strongly limit what classes an attacker can load by prefixing the input with a known safe package: 

```java
// YourController.java
private static final String ALLOWED_PKG = "org.acme.actions.public.";
...
String action = request.getParameter("action");
Class c = Class.forName(ALLOWED_PKG + action);
((SomeAction)c.newInstance()).execute(request, response);
```

### Ruby 
<br/>

Let's look at an unsafe example where the application takes untrusted data and constantizes it: 

```ruby
# YourController.rb
def vulnerable_basic_data_new
  klass=params[:class]
  obj=klass.constantize.new(params[:form])
  #...
end
```

Because this constatization results in the loading of a class, an attacker can use it to introduce malicious actions to the application. 
The best way to avoid this is to not allow for user data to be used in a `constantize` call. 

Although it provides less assurance, it's also possible to strongly limit what classes an attacker can load by ensuring the value of the supplied data: 


```ruby
# YourController.rb
def vulnerable_safer_data_new
  klass=params[:class]
  return unless klass == "File"

  file = "File".constantize.new(path)
end
```

### PHP 
<br/> 

Reflection injection occurs when the application allows user-controlled data to either load a class or call a function or method via the [API](https://www.php.net/manual/en/book.reflection.php). 

The simplest and most reliable way to avoid this issue is to never use untrusted user input as arguments when calling reflection functions. 
