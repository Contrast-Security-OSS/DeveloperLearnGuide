---
layout: default
title: Form Authorization Weakness
nav_order: 17
---
# Form Authorization Weakness
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Form Protection Authorization  

### Overview 
<br/>
The `All` protection mode indicates that the forms authentication cookie will be both encrypted and validated. 

All is the default protection mode for forms authentication. The forms authentication cookie contains the following information: username, date and time for forms authentication ticket expiration, date and time when the forms authentication ticket was issued, and any custom user data added by the application. 

Validation verifies that the contents of the cookie have not been changed. Encryption prevents users and attackers from learning the cookie contents and modifying the cookie contents (modifying the cookie value will result in the server failing to decrypt the cookie contents and an exception being thrown.

Forms authentication cookies that are not encrypted or validated (using the `None` mode) are subject to a number of flaws.  

Users can modify the cookie value to access other users' sessions by changing the username.  
Users can also infinitely extend their forms authentication ticket by modifying the expiration date. 
Any sensitve information stored by the application in the user data portion of the forms authentication ticket will also be revealed.

Forms authentication cookies that are encrypted but not validated (using the `Encrypted` mode) might be subject to chosen plain-text attacks. 
Forms authentication cookies that are validated but not encrypted (using the `Validated` mode) are created by concatenating a validation key with the cookie data, computing a message authentication code (MAC), and appending the MAC to the outgoing cookie.  

The cookie contents are plaintext and readable by users. This mode may reveal sensitve information stored by the application in the user data portion of the forms authentication ticket. Attackers may also be able to use knowledge of the forms authentication cookies' contents to further refine other attacks. 


### How To Fix 
<br/>

Change the forms authentication `protection` mode to `All` as is shown in the following example: 
	    
```xml
<authentication mode="Forms">
	<forms protection="All" ...
``` 


## Form Redirect Authorization   

### Overview 
<br/>

When `EnableCrossAppRedirects` is `true`, ASP.NET forms authentication allows users to be redirected to URLs outside of the application's path.  The default value for `EnableCrossAppRedirects` is `false` which does not allow users to be redirected outside of the application by forms authentication.  

An attacker that can trick users into clicking a link to the application could redirect users to malicious websites. 

Additionally, under forms authentication, if `CookiesSupported` is false, `EnableCrossAppRedirects` is true, and the redirect URL does not refer to a page within the current application, the `RedirectFromLoginPage` method issues an authentication ticket and places it in the `QueryString` property where it could be exposed to attackers. 


### How To Fix  
<br/>

The forms authentication section's `enableCrossAppRedirects` attribute should be set to `false`, as is shown in this example:
	    
```xml
<authentication mode="Forms"><forms enableCrossAppRedirects="false" ...
```


## Form SSL Authorization  

### Overview 
<br/>

When `requireSSL` is `true`, an SSL connection is required for forms authentication and the forms authentication cookie will have the 'secure' flag which prevents browsers from sending the cookie across unencrypted connections.  

Neither of these protections are used when `requireSSL` is `false`. An attacker could eavesdrop on forms authentication requests sent over HTTP and learn users' credentials as well as the users' forms authentication cookies, leading to the compromise of user accounts.


### How To Fix  
<br/>

The forms authentication section's `requireSSL` attribute should be set to `true`, as is shown in the following example: 
	    
```xml
<authentication mode="Forms">
	<forms requireSSL="true" ...
```

## How can Contrast help?
<br/>

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) observes the data flows in the source code and identifies if your custom code is vulnerable to this attack. 
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.