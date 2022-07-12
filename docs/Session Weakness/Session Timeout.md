---
layout: page
title: Session Timeout
permalink: /io/Session Weakness/Session Timeout
parent: Session Weakness
nav_order: 3
---

## Session Timeout

### What Is It? 

If an application has specified a session timeout value greater than 30 minutes, it is vulnerable to attack. 
Most sensitive applications in banking, trading and other sensitive industries tend to specify session timeouts between 15 and 30 minutes. 
Longer session timeouts make it easier for cross-user web attacks like Cross-Site Request Forgery (CSRF) and Cross-Site Scripting (XSS) more likely to be successful, because users' sessions, which attackers require to be active for their exploits to work, are around longer. 

Your value should depend on how your users use the application. Consider the following questions when deciding your timeout value: 

- Do your users use this application from work, home or both? 
- Would a user use this application from a kiosk? A friend's computer?
- Is there financial incentive for a random person who stumbles upon a user's logged in session?
- How critical is this application to the business? To your users' life or well-being? 


### Impact

This type of vulnerability is often used in a chain-attack, for example XSS. 
For more information, please visit our guide on: [Cross Site Scripting](/io/DeveloperLearnGuide/Cross Site Scripting (XSS)/Overview) or [Cross Site Request Forgery](/io/DeveloperLearnGuide/Cross Site Request Forgery/Overview)

### Prevention

#### Java 

Decreasing your session timeout is easy. 
Simply specify a reasonable `session-timeout` value in your application's /WEB-INF/web.xml file, like in this example: 
```
        <session-timeout>30</session-timeout>
</session-config>
```

#### .NET 

Specify a reasonable `sessionState.timeout` value in your application's Web.config file, like in this example: 

```
<sessionState timeout="30" cookieless="UseCookies" ... >
	<providers> ... </providers>
</sessionState>
``` 

If the session timeout is increased programmatically inside of a page, by using `Session.Timeout = 60` for example, then
ensure the timeout value is not excessive. 


#### .NET Core 

Specify a reasonable `IdleTimeout` value in your application's `SessionOptions`, like in this example: 

```
services.AddSession(options => {
	options.IdleTimeout = TimeSpan.FromMinutes(30);
});
``` 

#### Node 

The node.js built-in http module is stateless and has no notion of sessions or session variables, however frameworks such as [express](https://www.npmjs.com/package/express) are built on top of http and provide useful abstractions such as sessions, and can allow you to set session timeout values similarly to this: 

```
app.use(express.session({
    secret  : 'someSecretSessionKey',
    cookie  : { maxAge  : new Date(Date.now() + (60 * 1000 * 30)) },
    expires  : new Date(Date.now() + (60 * 1000 * 30))
}));
``` 

#### Ruby 


Specify a reasonable value in your application's configuration, like in this example: 

```
Demo::Rack::Application.config.session_store :cookie_store,
                                              expire_after: 1000 * 60 * 30
``` 


#### Python 

Each framework provides a different way for configuring session timeout values. 
For the given framework, simply set the timeout to a value representing 30 minutes or less. 
In most cases, this will be a value representing seconds.

- **Django** is configured in application's `settings.py` file:

```
# settings.py
SESSION_COOKIE_AGE = 15 * 60  # value represents seconds
``` 

- **Flask** is configured using the application's `config` object: 
```
app.config["PERMANENT_SESSION_LIFETIME"] = 15 * 60  # value represents seconds
# flask also allows the use of timedelta
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=15)
``` 

- **Pyramid** is configured by the `timeout` parameter of the session cookie factory: 
```
session = pyramid.session.SignedCookieSessionFactory(..., timeout=15*60)
``` 

- **Pylons** is configured by the `timeout` parameter of the session constructor: 

```
session = beaker.session.Session(..., timeout=15*60)
``` 







### How can Contrast help? 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect these vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block these attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.