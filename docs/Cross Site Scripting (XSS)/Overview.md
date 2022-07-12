---
layout: page
title: Overview
permalink: /io/Cross Site Scripting (XSS)/Overview
parent: Cross Site Scripting (XSS)
nav_order: 1
---

## Cross site Scripting (XSS)


### What Is It?


Cross Site Scripting scripting (XSS) describes a web security vulnerability that allows attackers to compromise user interactions by inserting malicious scripts designed to hijack vulnerable applications.  

An XSS attack targets the scripts running behind a webpage which are being executed on the client-side (in the user’s web browser). 

Because the unsuspecting browser has no way of knowing that a script should not be trusted, it will go ahead and execute the XSS script, which can access cookies, session tokens, and other sensitive information retained by the browser and used with that site. 

In short, cross-site scripting (XSS) allows the attacker to “commandeer” HTML pages, deceive users, and steal sensitive data as it assumes control, redirects links, and rewrites content on that site.

Three main types of attacks can target an XSS vulnerability:

- **Reflected XSS** (non persistent), where the malicious script comes from the current HTTP request.
- **Stored XSS** (persistent), where the malicious script comes from the website's database.
- **DOM-based XSS** where the vulnerability exists in client-side code rather than server-side code.


**Reflected XSS attacks** 

Also known as non-persistent attacks, these occur when a malicious script is reflected off of a web application to the victim's browser. The script is activated through a link, which sends a request to a website with a security vulnerability that enables execution of malicious scripts. 

**Stored XSS** 

This vulnerability is a more devastating variant of a cross-site scripting flaw: it occurs when the data provided by the attacker is saved by the server, and then permanently displayed on "normal" pages returned to other users in the course of regular browsing, without proper HTML escaping. 

**DOM-based XSS** 

This is a type of XSS occurring entirely on the client-side. 
A DOM-based XSS attack is possible if the web application writes data to the Document Object Model without proper sanitization. The attacker can manipulate this data to include XSS content on the webpage, for example, malicious JavaScript code. 
The attacker embeds a malicious script in the URL; the browser finds the JavaScript code in the HTML body and executes it. 
JavaScript sources are functions or DOM properties that can be influenced by the user, but vulnerable JavaScript sources can be exploited for a DOM-based attack.


### How Does It Work? 

By injecting a malicious client-side script into an otherwise trusted website, scripting XSS cross-site tricks an application into sending malicious code through the browser, which believes the script is coming from the trusted source.  
It then deceives users by manipulating scripts so that they execute in the manner desired by the attacker.

Cross-site scripting vulnerabilities typically allow an attacker to masquerade as a victim user in order to carry out any actions that the user is able to perform and access any of the user's data; capture the user’s login credentials; perform virtual defacement of the website, changing its messaging, look and feel; inject trojan functionality into the website, creating a backdoor that gives malicious users access to the user’s system.

The XSS attack works by manipulating a website vulnerability such that it returns malicious JavaScript code to users. 
When the malicious code executes inside a victim's browser, the attacker can fully compromise the user’s interaction with the application. 
If the victim user has privileged access within the application, the attacker might be able to gain full control over all of the application's functionality and data – a “worst case” application security scenario. 



### Impact 


XSS vulnerabilities are especially dangerous because an attacker exploiting an HTML or JavaScript vulnerability can gain the ability to do whatever the user can do, and to see whatever the user can see – including passwords, payments, sensitive financial information, and more. 

What makes the XSS attack even worse is the fact that victims, both the user and the vulnerable application, often won’t be aware they’re being attacked.

**Serious impact:** 
Attacker gains access to an application holding sensitive data, such as banking transactions, emails, or healthcare records. 

**Critical impact:** 
The compromised user has elevated privileges within the application, allowing the attacker to take full control of the vulnerable application and compromise all users and their data. 



### Prevention

OWASP has published a cheat sheet that can be used to prevent XSS attacks. 
These guidelines focus on three prevention strategies – escaping, validating input, and sanitizing.

In general, preventing XSS vulnerabilities is likely to involve a combination of the following four measures:

- **Filter input on arrival** At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
- **Encode data on output** At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.
- **Use appropriate response header** To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.
- **Use Content Security Policy** As a last line of defense against attackers, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur. 

And most importantly, never accept actual JavaScript code from an untrusted source and execute.



### How can Contrast help?



- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect XSS vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block XSS attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect XSS vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.