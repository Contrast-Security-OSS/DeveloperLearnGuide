---
layout: page
title: Overview
permalink: /io/Cross Site Request Forgery/Overview
parent: Cross Site Request Forgery
nav_order: 1
---

### Cross Site Request Forgery 

Application attacks are on the rise and becoming more advanced. On average, applications have more than 10 vulnerabilities when they release into production, leaving significant opportunities for attackers to exploit. 

As developers are pushed to speed release cycles for improved and complex applications, they must quickly and effectively prioritize vulnerability remediation. Too often, cross-site request forgery (CSRF) vulnerabilities are neglected and do not get fixed before code is released into production.
The above is true because CSRF application attacks result only in state changes when successful, meaning that user data is not at risk. 

Though a user's personal data is left unharmed, their personally identifiable information (PII), passwords, and even money are at risk. Developers and application security teams focus on more advanced attacks that could lead to sensitive data exposure; as a result, CSRF vulnerabilities are not remediated, leaving cyber criminals with more opportunities for successful execution


### What Is It?


CSRF application attacks manipulate a user’s web application into executing unwanted commands. 

A CSRF attack takes advantage of the fact that applications do not have the capacity to recognize the difference between malicious and secure requests once a user is authenticated. 

Attackers usually initiate the process by creating a corrupted link that they send to the target via email, text, or chat. A CSRF attack is often referred to as a “one-way” attack, as attackers can access and manipulate HTTP requests but cannot access the responses that follow. 

Therefore, they target state-changing requests within the application, generally leaving sensitive data unharmed.


A cross-site scripting (XSS) attack, on the other hand, is a “two-way” attack, allowing bad actors to not only tamper with requests but also read responses and even extract data. 

In XSS attacks, cyber criminals interfere with a browser-side script, injecting it into trusted websites. XSS attacks are not limited to actions only users can perform and thus they can jeopardize the content and code on an entire HTML page. 

The most notable difference between the two is authentication, where CSRF attacks require a successful login of the user, whereas XSS attacks do not.


### When Can It Affect My Application?


CSRF attacks work by targeting vulnerabilities in web applications, which makes them incapable of distinguishing between valid and malicious commands. Web applications are designed to automatically include cookies and session cookies once authentication is successful. 

Attackers first build a URL that mimics an action they wish to execute once the user is authenticated. Then, they must come up with a clever means of delivery or the link, one that has the highest probability that the user will click. 

For successful execution, the target must be logged into an application and in an active session. Once a user is authenticated and the malicious link is clicked, attackers have all they need to manipulate requests. This includes changing the target’s email, allowing unwanted transfers from banking accounts, or making undesired purchases.

Because cookies contain authentication data, they allow for faster logins and extended sessions. While this is convenient for users, attackers can exploit this application vulnerability by remaining authenticated in the user’s account as long as the session allows. 

During the authenticated session, attackers have full access to a user’s account and are able to make any number of changes without triggering an alert.

CSRF occurs in an application that just processes user requests without any checks. Because browsers send cookies in any request, these cross-site requests will often appear authenticated. 

When a logged in user at your side can submit actions by navigating on other sites (that reference your site), your application is vulnerable.


### Impact

The impact of such an attack depends highly on the target application, and privileges of the victim. 
A successful attack can result in a change to password or email address. For a user with administrator privileges, it could lead to an entire system compromise.  

In the example below we can see how it can be leveraged to transfer funds to the attacker.

The image HTML could be placed in a malicious page by an attacker.


(insert image-TBC)



If the victim were to visit a malicious page containing that code, the victim's browser would request the image with the URL specified, and in effect, the attacker's chosen malicious request would "ride along with" the user's already authenticated session. This is why some have called this vulnerability "Session Riding."

Even though the request is for an image, it will look "normal" to the bank, and will be processed as if the user had gone through the normal page workflow of transferring money.

This is a subtle vulnerability which requires explicit protection, and developer awareness is generally very low. We strongly recommend investing in creating an architectural solution for CSRF, rather than fixing individual pages.

## How can Contrast Security secure your application against CSRF attacks?

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) can monitor requests of your application and determine if the application checks origins or items that will block CSRF vulnerabilities.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block CSRF attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) observes the data flows in the source code and identifies if your custom code is vulnerable to this attack. 
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.




### Further Reading

- [White Paper: Route Coverage Through Instrumentation and Automated Vulnerability Management](https://www.contrastsecurity.com/hubfs/Route-Coverage-Through-Instrumentation_White%20Paper_052220_Final.pdf?hsLang=en)
- [White Paper: Advanced Threat Landscape and Legacy Application Security Ratchet Up Risk](contrastsecurity.com/hubfs/Advanced-Threat-Landscape-and-Legacy-Application-Security-Ratchets-Up-Risk_Whitepaper_07062020.pdf?hsLang=en)
- [Solution Brief: Contrast Protect with Runtime Application Self-protection (RASP)](https://www.contrastsecurity.com/runtime-application-self-protection-rasp-old)
