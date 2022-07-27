---
layout: default
title: Cross Site Request Forgery
nav_order: 5
---

# Cross Site Request Forgery
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Cross Site Request Forgery
<br/>
Application attacks are on the rise and becoming more advanced. On average, applications have more than 10 vulnerabilities when they release into production, leaving significant opportunities for attackers to exploit. 

As developers are pushed to speed release cycles for improved and complex applications, they must quickly and effectively prioritize vulnerability remediation. Too often, cross-site request forgery (CSRF) vulnerabilities are neglected and do not get fixed before code is released into production.
The above is true because CSRF application attacks result only in state changes when successful, meaning that user data is not at risk. 

Though a user's personal data is left unharmed, their personally identifiable information (PII), passwords, and even money are at risk. Developers and application security teams focus on more advanced attacks that could lead to sensitive data exposure; as a result, CSRF vulnerabilities are not remediated, leaving cyber criminals with more opportunities for successful execution


### Overview
<br/>

CSRF application attacks manipulate a user’s web application into executing unwanted commands. 

A CSRF attack takes advantage of the fact that applications do not have the capacity to recognize the difference between malicious and secure requests once a user is authenticated. 

Attackers usually initiate the process by creating a corrupted link that they send to the target via email, text, or chat. A CSRF attack is often referred to as a “one-way” attack, as attackers can access and manipulate HTTP requests but cannot access the responses that follow. 

Therefore, they target state-changing requests within the application, generally leaving sensitive data unharmed.


A cross-site scripting (XSS) attack, on the other hand, is a “two-way” attack, allowing bad actors to not only tamper with requests but also read responses and even extract data. 

In XSS attacks, cyber criminals interfere with a browser-side script, injecting it into trusted websites. XSS attacks are not limited to actions only users can perform and thus they can jeopardize the content and code on an entire HTML page. 

The most notable difference between the two is authentication, where CSRF attacks require a successful login of the user, whereas XSS attacks do not.


### How Is This Flaw Exploited?
<br/>

CSRF attacks work by targeting vulnerabilities in web applications, which makes them incapable of distinguishing between valid and malicious commands. Web applications are designed to automatically include cookies and session cookies once authentication is successful. 

Attackers first build a URL that mimics an action they wish to execute once the user is authenticated. Then, they must come up with a clever means of delivery or the link, one that has the highest probability that the user will click. 

For successful execution, the target must be logged into an application and in an active session. Once a user is authenticated and the malicious link is clicked, attackers have all they need to manipulate requests. This includes changing the target’s email, allowing unwanted transfers from banking accounts, or making undesired purchases.

Because cookies contain authentication data, they allow for faster logins and extended sessions. While this is convenient for users, attackers can exploit this application vulnerability by remaining authenticated in the user’s account as long as the session allows. 

During the authenticated session, attackers have full access to a user’s account and are able to make any number of changes without triggering an alert.

CSRF occurs in an application that just processes user requests without any checks. Because browsers send cookies in any request, these cross-site requests will often appear authenticated. 

When a logged in user at your side can submit actions by navigating on other sites (that reference your site), your application is vulnerable.


### Impact
<br/>
The impact of such an attack depends highly on the target application, and privileges of the victim. 
A successful attack can result in a change to password or email address. For a user with administrator privileges, it could lead to an entire system compromise.  

In the example below we can see how it can be leveraged to transfer funds to the attacker.

The image HTML could be placed in a malicious page by an attacker.


If the victim were to visit a malicious page containing that code, the victim's browser would request the image with the URL specified, and in effect, the attacker's chosen malicious request would "ride along with" the user's already authenticated session. This is why some have called this vulnerability "Session Riding."

Even though the request is for an image, it will look "normal" to the bank, and will be processed as if the user had gone through the normal page workflow of transferring money.

This is a subtle vulnerability which requires explicit protection, and developer awareness is generally very low. We strongly recommend investing in creating an architectural solution for CSRF, rather than fixing individual pages.


## Prevention 

<br/>
The best defense against a CSRF attack is to equip applications with a way to distinguish between legitimate and forged HTTP requests. One of the most effective ways is to change the way that applications manage cookies and CSRF tokens. 

Most of today's applications have built-in CSRF token defenses that help avert the risk of an application attack. However, as they are built-in, these defenses must be constantly configured to provide the strongest line of defense.
<br/>

As a prerequisite **always** ensure CSRF Protection is enabled as follows: `http.csrf();`.

### The Use of CSRF Tokens
<br/>
When configuring CSRF tokens to effectively prevent CSRF attacks, two things should take place. First, CSRF tokens should be configured to be generated on the server side. Second, the option for token generation should renew per request and not per session. With these two configurations, applications are more secure but lack efficiency. 

If tokens generate per request, things such as the “back button” can no longer remain valid. This means that with each click, users face the possibility of needing to re-enter their credentials. This is perhaps why most applications configure CSRF tokens per session, bringing about an additional application vulnerability if sessions are not properly managed.
<br/>

### Cookie Management
<br/>
Cookies are always sent along with requests from one origin to another as long as they are deemed secure. This allows for cross-domain passing of cookies, which can include user credentials. 

To combat this CSRF vulnerability, organizations need to flag cookies to transform them into same-site cookies. This means that the browser decides whether to execute requests based on the origin of the cookies, possibly preventing a CSRF attack. There are three possible options when choosing same-site cookies attributes, including lax, strict, or none. 

The none attribute grants permission for the sharing of cookies to all parties, which includes third-party and advertisers. Lax comes with more restrictions, allowing only first-party cookies to be sent or accessed. 

Strict is the most secure, used in banking applications and others that hold PII. Though this type of cookie management is more secure, it is still just an additional layer of defense that leaves holes for particular application attacks including XSS.
<br/>

### Verifying Headers
<br/>

When an HTTP request presents itself to an application, the browser can choose whether to accept or deny it. The key to allowing secure and legitimate HTTP requests is determining whether requests are coming from the source origin. 

If the request is not verified, it most likely falls under the forbidden headers list and the request is discarded. This is not the case for XSS attacks, which can manipulate script that the browser accepts. 

A strict verification process for all HTTP requests still leaves room for manipulated code injections if attackers know and understand the parameters.
<br/>

### Legacy Application Security Fails To Secure Against CSRF Attacks
<br/>

Legacy application security penetration testing and scanning approaches are employed by organizations to detect and remediate vulnerabilities in development before code releases are extended into production. 
<br/>
But as organizations embrace DevOps and Agile practices, legacy application security simply cannot scale to meet the corresponding demands of speed and flexibility. 

Penetration testing pushes application security into testing, which dramatically increases the cost of vulnerability remediation. This also delays development cycles and code releases.

Legacy application scanning such as static application security testing (SAST) and dynamic application security testing (DAST) shifts application security left, but both come with various challenges. Legacy SAST uses signature-based scans to identify potential vulnerabilities. But running application security scans and triaging and diagnosing security alerts require specialized application security specialists. 

Additionally, SAST generates significant false positives that consume valuable time. DAST generates fewer false positives, but a higher number of false negatives. As a result, both legacy SAST and DAST approaches impede release cycles while increasing application risk.


## Further Reading

- [White Paper: Route Coverage Through Instrumentation and Automated Vulnerability Management](https://www.contrastsecurity.com/hubfs/Route-Coverage-Through-Instrumentation_White%20Paper_052220_Final.pdf?hsLang=en)
- [White Paper: Advanced Threat Landscape and Legacy Application Security Ratchet Up Risk](contrastsecurity.com/hubfs/Advanced-Threat-Landscape-and-Legacy-Application-Security-Ratchets-Up-Risk_Whitepaper_07062020.pdf?hsLang=en)
- [Solution Brief: Contrast Protect with Runtime Application Self-protection (RASP)](https://www.contrastsecurity.com/runtime-application-self-protection-rasp-old)
