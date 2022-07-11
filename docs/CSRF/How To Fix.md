---
layout: page
title: How To Fix
permalink: /io/Cross Site Request Forgery/How To Fix
parent: Cross Site Request Forgery
nav_order: 3
---

### How To Fix 

The best defense against a CSRF attack is to equip applications with a way to distinguish between legitimate and forged HTTP requests. One of the most effective ways is to change the way that applications manage cookies and CSRF tokens. 

Most of today's applications have built-in CSRF token defenses that help avert the risk of an application attack. However, as they are built-in, these defenses must be constantly configured to provide the strongest line of defense.

### The Use of CSRF Tokens

When configuring CSRF tokens to effectively prevent CSRF attacks, two things should take place. First, CSRF tokens should be configured to be generated on the server side. Second, the option for token generation should renew per request and not per session. With these two configurations, applications are more secure but lack efficiency. 

If tokens generate per request, things such as the “back button” can no longer remain valid. This means that with each click, users face the possibility of needing to re-enter their credentials. This is perhaps why most applications configure CSRF tokens per session, bringing about an additional application vulnerability if sessions are not properly managed.


### Cookie Management

Cookies are always sent along with requests from one origin to another as long as they are deemed secure. This allows for cross-domain passing of cookies, which can include user credentials. 

To combat this CSRF vulnerability, organizations need to flag cookies to transform them into same-site cookies. This means that the browser decides whether to execute requests based on the origin of the cookies, possibly preventing a CSRF attack. There are three possible options when choosing same-site cookies attributes, including lax, strict, or none. 

The none attribute grants permission for the sharing of cookies to all parties, which includes third-party and advertisers. Lax comes with more restrictions, allowing only first-party cookies to be sent or accessed. 

Strict is the most secure, used in banking applications and others that hold PII. Though this type of cookie management is more secure, it is still just an additional layer of defense that leaves holes for particular application attacks including XSS.


### Verifying Headers


When an HTTP request presents itself to an application, the browser can choose whether to accept or deny it. The key to allowing secure and legitimate HTTP requests is determining whether requests are coming from the source origin. 

If the request is not verified, it most likely falls under the forbidden headers list and the request is discarded. This is not the case for XSS attacks, which can manipulate script that the browser accepts. 

A strict verification process for all HTTP requests still leaves room for manipulated code injections if attackers know and understand the parameters.


### Legacy Application Security Fails To Secure Against CSRF Attacks


Legacy application security penetration testing and scanning approaches are employed by organizations to detect and remediate vulnerabilities in development before code releases are extended into production. But as organizations embrace DevOps and Agile practices, legacy application security simply cannot scale to meet the corresponding demands of speed and flexibility. 

Penetration testing pushes application security into testing, which dramatically increases the cost of vulnerability remediation. This also delays development cycles and code releases.

Legacy application scanning such as static application security testing (SAST) and dynamic application security testing (DAST) shifts application security left, but both come with various challenges. Legacy SAST uses signature-based scans to identify potential vulnerabilities. But running application security scans and triaging and diagnosing security alerts require specialized application security specialists. 

Additionally, SAST generates significant false positives that consume valuable time. DAST generates fewer false positives, but a higher number of false negatives. As a result, both legacy SAST and DAST approaches impede release cycles while increasing application risk.
