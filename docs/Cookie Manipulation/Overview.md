---
layout: page
title: Overview
permalink: /io/Cookie Manipulation/Overview
parent: Cookie Manipulation
nav_order: 37
---

## Cookie Manipulation

### What Is It?


The most effective method of preventing Cookie Manipulation is to restrict data from untrusted sources dynamically writing to cookies, and apply appropriate sanitization to all incoming data.

### Impact

- For cookies that control behaviour from user actions, a malicious actor may be able to manipulate the cookie's value in order to perform unintended actions on behalf of the user.
- For session tracking cookies, the attacker may be able to leverage a session fixation attack. This attack works by using a valid token within the cookie parameter, and hijacking the user's next interaction with the site. The risk of this can range from privacy concerns to takeover of user's account.



### Prevention  

Ensure you restrict data from untrusted sources dynamically writing to cookies.

Always apply appropriate sanitization to all incoming data to protect your application.




### How can Contrast help?

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect Cookie Manipulation vulnerabilities
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block Cookie Manipulation attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect Cookie Manipulation vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.