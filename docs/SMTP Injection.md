---
layout: default
title: SMTP Injection
nav_order: 12
---

# SMTP Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


## SMTP Injection


### What Is It?

SMTP Injection is an attack that can be used to control part of the outgoing email or inject attachments.
When email or contact form headers are set and interpreted, these are turned into SMTP commands, and subsequently proocessed by the SMTP server. 

An application is at risk, however, if user input is not validated. 

This makes it possible for an attacker to set additional headers, allowing the mail server to perform unintended actions. 


### Impact 

As is shown, the user controls a piece of the outgoing SMTP message. Depending on the piece of the message the untrusted user can control, it's possible that the functionality can be abused.  

- By controlling the destination fields, subject or body, they can possibly repurpose the email for phishing purposes.  
- By controlling headers directly, they can create malicious attachments, re-route the message, or other undesirable behavior.


## Prevention 

Use indirect references, or static/trusted data to supply all the fields and headers of an SMTP message. 
As always, sanitize all user input. 

### Java

Let's walkthrough preventing this vulnerability when using Java in your application.

Here's an **unsafe** example of letting the user control the e-mail user input in a SMTP header:

```
String subject = request.getParameter("subject");
Message msg = new MimeMessage(session);
msg.setSubject(subject);
```

By using an indirect reference, we can allow the user to control the subject, without allowing them to supply an arbitrary value: 

```
String subject = null;
String subjectId = request.getParameter("subject");
Message msg = new MimeMessage(session);
if("SUB1".equals(subjectId)) {
  subject = "Your friend wants to send you a video!";
} else if("SUB2".equals(subjectId)) {
  subject = "Your friend wants to send you an image!";
} else if("SUB3".equals(subjectId)) {
  subject = "Your friend wants to send you a message!";
}
msg.setSubject(subject);
```

### .NET

Next, let's look at prevention of SMTP Injection when using .NET. 

Here's an **unsafe** example of letting the user control the e-mail user input in a SMTP header:

```
string subject = Request.QueryString["subject"];

var mailMessage = new MailMessage();
mailMessage.Subject = subject;
``` 

By using an indirect reference, we can allow the user to control the subject, without allowing them to supply an arbitrary value:

```
string subject;
switch (Request.QueryString["subject"])
{
    case "SUB1": subject = "Your friend wants to send you a video!"; break;
    case "SUB2": subject = "Your friend wants to send you an image!"; break;
    default: subject = "Your friend wants to send you a message!"; break;
}

var mailMessage = new MailMessage();
mailMessage.Subject = subject;
```



## How can Contrast help? 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect CMTP Injection vulnerabilities as you code.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block SMTP Injection attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect SMTP Injection vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.