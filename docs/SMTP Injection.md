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
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-green }

## SMTP Injection


### Overview 
<br/> 

SMTP Injection is an attack that can be used to control part of the outgoing email or inject attachments.
When email or contact form headers are set and interpreted, these are turned into SMTP commands, and subsequently proocessed by the SMTP server. 

An application is at risk, however, if user input is not validated. 

This makes it possible for an attacker to set additional headers, allowing the mail server to perform unintended actions. 


### Impact 
<br/> 

As is shown, the user controls a piece of the outgoing SMTP message. Depending on the piece of the message the untrusted user can control, it's possible that the functionality can be abused.  

- By controlling the destination fields, subject or body, they can possibly repurpose the email for phishing purposes.  
- By controlling headers directly, they can create malicious attachments, re-route the message, or other undesirable behavior.


## Prevention  
<br/> 

Use indirect references, or static/trusted data to supply all the fields and headers of an SMTP message. 
As always, sanitize all user input. 

### Java 
<br/> 

Let's walkthrough preventing this vulnerability when using Java in your application.

Here's an **unsafe** example of letting the user control the e-mail user input in a SMTP header:

```java
String subject = request.getParameter("subject");
Message msg = new MimeMessage(session);
msg.setSubject(subject);
```

By using an indirect reference, we can allow the user to control the subject, without allowing them to supply an arbitrary value: 

```java
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
<br/> 

Next, let's look at prevention of SMTP Injection when using .NET. 

Here's an **unsafe** example of letting the user control the e-mail user input in a SMTP header:

```csharp
string subject = Request.QueryString["subject"];

var mailMessage = new MailMessage();
mailMessage.Subject = subject;
``` 

By using an indirect reference, we can allow the user to control the subject, without allowing them to supply an arbitrary value:

```csharp
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