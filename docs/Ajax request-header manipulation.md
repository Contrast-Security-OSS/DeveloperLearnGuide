# Ajax Request Header Manipulation 
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

### Vulnerability 
<br/>
Ajax applications make asynchronous requests from the browser to the server. If the application's Javascript code takes information from an untrusted source (such as the URL) and use it in an XmlHttpRequest header, the attacker may be able to trick the application into generating a malicious request. 

The data flow that untrusted data follows to an Ajax request header command can often follow complex code paths that make header manipulation difficult to see.


### Attacks
<br/>

The attacker sends a malicious URL to a victim, who clicks on the link. The Ajax application uses data from that URL to create an Ajax request containing the malicious data in a header.


### Impact 
<br/>

Depending on how the server application handles the header data, this vulnerability may enable the attacker to perform actions on behalf of a user. As such, it may be used in a chain or sequence of attacks such as Cross Site Scripting (XSS), making the impact more severe.


### How To Fix 
<br/>
The most effective method of preventing Ajax Header Manipulation is to restrict data from untrusted sources being used to dynamically set Ajax request headers. Ensure to apply all standard security measures such as proper authentication and authorization, as well as validation of input, and appropriate escaping of output.