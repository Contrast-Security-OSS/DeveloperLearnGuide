# Ajax Request Header Manipulation 
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

### Overview 
<br/>
Ajax applications make asynchronous requests from the browser to the server. The Ajax code may take information from the URL and other attacker-controlled sources and use it in the header of an XmlHttpRequest. If the attacker can get a user to open a malicious URL, that user's browser will generate an Ajax request with a malicious header and send it to the server.


### Impact 
<br/>

Depending on how the server application handles the header data, this vulnerability may enable the attacker to perform actions on behalf of a user. As such, it may be used in a chain or sequence of attacks such as Cross Site Scripting (XSS), making the impact more severe.


### How To Fix 
<br/>
The most effective method of preventing Ajax Header Manipulation is to restrict data from untrusted sources being used to dynamically set Ajax request headers. Ensure to apply all standard security measures such as proper authentication and authorization, as well as validation of input, and appropriate escaping of output.