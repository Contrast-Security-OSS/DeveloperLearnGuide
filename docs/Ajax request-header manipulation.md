# Ajax Request Header Manipulation 
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[Find vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-green }

### Overview 
<br/>
This type of attack occurs using a script is used to write attacker controllable data. This is then placed into the request header of an Ajax request, provided by a XmlHttpRequest object.

An attacker can target this weakness to create a URL, that when visited will create a arbitrary header in the next Ajax request. 



### Impact 
<br/>

This vulnerability may enable the attacker to perform actions on behalf of a user. As such, it may be used in a chain or sequence of attacks such as Cross Site Scripting (XSS), making the impact more severe.


### How To Fix 
<br/>
The most effective method of preventing Ajax Header Manipulation is to restrict data from untrusted sources dynamically setting Ajax request headers. Ensure to apply all standard security measures such as proper authentication and authorization, as well as validation of input, and appropriate escaping of output.