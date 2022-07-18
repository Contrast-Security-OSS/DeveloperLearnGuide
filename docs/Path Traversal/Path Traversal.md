---
layout: default
title: Path Traversal
nav_order: 4
has_children: true
permalink: docs/utilities
---

# Path Traversal
{: .no_toc }


### What Is It? 
<br/>

Path traversal (also known as directory traversal) is an attack that uses an affected application to gain unauthorized access to server file system folders that are higher in the hierarchy than the web root folder. 

A successful path traversal attack can fool a web application into reading and consequently exposing the contents of files outside of the document root directory of the application or the web server, including credentials for back-end systems, application code and data, and sensitive operating system files.

Path traversal vulnerabilities can exist in a variety of programming languages, including Python, PHP, Apache, ColdFusion, and Perl. They can also be located in web server software or in application code executed on a server. 


### When Can It Affect My Application? 
<br/>

Path Traversal occurs when remote input is sent to file APIs that select which file to open for read or write.



### Impact 
<br/>

If an application is vulnerable to to Path Traversal, this can enable an attacker to obtain and read senitive files, for example database credentials, source code, and private encyrption keys. 

In some cases, bad actors may also be able to write data to arbitrary files, enabling them to upload malicious files that will automatically run, etc.





### How can Contrast help? 



- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) can monitor requests of your application and determine if the application checks origins or items that will block Path Traversal vulnerabilities.

- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block Path Traversal attacks at runtime. 

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) observes the data flows in the source code and identifies if your custom code is vulnerable to this attack. 

- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack.