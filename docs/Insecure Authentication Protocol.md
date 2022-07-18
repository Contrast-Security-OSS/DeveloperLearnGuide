---
layout: default
title: Insecure Authentication Protocol
nav_order: 5
---

# Insecure Authentication Protocol
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Insecure Authentication Protocol
<br/>
The use of outdated and insecure authentication protocols puts your application and sensitive data at serious risk.


### Impact

- The **Basic Authentication** protocol simply hides the plaintext username and password inside of Base64 encoding, and issues it as an Authorization header. To any attacker sniffing network traffic, the credentials may as well be in plaintext. 
<br/> 
Base64 offers zero cryptographic functionality. It is a keyless, deterministic algorithm, and most attack tools decode such credentials automatically.

- The **Digest Authentication** protocol is superior to Basic Authentication in that it doesn't offer a user's password in plaintext. Instead, it offers a method of authentication that proves knowledge of a secret (a password) without passing the password directly. 
<br/>
Since RFC2617, the optional security features of Digest Authentication have been improved, but not enforced. The disadvantages of the protocol, including the changes in RFC2617, are subtle.

Digest authentication is easily attacked by a man-in-the-middle (MITM) scenario.
Use of digest authentication precludes the usage of recommended password digests like bcrypt.
<br/>
Passwords, or some digested combination of the password and other metadata must be available to the server in plaintext in order to use this protocol.

### How To Fix

In Progress

### How can Contrast hekp?

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
