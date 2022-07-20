---
layout: default
title: Local File-Path Manipulation
nav_order: 8
---

# Local File-Path Manipulation
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Local File-Path Manipulation

### Overview 

An attacker may be able to use this flaw to modify the path, and access sensitive data and resources, such as config files.

### How To Fix 

The most effective method of preventing File Path Manipulation is to not place user controlled data into file paths in order to access resources. If this is not possible, there should be appropriate data validation against a list of allowed and accepted values.


## How can Contrast help?  

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.

