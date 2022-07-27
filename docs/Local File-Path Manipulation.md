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
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Local File-Path Manipulation

### Overview 
<br/>
An attacker may be able to use this flaw to modify the path, and access sensitive data and resources, such as config files.

### How To Fix 
<br/>
The most effective method of preventing File Path Manipulation is to not place user controlled data into file paths in order to access resources. If this is not possible, there should be appropriate data validation against a list of allowed and accepted values.
