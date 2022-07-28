---
layout: home
title: Welcome
permalink: /
has_children: true
nav_order: 0
has_toc: false
---
# Learning Guide

**In Progress-Confirm if we're keeping a landing page?**
<br/> 
<br/> 
The Contrast Learn Guide is for developers like you.

We strive to use our years of experience in the field to provide the most helpful point of reference. 

While we will walk you through the correct techniques to fix and prevent attacks, we aim to empower Engineers within your team and organization to make the most informed decision regarding your security landscape.

## Contribute 

<br/> 
Do you have another attack example to share? 
<br/>
Are there any descriptions that are unclear?
<br/><br/>
We welcome you to contribute to our guide by submitting an issue or pull request.
<br/><br/>
[Contrast GitHub Community](https://github.com/Contrast-Security-Inc){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }
<br/> 


## Developer Resources 

### Contrast CodeSec 
<br/> 
CodeSec is Contrast Security’s new free developer security tool that brings the fastest and most accurate
scanner in the market right to developers for FREE. 
<br/> 

Providing actionable remediation guidance, CodeSec by Contrast enables developers to get up and running in less than five minutes. 

Here's how: 


#### 1. Start Now
<br/> 
Head over to https://www.contrastsecurity.com/developer to begin. 

#### 2. Install via CLI 
<br/> 
CodeSec also offers multiple install options including NPM, Artifactory, and Homebrew 

**Via Homebrew**

```ruby
brew tap contrastsecurity/tap
brew install contrast
```
<br/>
**Via NPM**

```js
npm install -g @contrast/contrast
```
<br/>

**Via Artifactory**

- Go to https://pkg.contrastsecurity.com/ui/repos/tree/General/cli
- Select your operating system under the **cli** folder and download the package.
- You must allow execute permissions on the file depending on your OS.




#### 3. Authorize 
<br/> 
CodeSec allows you to auth with either Google or GitHub. 

#### 4. Run CodeSec<br/> 
<br/> 
CodeSec gives you the option to run serverless or scan in your project folder.

```
Searched 3 directory levels & found:
- build/...SNAPSHOT.jar
- build/...SNAPSHOT.war
``` 
<br/>

#### 5. Scan JAR / WAR 
<br/> 
Scan via: 

```js
contrast scan -f build/libs/
terracotta-bank-servlet-0.0.1-
SNAPSHOT.jar
``` 


Example output: 

```js
Found 17 vulnerabilities
8 Critical | 3 High | 5 Medium |
0 Low | 1 Note
``` 
<br/>

#### 6. Results 
<br/> 

We’ll tell you not only what vulnerabilities you have, but what you should tackle first.

```js
Scan completed in 25.19s
Here are your top priorities to fix
CRITICAL | sql-injection
...
```
<br/> 

### Contrast Platform

#### Contrast Assess 
<br/>
<iframe width="560" height="315" src="https://www.youtube.com/embed/z0DBdAW6IKw" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe> 

<br/>

#### Contrast Protect 
<br/>
<iframe width="560" height="315" src="https://www.youtube.com/embed/-cV6BsTQpi4" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe> 
<br/> 



#### Contrast Scan
<br/> 
<iframe width="560" height="315" src="https://www.youtube.com/embed/AvRG2KzQk4w" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe> 
<br/>  


#### Contrast SCA
<br/> 
<iframe width="560" height="315" src="https://www.youtube.com/embed/8HH6kjSva1k" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
<br/> 

#### Contrast Serverless
<br/> 
<iframe width="560" height="315" src="https://www.youtube.com/embed/ferTzMA-uhI" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
