---
layout: page
title: Command Injection in PHP
permalink: /io/Command Injection/Command Injection in PHP
parent: Command Injection
nav_order: 9
---

## Command Injection in PHP


###  How To Fix in PHP 
<br/>
Any time user input is used to build a system command, this is a high impact flaw.
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk: 

- **Refactor the command line call out**
<br/> 
There are many who believe that calls like `os.system` or `subprocess.Popen` represent an inherently bad design. 
If possible, use existing PHP APIs, modules, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent PHP-to-OS bridge. 

- **Avoid starting with specific commands** 
<br/>
`/bin/sh -` or `cmd.exe /c` commands allow any user input to be processed by the command shell instead of as parameters to a pure native `system`. 

For the same reason, when using `shell_exec` or related functions, do not set the first parameter as user-supplied input. 
If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible.