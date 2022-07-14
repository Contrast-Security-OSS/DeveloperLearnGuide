---
layout: page
title: Command Injection in Ruby
permalink: /io/Command Injection/Command Injection in Ruby
parent: Command Injection
nav_order: 7
---

## Command Injection in Ruby


###  How To Fix in Ruby 
<br/>
Any time user input is used to build a system command, this is a high impact flaw.
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk: 

- **Refactor the command line call out** 
There are many who believe that calls like `eval` or `cKernel.exec` represent an inherently bad design.  If possible, use existing Ruby APIs, modules, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Ruby-to-OS bridge. 

- **Avoid starting with specific commands** 
`/bin/sh -` or `cmd.exe /c` commands allow any user input to be processed by the command shell instead of as parameters to a pure native `Kernel.spawn`.  
If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 

- **Use a parameterized interface** 
If you must allow for user controlled options, use methods such as [exec(cmdname, arg1, ...)](https://ruby-doc.org/core-2.5.1/Kernel.html#method-i-exec:~:text=exec(cmdname%2C%20arg1%2C%20...)), which cleanly separate the arguments from the command itself (which should never be set from user-supplied data), and may help prevent a successful injection attack. 