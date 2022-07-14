---
layout: page
title: Command Injection in Go
permalink: /io/Command Injection/Command Injection in Go
parent: Command Injection
nav_order: 8
---

## Command Injection in Go


###  How To Fix in Go 
<br/>
Any time user input is used to build a system command, this is a high impact flaw.
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk: 

- **Refactor the command line call out** 
There are many who believe that calls like `os/exec.Command(...).Run()` or `os.StartProcess(...)` represent an inherently bad design. 
If possible, use existing Go APIs, modules, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Go-to-OS bridge. 

- **Avoid starting with specific commands** 
`/bin/sh -` or `cmd.exe /c` commands allow any user input to be processed by the command shell instead of as parameters to a pure native `os/exec.Command(...).Run()`. 

- **Avoid setting first parameter as user supplied** 
When using `os/exec.Command(...).Run()` or related functions, do not set the first parameter as user supplied. 
If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 