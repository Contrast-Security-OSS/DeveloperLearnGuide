---
layout: page
title: Command Injection in Python
permalink: /io/Command Injection/Command Injection in Python
parent: Command Injection
nav_order: 6
---

## Command Injection in Python


###  How To Fix in Python 
<br/>
Any time user input is used to build a system command, this is a high impact flaw.
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk: 

- **Refactor the command line call out** 
<br/>
There are many who believe that calls like `os.system` or `subprocess.Popen` represent an inherently bad design. If possible, use existing Python APIs, modules, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Python-to-OS bridge. 

- **Avoid starting with specific commands** 
<br/>

`/bin/sh -` or `cmd.exe /c` commands allow any user input to be processed by the command shell instead of as parameters to a pure native `subprocess.Popen`. 
For the same reason, when using `subprocess.Popen` or related functions, do not set `shell=True`. If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 