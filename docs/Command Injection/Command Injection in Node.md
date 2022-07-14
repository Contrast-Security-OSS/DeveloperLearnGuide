---
layout: page
title: Command Injection in Node
permalink: /io/Command Injection/Command Injection in Node
parent: Command Injection
nav_order: 5
---

## Command Injection in Node


###  How To Fix in Node
<br/>
Any time user input is used to build a system command, this is a high impact flaw.
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk:

- **Refactor the command line call out** 
<br/>
There are many who believe that calls like `eval` or `child_process.exec` represent an inherently bad design. If possible, use existing Node APIs, modules, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Node-to-OS bridge.

- **Avoid starting with specific commands* 
<br/> 
`/bin/sh -` or `cmd.exe /c` commands allow any user input to be processed by the command shell instead of as parameters to a pure native `child_process.spawn`. 
If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 

- **Use a parameterized interface** 
<br/>
If you must allow for user controlled options, use methods such as [child_process.spawn(command[, args][, options])](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) and [child_process.exec(command[, options][, callback])](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback). 
