---
layout: default
title: Command Injection
nav_order: 1
---

# Command Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Command Injection

### Overview 
<br/>
**In Progresss- Do we have any Contrast Branded Diagrams/Video demos of this?** 

With a Command Injection attack, the goal is to hijack a vulnerable application in order to execute arbitrary commands on the host operating system. Command injection is made possible when an application passes unsafe user-supplied data (forms, cookies, HTTP headers, etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. 
<br/><br/>
Command injection vulnerabilities are most often found in older, legacy code, such as CGI scripts. By identifying a critical vulnerability, attackers can insert malicious code in an application, gaining functionality and ultimately executing specific commands that infect the targeted user and system networks.
<br/><br/> 
Under this attack, functionality on the application server can be modified and invoked. With unauthorized access to data, an account can add additional commands and potentially take complete control of the web server’s host operating system.


## Command Injection by Language 

### .NET 
<br/>
Any time user input is used to build a system command, the possibilities for abuse are real. Passing arbitrary command arguments to a process can lead to code execution or similar dangers. Here are a few best practices that may help reduce your risk:

- Refactor the command line call out. There are many who believe that native OS calls represent an inherently bad software design. In .NET, this is done by using the `System.Diagnostics.Process` class as illustrated in the example below. If possible, use existing .NET APIs, libraries, or external systems to accomplish the functionality without needing a dangerous, platform-dependent .NET-to-OS bridge.
- Avoid starting your command with the shell. Starting a command with the shell (e.g. `cmd.exe /c` on Windows or `/bin/sh -c` on Linux) allows any user input in the command to be processed by the command shell instead of as parameters to a native program.  If the shell is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. Instead, calls to `System.Diagnostics.Process.Start` should directly invoke the program you want to execute. Don't pass the program name as a parameter to a shell.


Let's take a more detailed look at the issue to understand what steps we should take. Here's an example of an unsafe command execution in C#:

```csharp
    String statementId = request.getParameter("statementId");
    Process p = new Process();
    p.StartInfo.Filename = "cmd.exe";
    p.StartInfo.Arguments = "/c c:\\del_statement.exe " + statementId;
    p.Start();
```

This is trivially exploitable. For instance, passing the `statementId` a value of `foo & calc`, as shown in the following URL for the code above will cause the calculator to run on the target host: `http://yoursite.com/app/deleteStatement?statementId=foo+%26+calc`

The following version of the same functionality does not exhibit the same risk. In this version, the attacker can only possibly inject additional arguments to the executable, and not actually issue new commands:

```csharp
String statementId = Request.QueryString("statementId");
    Process p = new Process();
    p.StartInfo.Filename = "c:\\del_statement.exe";
    p.StartInfo.Arguments = statementId;
    p.StartInfo.UseShellExecute = false;
    p.Start();
``` 

**Warning:** 
Sometimes, an attacker can cause harm or undesirable behavior even if they can't directly inject into the command the application executes. The best defense against command injection is to not pass user input to `System.Diagnostics.Process`.

It's also always helpful to ensure that the application user is granted only the minimum OS and filesystem privileges necessary to perform its function, this may help reduce the impact of a successful command injection attack.


<br/>
Any time user input is used to build a system command, the possibilities for abuse are real but widely misunderstood. 
In other languages, this is a high impact flaw without much further consideration. In Java, the picture is a little less clear. 
<br/>
<br/>

### Java
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk:


- **Refactor the command line call out** There are many who believe that Runtime.exec()calls inherently represent a bad design. If possible, use existing Java APIs, libraries, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Java-to-OS bridge.
- **Use a parameterized interface** There are versions of the [class runtime](https://docs.oracle.com/javase/1.5.0/docs/api/java/lang/Runtime.html) and [Class ProcessBuilder](https://docs.oracle.com/javase/1.5.0/docs/api/java/lang/ProcessBuilder.html) calls that can hint to the OS to cleanly separate the arguments, which may help prevent a successful injection attack.
- **Avoid starting your command with /bin/sh -c or cmd.exe /c** These allow any user input in the command to be processed by the command shell instead of as parameters to a pure native CreateProcess(), execve() or similar. If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 

Let's take a more detailed look at the issue to understand what steps we should take. Here's an example of an unsafe command execution:

```java
// DeleteStatementController.java

String statementId = request.getParameter("statementId");
String cmd = "cmd.exe /c C:/del_statement.exe " + statementId;
Runtime.getRuntime().exec(cmd);
```
<br/>

### Node 
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
<br/>
<br/>

### Python 
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
<br/>
<br/>

### Ruby 
<br/>
Any time user input is used to build a system command, this is a high impact flaw.
<br/>
Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk: 

- **Refactor the command line call out**
<br/> 
There are many who believe that calls like `eval` or `cKernel.exec` represent an inherently bad design.  If possible, use existing Ruby APIs, modules, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Ruby-to-OS bridge. 

- **Avoid starting with specific commands** 
<br/>
`/bin/sh -` or `cmd.exe /c` commands allow any user input to be processed by the command shell instead of as parameters to a pure native `Kernel.spawn`.  
If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 

- **Use a parameterized interface** 
<br/>
If you must allow for user controlled options, use methods such as [exec(cmdname, arg1, ...)](https://ruby-doc.org/core-2.5.1/Kernel.html#method-i-exec:~:text=exec(cmdname%2C%20arg1%2C%20...)), which cleanly separate the arguments from the command itself (which should never be set from user-supplied data), and may help prevent a successful injection attack. 
<br/>
<br/>

### PHP 
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


## How can Contrast help?
<br/>

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect Command Injection vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block Command Injection attacks at runtime. 
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect Command Injection vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
- [Contrast Serverless](https://www.contrastsecurity.com/contrast-serverless) can determine if you are vulnerable within your Cloud Native environment.









