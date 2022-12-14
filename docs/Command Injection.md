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
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Command Injection

### Vulnerability 
<br/>
Applications sometimes invoke the operating system to perform tasks. Application server processes often run with significan privilege, so the commands sent to the operating system are powerful.

In some cases, applications use untrusted data (URL, form data, cookies, headers, etc...) as part of the command sent to the operating system. Unless that data is carefully validated and escaped, special characters could change the meaning of the command. In some cases it's possible to chain additional commands. This is a Command Injection vulnerability.

The data flow that untrusted data follows to an operating system command can often be quite complex, with application frameworks, business logic, data layers, libraries, and other complicated code paths that make XSS difficult to see.

### Attacks
<br/>

### Impact 
<br/>
Command injection vulnerabilities can potentially run arbitrary code on an application server host and access or corrupt all data stored there, including software code, credentials, keys, tokens, and data.


### How To Fix 
Generally you should avoid the use of operating system commands in your applications. If you must use them, try not to use any untrusted data in them. If you must use untrusted data, be sure to escape all non-ASCII characters and validate carefully. See language specific details below.
<br/>


## Command Injection by Language 

### .NET 
<br/>

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
Unless a call to Runtime.exec() actually invokes the shell, arbitrary command execution usually isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk:


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



Passing the `statementId` a value of `foo &amp; calc`, as shown in the following URL for the code above will cause the calculator to run on the target host:

`http://yoursite.com/app/deleteStatement?statementId=foo+%26+calc`

Let's fix this problem-in this version, the attacker can only possibly inject additional arguments to the executable, and not actually issue new commands:

```java
String statementId = Request.QueryString("statementId");
Process p = new Process();
p.StartInfo.Filename = "c:\\del_statement.exe";
p.StartInfo.Arguments = statementId;
p.StartInfo.UseShellExecute = false;
p.Start();
```

**Note:** 
<br/>
Sometimes, an attacker can cause harm or undesirable behavior even if they can't directly inject into the command the application executes. The best defense against command injection is to not pass user input to `System.Diagnostics.Process`.

It's also always helpful to ensure that the application user is granted only the minimum OS and filesystem privileges necessary to perform its function. This may help reduce the impact of a successful command injection attack.


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









