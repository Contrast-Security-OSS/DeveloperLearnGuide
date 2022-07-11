---
layout: page
title: Command Injection in Dotnet
permalink: /io/Command Injection/Command Injection in Dotnet
parent: Command Injection
nav_order: 3
---

### Command Injection in .NET

## How To Fix

Any time user input is used to build a system command, the possibilities for abuse are real. Passing arbitrary command arguments to a process can lead to code execution or similar dangers. Here are a few best practices that may help reduce your risk:

	- Refactor the command line call out. There are many who believe that native OS calls represent an inherently bad software design. In .NET, this is done by using the `System.Diagnostics.Process` class as illustrated in the example below. If possible, use existing .NET APIs, libraries, or external systems to accomplish the functionality without needing a dangerous, platform-dependent .NET-to-OS bridge.
	- Avoid starting your command with the shell. Starting a command with the shell (e.g. `cmd.exe /c` on Windows or `/bin/sh -c` on Linux) allows any user input in the command to be processed by the command shell instead of as parameters to a native program.  If the shell is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. Instead, calls to `System.Diagnostics.Process.Start` should directly invoke the program you want to execute. Don't pass the program name as a parameter to a shell.


Let's take a more detailed look at the issue to understand what steps we should take. Here's an example of an unsafe command execution in C#:

    String statementId = request.getParameter("statementId");
    Process p = new Process();
    p.StartInfo.Filename = "cmd.exe";
    p.StartInfo.Arguments = "/c c:\\del_statement.exe " + statementId;
    p.Start();

This is trivially exploitable. For instance, passing the `statementId` a value of `foo & calc`, as shown in the following URL for the code above will cause the calculator to run on the target host:
http://yoursite.com/app/deleteStatement?statementId=foo+%26+calc

The following version of the same functionality does not exhibit the same risk. In this version, the attacker can only possibly inject additional arguments to the executable, and not actually issue new commands:

    String statementId = Request.QueryString("statementId");
    Process p = new Process();
    p.StartInfo.Filename = "c:\\del_statement.exe";
    p.StartInfo.Arguments = statementId;
    p.StartInfo.UseShellExecute = false;
    p.Start();

WARNING! Sometimes, an attacker can cause harm or undesirable behavior even if they can't directly inject into the command the application executes. The best defense against command injection is to not pass user input to `System.Diagnostics.Process`.

It's also always helpful to ensure that the application user is granted only the minimum OS and filesystem privileges necessary to perform its function. This may help reduce the impact of a successful command injection attack.