---
layout: page
title: Command Injection in Java
permalink: /io/Command Injection/Command Injection in Java
parent: Command Injection
nav_order: 4
---

## Command Injection in Java 

###  Introduction 

Any time user input is used to build a system command, the possibilities for abuse are real but widely misunderstood. 
In other languages, this is a high impact flaw without much further consideration. In Java, the picture is a little less clear. 


###  How To Fix in Java

Most of the time, arbitrary command execution isn't possible, but passing arbitrary command arguments to the target function can lead to similar dangers. Here are a few best practices that may help reduce your risk:


- **Refactor the command line call out** There are many who believe that Runtime.exec()calls inherently represent a bad design. If possible, use existing Java APIs, libraries, or external batch systems to accomplish the functionality without needing a dangerous, platform-dependent Java-to-OS bridge.
- **Use a parameterized interface** There are versions of the [class runtime](https://docs.oracle.com/javase/1.5.0/docs/api/java/lang/Runtime.html) and [Class ProcessBuilder](https://docs.oracle.com/javase/1.5.0/docs/api/java/lang/ProcessBuilder.html) calls that can hint to the OS to cleanly separate the arguments, which may help prevent a successful injection attack.
- **Avoid starting your command with /bin/sh -c or cmd.exe /c** These allow any user input in the command to be processed by the command shell instead of as parameters to a pure native CreateProcess(), execve() or similar. If the shell (like bash or cmd.exe) is used, malicious input can redirect commands, chain new commands, and in general cause more damage than otherwise possible. 

Let's take a more detailed look at the issue to understand what steps we should take. Here's an example of an unsafe command execution:
```
// DeleteStatementController.java

String statementId = request.getParameter("statementId");
String cmd = "cmd.exe /c C:/del_statement.exe " + statementId;
Runtime.getRuntime().exec(cmd);
```


This is trivially exploitable. For instance, passing the statementId{a value of foo &amp; calc, as shown in the following URL for the code above will cause the calculator to run on the target host
http://yoursite.com/app/deleteStatement?statementId=foo+%26+calc 


The following version of the same functionality does not exhibit the same risk. In this version, the attacker can only possibly inject additional arguments to the executable, and not actually issue new commands:

```
String statementId = request.getParameter("statementId");
String[] cmd = new String[2];
cmd[0] = "C:\del_statement.exe";
cmd[1] = statementId;
Runtime.getRuntime().exec(cmd);
```

{{#paragraph}}{{#badConfig}}WARNING!{{/badConfig}} Sometimes, an attacker can "do bad stuff", even if they can't directly inject into the command the application executes. Let's look at an example using /usr/bin/mail on a Linux machine. Even though direct injection isn't possible, the attacker can still attack the /usr/bin/mail program through the parameters.

```
String body = request.getParameter("body");
String[] args = {"/usr/bin/mail","-l","-s", validate(subject)};
Process p = Runtime.getRuntime().exec(args);
OutputStream os = p.getInputStream();
os.write(body.getBytes());
os.flush();
os.close();
```

Now consider the user sends in this value for the body parameter:

```
====8x==8x==8x====
~!/bin/cat /etc/passwd
====8x==8x==8x====
```
 

When processed, /usr/bin/mail interprets the {{#code}}~!{{/code}} to execute the command that follows. The contents of /etc/passwd will end up in the mail that is sent. The point of this is to emphasize the understanding of the interpretive capabilities that exist in the command you are executing, and not just those of the command shell itself. 


It's also always helpful to ensure that the application user is granted only the minimum OS and filesystem privileges necessary to perform its function. This may help reduce the impact of a successful command injection attack.