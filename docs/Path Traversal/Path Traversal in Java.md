---
layout: page
title: Path Traversal in Java
permalink: /io/Path Traversal/Path Traversal in Java
parent: Path Traversal
nav_order: 4
---

## Path Traversal in Java 
<br/>
Let's walkthrough an example of Path Traversal in Java and how to fix this. 

```
String statement = request.getParameter("statement");
if(!statement.endsWith(".xml")) { // Validate (weakly) this file is an xml file
   logger.error("Bad filename sent");
   return;
}
// Read the specified file
File file = new File(STATEMENT_DIR, statement);
FileInputStream fis = new FileInputStream(file);
byte[] fileBytes = new byte[file.length()];
fis.read(fileBytes);
response.getOutputStream().write(fileBytes);
``` 

Often, there is no filename validation at all. 

Either way, an attacker could abuse this functionality to view the ```/etc/passwd``` file on a UNIX system by passing the following value for the ```statement``` parameter: ```http://yoursite.com/app/pathTraversal?statement=../../../../../../../../etc/passwd%00.xml``` 


The NULL byte ```(%00)``` is just another ```char``` to Java, so the malicious value passes the ```endsWith()``` check. 

However, when the value is passed to the operating system's native API, the NULL byte will represent an end-of-string character, and open the attacker's intended file.

**Note:** that Null byte injection in Java was fixed in Java 7 Update 45. 
Ensure you are using _at least_ this version of Java, in addition to validating the user's input to this File accessor code. 


### How to Fix 
<br/>


To prevent these types of attacks when using Dotnet, try the following steps: 

- **Use maps to filter out invalid values** 

Instead of accepting input like ```file=string```, accept ```file=int```. That ```int``` can be a key in a map that points to an allowed file.  
If the map has no corresponding value for the key given, then throw an error. 

- **Strongly validate the file value** 

Validate the file using an allowlist or regular expression: 
```
Pattern p = Pattern.compile("^[A-Za-z0-9]+\\.xml$");
String statement = request.getParameter("statement");
/* Validate the statement to prevent access to anything but XML files */
if( !p.matcher(statement).matches() ) {
    response.sendError(404);
    return;
}
// Read the file here as normal
```