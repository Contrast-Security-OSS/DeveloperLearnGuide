---
layout: page
title: Path Traversal in Dotnet
permalink: /io/Path Traversal/Path Traversal in Dotnet
parent: Path Traversal
nav_order: 3
---

## Path Traversal in Dotnet 

Let's walkthrough an example of Path Traversal in .NET Core and how to fix this.

```
String statement = HttpContext.Request.Query("statement");
#end
if (!statement.EndsWith(".xml")) { // Validate (weakly) this file is an xml file
	logger.Error("Bad filename sent");
	return;
}

// Read the specified file
String path = STATEMENT_DIR + statement;
FileStream fs = File.Open(path, FileMode.Open);
byte[] b = new byte[1024];
int len;
while ((len=fs.Read(b,0,b.Length)) > 0) {
	Response.OutputStream.Write(b,0,len);
}
```

Often, there is no filename validation at all. 

Either way, an attacker could abuse this functionality to view protected configuration files by passing the following value for the ```statement``` parameter: ```http://yoursite.com/app/pathTraversal?statement=../../../../../../web.xml``` 

To prevent attacks like this, any of the following steps could help:

- **Use maps to filter out invalid values** 

Instead of accepting input like ```file=string```, accept ```file=int```. That ```int``` can be a key in a map that points to an allowed file. 
If the map has no corresponding value for the key given, then throw an error.

- **Strongly validate the file value** 

Validate the file using an allowlist or regular expression. 


Example Path Traversal validator:

```
namespace Contrast;

public static class SecurityUtils
{
    // Validate 'statement' to prevent access to anything but XML files with no path
    public static bool IsValidStatementPath(string statementPath)
    {
        Regex r = new Regex("^[A-Za-z0-9]+\\.xml$");
        return r.IsMatch(statementPath);
    }
}
``` 


- Example usage of validator in **.NET Core**: 

```
    String statement = HttpContext.Request.Query("statement");
#end
    if (Contrast.SecurityUtils.IsValidStatementPath(statement))
    {
        // Read the file here as normal
    }
    else
    {
        // log error message
    }
```