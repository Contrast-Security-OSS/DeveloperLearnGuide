# Path Traversal
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Path Traversal 

<br/>

Path traversal (also known as directory traversal) is an attack that uses an affected application to gain unauthorized access to server file system folders that are higher in the hierarchy than the web root folder. 

A successful path traversal attack can fool a web application into reading and consequently exposing the contents of files outside of the document root directory of the application or the web server, including credentials for back-end systems, application code and data, and sensitive operating system files.

Path traversal vulnerabilities can exist in a variety of programming languages, including Python, PHP, Apache, ColdFusion, and Perl. They can also be located in web server software or in application code executed on a server. 


### When Can It Affect My Application? 
<br/>

Path Traversal occurs when remote input is sent to file APIs that select which file to open for read or write.



### Impact 
<br/>

If an application is vulnerable to to Path Traversal, this can enable an attacker to obtain and read senitive files, for example database credentials, source code, and private encyrption keys. 

In some cases, bad actors may also be able to write data to arbitrary files, enabling them to upload malicious files that will automatically run, etc.





### How can Contrast help? 



- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) can monitor requests of your application and determine if the application checks origins or items that will block Path Traversal vulnerabilities.

- [Contrast Protect](https://www.contrastsecurity.com/contrast-protect) can detect and block Path Traversal attacks at runtime. 

- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) observes the data flows in the source code and identifies if your custom code is vulnerable to this attack. 

- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack. 



## Path Traversal by Language

### Path Traversal in Dotnet 

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
<br/>


- Example Path Traversal validator

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
<br/> 

### Path Traversal in Java 

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

**How to Fix**

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
<br/> 

### Path Traversal in Go 

Let's walkthrough an example of Path Traversal in Go and how to fix this.

```
http.HandleFunc("/endpoint", func(w http.ResponseWriter, r *http.Request) {
    // Read untrusted data from the Request
		filepath := r.FormValue("filepath")

    ...

    // Untrusted data is used to open a file
		f,err := os.Open(filepath)

    ...
	})
```

Often, there is no filename validation at all. 

Either way, an attacker could abuse this functionality to view protected configuration files by passing the following value for the ```filename``` parameter: ```http://yoursite.com/app/pathTraversal?statement=../../../../../../config.yaml``` 


To prevent attacks like this, any of the following steps could help: 

**Use maps to filter out invalid values** 

Instead of accepting input like ```file_id=string```, accept
``file_id=int```. That ```int``` can be a key in a map that points to an allowed file. 
If the map has no corresponding value for the key given, then throw an error.

**Strongly validate the filename value** 

For example, validate the filename using an allowlist or regular expression. 
<br/> 

### Path Traversal in Node 

The following [module](https://nodejs.org/api/path.html) contains tools to help reduce the risk of an attacker accessing 
files they should not have access to.  

For example, if user input is needed to determine the location of a file, it could be done as follows:

```
var path = require('path');
var rootDir = '/foo/bar/';
var fileName = path.join(rootDir, fileNameFromUserInput);
```

**Note:** the slash at the end of the root directory name. 

This is to prevent an attacker from changing the name of the bar directory. 

```path.resolve``` handles things like slash direction for operating systems and removal of ```..``` 

However, that if user input contained ``..`` the user may still have been able to manipulate ``path.join`` into return a directory with a root that is different from what was supplied. 

Always be sure to check for this. 
<br/> 

### Path Traversal in PHP 
<br/>

Let's walkthrough an example of Path Traversal in PHP and how to fix this.

```
$fileContents = '';
$filename = $_GET['filename'] ?? '';

/* This type of validation is not strong enough to prevent path traversal */
if (str_ends_with($filename, ".yaml")) {
    $fileContents = file_get_contents($filename);
}
```

Often, there is no filename validation at all.  
Either way, an attacker could abuse this functionality to view protected configuration files by passing the following value for the ```filename``` parameter: ```http://yoursite.com/app/pathTraversal?statement=../../../../../../config.yaml``` 


To prevent attacks like this, any of the following steps could help: 

**Use maps to filter out invalid values** 

Instead of accepting input like ```$file_id=string```, accept ```$file_id=int```. 
```int``` can be a key in an array that points to an allowed file. 
If the array has no corresponding value for the key given then throw an error. 

**Strongly validate the filename value** 

For example, validate the filename using an allowlist or regular expression.
<br/> 


### Path Traversal in Python
<br/> 


Let's walkthrough an example of Path Traversal in Python and how to fix this.

```
file_contents = ''
filename = request.GET.get('filename', '')

# This type of validation is not strong enough to prevent path traversal
if filename.endswith('.yaml')
    f = open(filename, 'r')
    with open(filename, 'r') as file_handle:
        file_contents = file_handle.read()

return render(request, 'template.html', {'file_contents': file_contents})
``` 


Often, there is no filename validation at all. 
Either way, an attacker could abuse this functionality to view protected configuration files by passing the
following value for the ```filename``` parameter:```http://yoursite.com/app/pathTraversal?statement=../../../../../../config.yaml``` 


To prevent attacks like this, any of the following steps could help: 

**Use maps to filter out invalid values**  
Instead of accepting input like ```file_id=string```, accept
```file_id=int```. That ```int``` can be a key in a Map that points to an allowed file. 
If the map has no corresponding value for the key given, then throw an error.

**Strongly validate the filename value** 

For example, validate the filename using an allowlist or regular expression. 

Some frameworks provide functions for safely accessing the file system. For example, [Flask](https://flask.palletsprojects.com/en/1.1.x/api/#flask.safe_join) provides the function for safely joining user input to a trusted base directory. 

<br/> 


### Path Traversal in Ruby 
<br/>
Let's walkthrough an example of Path Traversal in Ruby and how to fix this. 

```
statement = params['statement']
unless statement.end_with?('.yaml') # Validate (weakly) this file is a yaml file
  logger.Error {'Bad filename sent'}
  return
}

# Read the specified file
path = STATEMENT_DIR + statement
file = File.read(path);
render :text => file
}
```

Often, there is no filename validation at all. 

Either way, an attacker could abuse this functionality to view protected configuration files by passing the following value for the ```filename``` parameter: ```http://yoursite.com/app/pathTraversal?statement=../../../../../../config.yaml``` 


To prevent attacks like this, any of the following steps could help: 

- **Use maps to filter out invalid values** 
Instead of accepting input like ```file_=string```, accept
```file_=int```. That ```int``` can be a key in a map that points to an allowed file. 
If the map has no corresponding value for the key given, then throw an error. 

- **Strongly validate the filename value** 

For example, validate the filename using an allowlist or regular expression: 


```
statement = params['statement']
regexp = /^[A-Za-z0-9]+\.yaml$/

# Validate 'statement' to prevent access to anything but yaml files with no path
if statement =~ regexp
  logger.Error {'Bad filename sent'}
  return
}
# Read the file here as normal
```






