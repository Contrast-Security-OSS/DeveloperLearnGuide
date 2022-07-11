---
layout: page
title: Arbitrary Server Side Forwards in Dotnet
permalink: /io/Arbitrary Server Side Forwards/Arbitrary Server Side Forwards in Dotnet
parent: Arbitrary Server Side Forwards
nav_order: 4
---

## Arbitrary Server Side Forwards in Dotnet 


For applications running in **.NET**, the application takes input from the user, and uses it to build a path to another page to which execution is transferred. Users can bypass IIS and ASP.NET's authentication and authorization checks if a user controls a part of that path. 
IIS and ASP.NET do not perform authorization checks for the target page of the Transfer() and Execute() methods. That is, authorization modules (such as ```FileAuthorizationModule``` or ```UrlAuthorizationModule```) that occur earlier in the ASP.NET pipeline are executed for the initial page but the ```Transfer()``` and ```Execute()``` methods pass execution to a new handler without re-executing steps earlier in the pipeline. 



For example, consider the following code: 

```
String target = Request.QueryString("target");
Server.Transfer(target);
``` 

If a user passed a querystring like the following, they may get access to sensitive parts of the application: ```http://yoursite.com/app/vulnerable.aspx?target=/admin/admin.aspx``` 

Transferring to internal resources is dangerous 
It can also bypass authentication and access controls as ```Transfer()``` and ```Execute()``` do not trigger ASP.NET's authentication and authorization checks on the destination page. There are three primary ways to resolve this issue: 

- The functionality/application logic should be abstracted away from the use of ```Transfer()``` and ```Execute()```. 
- IIS and ASP.NET authorization can be triggered by using ```Response.Redirect``` rather than the ```Transfer()``` or ```Execute()``` methods. 
Ideally the target of Response.Redirect should not include user data (in order to avoid unvalidated redirect vulnerabilities) or if they must include user data, then this data should be thoroughly validated. 
- If the application functionality must use ```Transfer()``` or ```Execute()```, the user-supplied value should be thoroughly validated. 
For instance, if the user is only allowed to access aspx files in ```/data/```, your code could look like this:

```
// C#:
Regex p = new Regex("^/data/[A-Za-z0-9]+\\.aspx$");
String target = Request.QueryString("target");
if ( p.IsMatch(target) ) {
Server.Transfer(target);
} else {
// process error
}

' VB.NET:
Dim p As New Regex("^/data/[A-Za-z0-9]+\\.aspx$")
Dim target As String = Request.QueryString("target")
If ( p.IsMatch(target)) Then
Server.Transfer(target)
Else
' process error
End
```