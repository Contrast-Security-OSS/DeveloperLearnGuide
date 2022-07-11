---
layout: page
title: Arbitrary Server Side Forwards in Java
permalink: /io/Arbitrary Server Side Forwards/Arbitrary Server Side Forwards in Java
parent: Arbitrary Server Side Forwards
nav_order: 3
---



## Arbitrary Server Side Forwards in Java 

For applications running in Java, the application takes input from the user, and uses it to build a file path to which the user is forwarded. 
If a user controls a part of that path, they may be able to direct themselves to sensitive files, like ```/WEB-INF/web.xml```, application code, or configuration files, which may contain passwords. 


There's probably some code in your application that looks like this:

```
String target = request.getParameter("target");
request.getRequestDispatcher(target).forward(request, response);
``` 

If a user passes a querystring like the following, they may get access to important application details:```http://yoursite.com/app/vulnerable.do?target=/WEB-INF/web.xml``` 

This can also lead to server-side code disclosure, too:```http://yoursite.com/app/vulnerable.do?target=/WEB-INF/classes/org/yoursite/app/YourClass.class``` 


Forwarding to internal resources is dangerous. It can be abused to get to files that should never be served, like ```web.xml```.
It can also bypass authentication and access controls enforced by 3rd party systems like SiteMinder 
or WebSEAL. 
If the functionality can't be abstracted away from the ```RequestDispatcher```, the value that is user 
supplied should be thoroughly validated. For instance, if the user is only allowed to access XML files in ```/data/```, your code 
could look like this:

```
Pattern p = Pattern.compile("^/data/[A-Za-z0-9]+\\.xml$");
String target = request.getParameter("target");
if( p.matcher(target).matches() ) {
    request.getRequestDispatcher(target).forward(request, response);
} else {
    response.sendError(404);
}
```
