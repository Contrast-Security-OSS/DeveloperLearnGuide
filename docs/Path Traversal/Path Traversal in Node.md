---
layout: page
title: Path Traversal in Node
permalink: /io/Path Traversal/Path Traversal in Node
parent: Path Traversal
nav_order: 6
---

## Path Traversal in Node 



The following [module](https://nodejs.org/api/path.html) contains tools to help reduce the risk of an attacker accessing 
files they should not have access to.  

For example, if user input is needed to determine the location of a file, it could be done as follows:

```
var path = require('path');
var rootDir = '/foo/bar/';
var fileName = path.join(rootDir, fileNameFromUserInput);
```

**Note** the slash at the end of the root directory name. 

This is to prevent an attacker from changing the name of the bar directory.  
```path.resolve``` handles things like slash direction for operating systems and removal of ```..``` 

Note, however, that if user input contained ``..`` the user may still have been able to manipulate ``path.join`` into return a directory with a root that is different from what was supplied. 
Always be sure to check for this.


