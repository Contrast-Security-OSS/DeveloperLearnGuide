---
layout: page
title: Path Traversal in Python
permalink: /io/Path Traversal/Path Traversal in Python
parent: Path Traversal
nav_order: 6
---

## Path Traversal in Python
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