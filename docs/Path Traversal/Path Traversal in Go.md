---
layout: page
title: Path Traversal in Go
permalink: /io/Path Traversal/Path Traversal in Go
parent: Path Traversal
nav_order: 7
---

## Path Traversal in Go 


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

- **Use maps to filter out invalid values** 

Instead of accepting input like ```file_id=string```, accept
``file_id=int```. That ```int``` can be a key in a map that points to an allowed file. 
If the map has no corresponding value for the key given, then throw an error.

- **Strongly validate the filename value** 

For example, validate the filename using an allowlist or regular expression.
