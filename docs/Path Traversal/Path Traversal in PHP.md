---
layout: page
title: Path Traversal in PHP
permalink: /io/Path Traversal/Path Traversal in PHP
parent: Path Traversal
nav_order: 7
---

## Path Traversal in PHP 


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
Either way, an attacker could abuse this functionality to view protected configuration files by passing the
following value for the ```filename``` parameter:
```http://yoursite.com/app/pathTraversal?statement=../../../../../../config.yaml``` 


To prevent attacks like this, any of the following steps could help: 
**Use maps to filter out invalid values** 
Instead of accepting input like ```$file_id=string```, accept
```$file_id=int```. That ```int``` can be a key in an array that
  points to an allowed file. If the array has no corresponding value for the key given,
  then throw an error.

**Strongly validate the filename value** 

For example, validate the filename using an allowlist or regular expression.
