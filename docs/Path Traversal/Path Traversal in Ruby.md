---
layout: page
title: Path Traversal in Ruby
permalink: /io/Path Traversal/Path Traversal in Ruby
parent: Path Traversal
nav_order: 5
---

## Path Traversal in Ruby 
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

