---
layout: default
title: Unsafe XML Decoding
nav_order: 15
---

# Unsafe XML Decoding
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Overview 
<br/> 

Using unsafe decoders such as [XMLDecoder](https://docs.oracle.com/javase/7/docs/api/index.html?java/beans/XMLDecoder.html) to deserialize data that comes from an untrusted source, such as an HTTP request, is a dangerous practice. 

Deserializing untrusted user input can lead to arbitrary code execution.


The [JavaBeans](http://docs.oracle.com/javase/7/docs/api/index.html?java/beans/XMLEncoder.html) classes provide developers with an easy way to serialize Java objects. Objects can easily be read back and forth, as is shown in the example from the JavaDocs: 

```java
// Writing an Object
XMLEncoder e = new XMLEncoder(new BufferedOutputStream(new FileOutputStream("Test.xml")));
e.writeObject(new JButton("Hello, world"));
e.close();

// Reading an Object
XMLDecoder d = new XMLDecoder(new BufferedInputStream(new FileInputStream("Test.xml")));
JButton button = (JButton)d.readObject();
d.close();
```

## How To Fix 
<br/> 

Unfortunately, there is no way to safely deserialize XML that comes from untrusted sources. The XML literally contains the "code" used to restore the state of the Object. This can be maliciously altered to execute arbitrary code. The following [code](https://stackoverflow.com/questions/14307442/is-it-safe-to-use-xmldecoder-to-read-document-files), shows an example malicious XML that can be used to write a file to the filesystem upon deserialization:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<java version="1.4.0" class="java.beans.XMLDecoder">
  <object class="java.io.PrintWriter">
    <string>/tmp/Hacked.txt</string>
    <void method="println">
      <string>You have been hacked!</string>
    </void>
    <void method="close"/>
  </object>
</java>
``` 

We primarily recommend **not using XMLDecoder with untrusted input** or **moving to a different serialization format**.
	
It _may_ be possible to subclass XMLDecoder and develop a safe alternative, or sandbox the application to prevent obvious exploits. 

## How can Contrast help? 
<br/> 

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect SQLi vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning your code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
- [Contrast Serverless](https://www.contrastsecurity.com/contrast-serverless) can determine if you are vulnerable within your Cloud Native environment.

