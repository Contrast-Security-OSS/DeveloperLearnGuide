---
layout: page
title: XXE in Dotnet
permalink: /io/XML External Entity/XXE in Dotnet
parent: XML External Entity
nav_order: 4
---

## XXE in Dotnet 
<br/>
Preventing a `XmlReader` from being susceptible to XXE is easy. 
In some cases, this interpretation is done by a middleware framework and resolving the issue may require updating your dependency or patching the parsing code yourself. 

### Example 
<br/>
Here's an example of using `XmlReader`

- **Unsafe example** 

```
XmlReader reader = XmlReader.Create(untrustedDataSource);    // Unsafe!
/* Unsafe! We haven't turned any security features on in the factory! */
``` 


- **Safe example**

The next code snippet makes two changes to the configuration of the `XmlReader`. 
It turns off the resolution of external entities and disallows the document supplying its own DOCTYPE. 

```
XmlReaderSettings settings = new XmlReaderSettings();
/* Safe! Don't allow users to control the DOCTYPE or specify external entities! */
#if ($language == ".NET")
settings.DtdProcessing = DtdProcessing.Ignore; // New attribute in .NET 4.0
settings.ProhibitDtd = true; // Obsolete starting in .NET 4.0. Use this instead if on .NET 3.5 or earlier
#elseif($language == ".NET Core")
settings.DtdProcessing = DtdProcessing.Ignore;
#end
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(untrustedDataSource, settings);
```
