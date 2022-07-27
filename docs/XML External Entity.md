---
layout: default
title: XML External Entity
nav_order: 2
---

# XML External Entity
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


### Overview 
<br/>
An XML External Entity (XXE) attack can occur when an application parses an XML document from an untrusted source, with a parser that doesn't disable resolution of external entities. 

Attackers can supply malicious XML to this interface, and trick the XML interpreter into leaking sensitive server side data back to the attacker.


### Scenario 
<br/>
Let's look at an example attack. The following is a malicious document that an attacker would send. 
Notice the malicious ENTITY defined in the DOCTYPE:  

```xml
<?xml version="1.0"?>
<!DOCTYPE root
[
<!ENTITY attack SYSTEM "file:///etc/passwd">
]>
<status>&attack;</status>
``` 

To the XML interpreter, the "attack" entity is defined as the contents of the /etc/passwd file. 
Since the XML interpreter hasn't been instructed to ignore external entities, it will perform this resolution and replace the `&attack;` entity with that file. 

In our example scenario, when the attacker views the status code in the resulting web page, they see something like the following: 

```xml
    Thanks for your upload! The status of the document is:
    <!-- Print out the status code from the XML document -->
    root:*:0:0:System Administrator:/var/root:/bin/sh
    daemon:*:1:1:System Services:/var/root:/usr/bin/false
```

To fully exploit this vulnerability, an attacker must be able to supply the malicious XML to the XML interpreter and see any of the data after it has entered the application. 
<br/>
In the majority of cases, attackers who meet the first condition almost always also meet the second.


### Impact
<br/>
A successful exploit can result in local files containing sensitive data, such as passwords, being disclosed.
Additionally, it is also common to use this vulnerability to perform a Denial of Service (DoS) attack. 
Attackers can also utilize this flaw to laterally traverse to other internal systems, leading to a potential SSRF attack.


## XXE in .NET 
<br/>
Preventing a `XmlReader` from being susceptible to XXE is easy. 
In some cases, this interpretation is done by a middleware framework and resolving the issue may require updating your dependency or patching the parsing code yourself. 

### Example 
<br/>
Here's an example of using `XmlReader`

- **Unsafe example** 

```csharp
XmlReader reader = XmlReader.Create(untrustedDataSource);    // Unsafe!
/* Unsafe! We haven't turned any security features on in the factory! */
``` 


- **Safe example**

The next code snippet makes two changes to the configuration of the `XmlReader`. 
It turns off the resolution of external entities and disallows the document supplying its own DOCTYPE. 

```csharp
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

## XXE in Java 
<br/>
Sometimes, fixing XXE issues can be tricky. In some cases, the XML parsing is done by a middleware framework, so your code is never
observed in the data flow. 

On top of that, some libraries that use XML interpreters, like `nu.xom`, sit on top of `javax.xml` APIs and don't offer any any protections
against this attack without heavy customization. 

Moreso than other vulnerabilities, resolving the issue may require updating your dependency, patching the parsing code yourself, or running with Contrast Protect to prevent exploitation. 

If you have the ability to patch the vulnerable code, fixing the code is usually done by enabling some security features. 
The most popular XML library API is probably DocumentBuilderFactory. 
Preventing a `DocumentBuilderFactory` from being susceptible to XXE is easy. 


### Example 
<br/>
Here's an example of using DocumentBuilderFactory: 

- **Unsafe example**

```java
    DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
    /* Unsafe! We haven't turned any security features on in the factory! */
    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
    Document doc = docBuilder.parse(untrustedDataSource); // Unsafe!
``` 

- **Safe example**

The next code snippet makes two changes to the configuration of the DocumentBuilderFactory.  
It turns off the resolution of external entities and disallows the document supplying its own DOCTYPE. 

```java
    DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
    /* Safe! Don't allow users to control the DOCTYPE or specify external entities! */
    docBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
    Document doc = docBuilder.parse(untrustedDataSource); // Safe!
``` 


### Cheat Sheet 
<br/>
There are other popular Java libraries that require similar steps to be protected. 

These code snippets are all provided by the [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

- SAXParser 

```java
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    SAXParser saxParser = factory.newSAXParser();
    XMLReader xmlReader = saxParser.getXMLReader(); // This XMLReader is safe to use!
``` 

- XOM 

```java
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    SAXParser saxParser = factory.newSAXParser();
    XMLReader xmlReader = saxParser.getXMLReader(); // now we have a safe xmlReader to use

    Builder parser = new Builder(xmlReader); // build a nu.xom.Builder instance that uses the safe reader
    Document document = parser.build(targetFile);
``` 

- XMLInputFactory 

```java
    xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // This disables DTDs entirely for that factory
    xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // disable external entities
``` 

- Unmarshaller / JAXBContext 

```java
    SAXParserFactory spf = SAXParserFactory.newInstance();
    spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

    Source xmlSource = new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(new StringReader(xml)));
    JAXBContext jc = JAXBContext.newInstance(Object.class);
    Unmarshaller unmarshaller = jc.createUnmarshaller();
    unmarshaller.unmarshal(xmlSource);
``` 

### Further Reading
<br/>

- [XXE Pitfalls with JAXB](https://www.contrastsecurity.com/security-influencers/xml-xxe-pitfalls-with-jaxb)


