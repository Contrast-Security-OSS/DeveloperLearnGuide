---
layout: page
title: XXE in Java
permalink: /io/XML External Entity/XXE in Java
parent: XML External Entity
nav_order: 5
---

## XXE in Java 

Sometimes, fixing XXE issues can be tricky. In some cases, the XML parsing is done by a middleware framework, so your code is never
observed in the data flow. 

On top of that, some libraries that use XML interpreters, like `nu.xom`, sit on top of `javax.xml` APIs and don't offer any any protections
against this attack without heavy customization. 

Moreso than other vulnerabilities, resolving the issue may require updating your dependency, patching the parsing code yourself, or running with Contrast Protect to prevent exploitation. 

If you have the ability to patch the vulnerable code, fixing the code is usually done by enabling some security features. 
The most popular XML library API is probably DocumentBuilderFactory. 
Preventing a `DocumentBuilderFactory` from being susceptible to XXE is easy. 


### Example 

Here's an example of using DocumentBuilderFactory: 

- **Unsafe example**

```
    DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
    /* Unsafe! We haven't turned any security features on in the factory! */
    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
    Document doc = docBuilder.parse(untrustedDataSource); // Unsafe!
``` 

- **Safe example**

The next code snippet makes two changes to the configuration of the DocumentBuilderFactory.  
It turns off the resolution of external entities and disallows the document supplying its own DOCTYPE. 

```
    DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
    /* Safe! Don't allow users to control the DOCTYPE or specify external entities! */
    docBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
    Document doc = docBuilder.parse(untrustedDataSource); // Safe!
``` 


### XXE Cheat Sheet 

There are other popular Java libraries that require similar steps to be protected. 

These code snippets are all provided by the [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

- SAXParser 
```
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    SAXParser saxParser = factory.newSAXParser();
    XMLReader xmlReader = saxParser.getXMLReader(); // This XMLReader is safe to use!
``` 

- XOM 
```
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
```
    xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // This disables DTDs entirely for that factory
    xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // disable external entities
``` 

- Unmarshaller / JAXBContext 
```
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

- [XXE Pitfalls with JAXB](https://www.contrastsecurity.com/security-influencers/xml-xxe-pitfalls-with-jaxb)

