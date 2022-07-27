---
layout: default
title: Untrusted Deserialization
nav_order: 4
---

# Untrusted Deserialization
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview
<br/>
Insecure deserialization, represents an application vulnerability in which all serialized data structures are treated the same—that is, by default, data received from an unvalidated source is treated the same as data received from a validated one. 

To illustrate, an application attack can assail a web application by loading malicious code into a serialized object and pass it to the application.  
If the web application deserializes user-controlled input in the absence of any validation check, the malicious code is enabled to access more surface area of the application. 

Subsequently, this sets the table for the initiation of secondary application attacks that could potentially lead to sensitive data exposure.


## Impact
<br/>
If exploited, data deserialized insecurely can serve as an embarkation point for a cascading series of cyberattacks, including denial of service (DoS), authentication bypass, remote code execution attacks, and SQL injection.


## Prevention
<br/>
There are only a few options for securing the deserialization of untrusted objects. The first, and most safe option, is to remove 
the deserializing of user input completely. Although the recommendations today appear to be totally effective, it's worth noting 
that attacks against serialization have been getting more effective for many years. 

The consensus amongst security researchers is that developers should be moving away from object serialization when possible.

## Untrusted Deserialization in .NET  
<br/>
As the object being deserialized is originating from an untrusted source, the application must consider that the constructed object may not 
be the expected type and that some objects may have dangerous side-effects when constructed. An attacker could force the deserializer 
to construct an object that can be repurposed towards malicious ends - for example, to execute arbitrary commands.

The only requirement would be that the attacker-supplied type be loadable by the runtime. Several commonly available, framework types, 
have been discovered that can be used to affect remote code execution, so it is safe to assume that most applications will have at 
least one type that can be used as an attack vector.


### BinaryFormatter 
<br/>
The [BinaryFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter) type is vulnerable to untrusted data by default. We recommend not deserializing user data using the BinaryFormatter when possible. If BinaryFormatter deserialization is required, then a custom [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder) must be implemented to verify all types that BinaryFormatter attempts to materialize. See [BinaryFormatter.Binder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter.binder) and [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder), for implementation details.

```csharp
new BinaryFormatter()
{
  Binder = new CustomBinder()
}
```

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data) or Microsoft's [BinaryFormatter Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2300-do-not-use-insecure-deserializer-binaryformatter)



### SoapFormatter 
<br/>
The [SoapFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter) type is vulnerable to untrusted data by default. The SoapFormatter API was marked as obsolete as of .NET Framework 2.0, Microsoft recommends using the [BinaryFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter).

We recommend not deserializing user data using the SoapFormatter when possible. If SoapFormatter deserialization is required, then a custom [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder) must be implemented to verify all types that SoapFormatter attempts to materialize. See [SoapFormatter.Binder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter.binder) and [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder), for implementation details.

```csharp
new SoapFormatter()
{
  Binder = new CustomBinder()
}
```

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data).

### ObjectStateFormatter 
<br/>
The [ObjectStateFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.objectstateformatter) type is vulnerable to untrusted data when message authentication code (MAC) verification has been not been enabled. This is default when the ObjectStateFormatter is constructed using the parameterless constructor. The ObjectStateFormatter is also used internally by ASP.Net components, and is by default safe, unless MAC verification is disabled.

If either .NET Framework 4.5.2 (or greater) or the out-of-band Windows Server update KB2905247 is installed, MAC verification is enforced in ASP.Net Framework components. For more information, refer to [Microsoft Security Advisory 2905247](https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2013/2905247).

If this rule was triggered outside of ASP.Net Framework code, we recommend refactoring the code to not use the ObjectStateFormatter. The ObjectStateFormatter cannot be used safely in user code.

If this rule was triggered within ASP.Net Framework code, ensure MAC verification is enabled. This can be done in one of three ways:
- Install the .NET Framework 4.5.2 (or greater) update.
- Install KB2905247.
- Remove code that disables MAC verification. Consider looking for the following:

```csharp
// In ASPX pages.
<%@ Page EnableViewStateMac="false" %>
// In the web.config/applicationHost.config
<pages enableViewStateMac=”false” />
// In ASPX code-behind.
System.Web.UI.Page.EnableViewStateMac = false;
```

For additional security considerations see Microsoft's [Insecure ObjectStateFormatter Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2300-do-not-use-insecure-deserializer-binaryformatter).

### LosFormatter 
<br/>
The [LosFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter) type is vulnerable to untrusted data when message authentication code (MAC) verification has been not been enabled. This is the default when the LosFormatter type is constructed using the parameterless constructor.

We recommend not deserializing user data using the LosFormatter when possible. If LosFormatter deserialization is required, then MAC verification must be enabled. This can be done in one of two ways:

```csharp
byte[] macKeyModifier = // MAC Key Modifier
new LosFormatter(true, macKeyModifier); // Safe

// or

string macKeyModifier = // MAC Key Modifier
new LosFormatter(true, macKeyModifier); // Safe
```

For additional security considerations see Microsoft's [Insecure LosFormatter Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2305-do-not-use-insecure-deserializer-losformatter). 


### JavaScriptSerializer
<br/>
The [JavaScriptSerializer](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascriptserializer) type is vulnerable to untrusted data when the [SimpleTypeResolver](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.simpletyperesolver) type is used to resolve types during deserialization.

```csharp
new JavaScriptSerializer(new SimpleTypeResolver()); // Unsafe
```

We recommend not deserializing user data using the JavaScriptSerializer when type information is provided within the JSON payload. If this behavior is required, then a custom [JavaScriptTypeResolver](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascripttyperesolver) must be implemented to validate types sent within the JSON payload. See [JavaScriptTypeResolver](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascripttyperesolver), for implementation details.

```csharp
new JavaScriptSerializer(new CustomTypeResolver()); // Safe
```

For additional security considerations see Microsoft's [Insecure JavaScriptSerializer Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2321).

### NetDataContractSerializer 
<br/>
The [NetDataContractSerializer](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer) type is vulnerable to untrusted data by default. We recommend not deserializing user data using the NetDataContractSerializer when possible. If NetDataContractSerializer deserialization is required, then a custom [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder) must be implemented to verify all types that NetDataContractSerializer attempts to materialize. See [NetDataContractSerializer.Binder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer.binder) and [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder), for implementation details.

```csharp
new NetDataContractSerializer()
{
  Binder = new CustomBinder()
}
```

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data#datacontractserializer) or Microsoft's [Insecure NetDataContractSerializer Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2310-do-not-use-insecure-deserializer-netdatacontractserializer).

### DataContractSerializer 
<br/>
The [DataContractSerializer](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.datacontractserializer) type is vulnerable to untrusted data when type information can be supplied with user data. For example:

```csharp
string type = HttpContext.Current.Request.QueryString["type"];
Stream xml = HttpContext.Current.Request.InputStream;

DataContractSerializer serializer = new # DataContractSerializer(Type.GetType(type));
serializer.ReadObject(xml); // Vulnerable 
```

We recommend not deserializing user data using the DataContractSerializer when the type information is derived directly from user data. If this is required, then the type from user data must be validated before usage.

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data#datacontractserializer) or Microsoft's [Insecure DataContractSerializer Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2310-do-not-use-insecure-deserializer-netdatacontractserializer). 



### JsonSerializer (Json.NET) 
<br/>
The Newtonsoft [JsonSerializer](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_JsonSerializer.htm) type is vulnerable to untrusted data when type name handling is enabled - i.e the [TypeNameHandling enum](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm) is specified with any value other than `TypeNameHandling.None`. By default, `TypeNameHandling.None` is used.

```csharp
new JsonSerializer
{
  TypeNameHandling = TypeNameHandling.All
}; // Unsafe
```
The value `TypeNameHandling.All` is used for the remainder of this text as an example, but other vulnerable values are as follows:

- `TypeNameHandling.Objects`
- `TypeNameHandling.Arrays`
- `TypeNameHandling.Auto`

We recommend not deserializing user data using the JsonSerializer when type information is provided within the JSON payload. If this rule was triggered, but this behavior is not required, then ensure that type name handling is not enabled. Consider looking for the following common methods in overriding type name handling:

```csharp
// JsonPropertyAttributes
[Newtonsoft.Json.JsonPropertyAttribute(ItemTypeNameHandling = TypeNameHandling.All)]
[Newtonsoft.Json.JsonPropertyAttribute(TypeNameHandling = TypeNameHandling.All)]

// JsonContainerAttributes
[Newtonsoft.Json.JsonArrayAttribute(ItemTypeNameHandling = TypeNameHandling.All)]
[Newtonsoft.Json.JsonDictionaryAttribute(ItemTypeNameHandling = TypeNameHandling.All)]
[Newtonsoft.Json.JsonObjectAttribute(ItemTypeNameHandling = TypeNameHandling.All)]

// JsonSerializerSettings Instances
new Newtonsoft.Json.JsonSerializerSettings
{
  TypeNameHandling = TypeNameHandling.All
}

// JsonSerializer Instances
new JsonSerializer
{
  TypeNameHandling = TypeNameHandling.All
};
```

If dynamic deserialization of user provided types is required, then a custom [ISerializationBinder](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_SerializationBinder.htm) must be implemented to validate types sent within the JSON payload. See [Custom SerializationBinder](https://www.newtonsoft.com/json/help/html/SerializeSerializationBinder.htm), for implementation details.

```csharp
KnownTypesBinder knownTypesBinder = new KnownTypesBinder
{
    KnownTypes = new List<Type> { typeof(Car) }
};

new JsonSerializer
{
  TypeNameHandling = TypeNameHandling.All,
  SerializationBinder = knownTypesBinder
}; // Safe
```

In older versions of Newtonsoft.Json, the [Binder property](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_Binder.htm) can be substituted for [SerializationBinder](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_SerializationBinder.htm), and the [SerializationBinder](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_Binder.htm) type for [ISerializationBinder](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_SerializationBinder.htm). 

## Untrusted Deserialization in Java  
<br/>
The application deserializes Java objects from an untrusted source. Because the source is untrusted, the application must consider that 
it may not be the expected type. An attacker could submit an object whose type is any Java class on the application's classpath.

Attackers could choose a class with a ```Serializable#readObject()``` method that can be re-purposed towards malicious ends. 
here have been several commonly available classes can be used to effect remote code execution.


### Prevention  
<br/>
If serialization must occur on user data, the ObjectInputStream must be hardened to ensure only the expected classes are being deserialized. 
Here is an example of **vulnerable** code:

```java
InputStream untrustedStream = request.getInputStream();
ObjectInputStream in = new ObjectInputStream(untrustedStream);
Acme acmeObject = (Acme)in.readObject();
```

By overriding the `ObjectInputStream#resolveClass()` method, we can ensure that only the expected classes are deserialized. 

In the following **secure** example, only the Acme and String classes will be allowed to be deserialized. 
Anything else seen will cause a SecurityException to be found:

```java
InputStream untrustedStream = request.getInputStream();
List safeClasses = Arrays.asList(new Class[] { Acme.class, String.class });
ObjectInputStream in = new ObjectInputStream(untrustedStream) {
    protected Class resolveClass(ObjectStreamClass desc) {
        Class clazz = null;
        try {
            clazz = super.resolveClass(desc);
            if (clazz.isArray() || clazz.isPrimitive() || safeClasses.contains(clazz) ) {
                return clazz;
            }
        } catch (ClassNotFoundException | IOException e) {
            throw new SecurityException("Attempt to deserialize unauthorized class: " + clazz.getName());
        }
    }
};

Acme acmeObject = (Acme)in.readObject();
``` 
 

### Kyro  
<br/>

The only definite way to protect yourself against side-effects is to allow the types that Kryo is allowed to deserialize. 
This can be done by requiring registration, which is accomplished by adding one line of code: 

```java
Kryo kryo = new Kryo();
kryo.setRegistrationRequired(true);
``` 

### XStream 
<br/>
The only definite way to protect yourself against unwanted side-effects is to [specify](https://x-stream.github.io/security.html) the types 
that XStream is allowed to deserialize. This can be done by modifying the permissions. Here is an example from XStream's own documentation:

```java
// clear out existing permissions and set own ones
xstream.addPermission(NoTypePermission.NONE);
// allow some basics
xstream.addPermission(NullPermission.NULL);
xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
xstream.allowTypeHierarchy(Collection.class);
// allow any type from the same package
xstream.allowTypesByWildcard(new String[] {
Blog.class.getPackage().getName()+".*"
});
```

To prevent this issue from being reported again, please make sure the `NoTypePermission.NONE` permission is added to your XStream 
instance before it deserializes objects from untrusted sources.



