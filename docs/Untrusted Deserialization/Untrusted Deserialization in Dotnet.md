---
layout: page
title: Untrusted Deserialization in Dotnet
permalink: /io/Untrusted Deserialization/Untrusted Deserialization in Dotnet
parent: Untrusted Deserialization
nav_order: 5
---

# Untrusted Deserialization in Dotnet  

As the object being deserialized is originating from an untrusted source, the application must consider that the constructed object may not 
be the expected type and that some objects may have dangerous side-effects when constructed. An attacker could force the deserializer 
to construct an object that can be repurposed towards malicious ends - for example, to execute arbitrary commands.

The only requirement would be that the attacker-supplied type be loadable by the runtime. Several commonly available, framework types, 
have been discovered that can be used to affect remote code execution, so it is safe to assume that most applications will have at 
least one type that can be used as an attack vector.


### BinaryFormatter 

The [BinaryFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter) type is vulnerable to untrusted data by default. We recommend not deserializing user data using the BinaryFormatter when possible. If BinaryFormatter deserialization is required, then a custom [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder) must be implemented to verify all types that BinaryFormatter attempts to materialize. See [BinaryFormatter.Binder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter.binder) and [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder), for implementation details.

```
new BinaryFormatter()
{
  Binder = new CustomBinder()
}
```

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data) or Microsoft's [BinaryFormatter Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2300-do-not-use-insecure-deserializer-binaryformatter)



### SoapFormatter 

The [SoapFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter) type is vulnerable to untrusted data by default. The SoapFormatter API was marked as obsolete as of .NET Framework 2.0, Microsoft recommends using the [BinaryFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter).

We recommend not deserializing user data using the SoapFormatter when possible. If SoapFormatter deserialization is required, then a custom [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder) must be implemented to verify all types that SoapFormatter attempts to materialize. See [SoapFormatter.Binder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter.binder) and [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder), for implementation details.

```
new SoapFormatter()
{
  Binder = new CustomBinder()
}
```

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data).

### ObjectStateFormatter 

The [ObjectStateFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.objectstateformatter) type is vulnerable to untrusted data when message authentication code (MAC) verification has been not been enabled. This is default when the ObjectStateFormatter is constructed using the parameterless constructor. The ObjectStateFormatter is also used internally by ASP.Net components, and is by default safe, unless MAC verification is disabled.

If either .NET Framework 4.5.2 (or greater) or the out-of-band Windows Server update KB2905247 is installed, MAC verification is enforced in ASP.Net Framework components. For more information, refer to [Microsoft Security Advisory 2905247](https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2013/2905247).

If this rule was triggered outside of ASP.Net Framework code, we recommend refactoring the code to not use the ObjectStateFormatter. The ObjectStateFormatter cannot be used safely in user code.

If this rule was triggered within ASP.Net Framework code, ensure MAC verification is enabled. This can be done in one of three ways:
- Install the .NET Framework 4.5.2 (or greater) update.
- Install KB2905247.
- Remove code that disables MAC verification. Consider looking for the following:

```
// In ASPX pages.
<%@ Page EnableViewStateMac="false" %>
// In the web.config/applicationHost.config
<pages enableViewStateMac=”false” />
// In ASPX code-behind.
System.Web.UI.Page.EnableViewStateMac = false;
```

For additional security considerations see Microsoft's [Insecure ObjectStateFormatter Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2300-do-not-use-insecure-deserializer-binaryformatter).

### LosFormatter 

The [LosFormatter](https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter) type is vulnerable to untrusted data when message authentication code (MAC) verification has been not been enabled. This is the default when the LosFormatter type is constructed using the parameterless constructor.

We recommend not deserializing user data using the LosFormatter when possible. If LosFormatter deserialization is required, then MAC verification must be enabled. This can be done in one of two ways:

```
byte[] macKeyModifier = // MAC Key Modifier
new LosFormatter(true, macKeyModifier); // Safe

// or

string macKeyModifier = // MAC Key Modifier
new LosFormatter(true, macKeyModifier); // Safe
```

For additional security considerations see Microsoft's [Insecure LosFormatter Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2305-do-not-use-insecure-deserializer-losformatter). 


### JavaScriptSerializer

The [JavaScriptSerializer](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascriptserializer) type is vulnerable to untrusted data when the [SimpleTypeResolver](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.simpletyperesolver) type is used to resolve types during deserialization.

```
new JavaScriptSerializer(new SimpleTypeResolver()); // Unsafe
```

We recommend not deserializing user data using the JavaScriptSerializer when type information is provided within the JSON payload. If this behavior is required, then a custom [JavaScriptTypeResolver](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascripttyperesolver) must be implemented to validate types sent within the JSON payload. See [JavaScriptTypeResolver](https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascripttyperesolver), for implementation details.

```
new JavaScriptSerializer(new CustomTypeResolver()); // Safe
```

For additional security considerations see Microsoft's [Insecure JavaScriptSerializer Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2321).

### NetDataContractSerializer 


The [NetDataContractSerializer](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer) type is vulnerable to untrusted data by default. We recommend not deserializing user data using the NetDataContractSerializer when possible. If NetDataContractSerializer deserialization is required, then a custom [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder) must be implemented to verify all types that NetDataContractSerializer attempts to materialize. See [NetDataContractSerializer.Binder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer.binder) and [SerializationBinder](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder), for implementation details.

```
new NetDataContractSerializer()
{
  Binder = new CustomBinder()
}
```

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data#datacontractserializer) or Microsoft's [Insecure NetDataContractSerializer Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2310-do-not-use-insecure-deserializer-netdatacontractserializer).

### DataContractSerializer 

The [DataContractSerializer](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.datacontractserializer) type is vulnerable to untrusted data when type information can be supplied with user data. For example:

```
string type = HttpContext.Current.Request.QueryString["type"];
Stream xml = HttpContext.Current.Request.InputStream;

DataContractSerializer serializer = new # DataContractSerializer(Type.GetType(type));
serializer.ReadObject(xml); // Vulnerable 
```

We recommend not deserializing user data using the DataContractSerializer when the type information is derived directly from user data. If this is required, then the type from user data must be validated before usage.

For additional security considerations see [WCF Data Security Considerations](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data#datacontractserializer) or Microsoft's [Insecure DataContractSerializer Code Quality Rule](https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2310-do-not-use-insecure-deserializer-netdatacontractserializer). 



### JsonSerializer (Json.NET) 


The Newtonsoft [JsonSerializer](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_JsonSerializer.htm) type is vulnerable to untrusted data when type name handling is enabled - i.e the [TypeNameHandling enum](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm) is specified with any value other than `TypeNameHandling.None`. By default, `TypeNameHandling.None` is used.

```
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

```
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

```
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