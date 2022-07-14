---
layout: page
title: Untrusted Deserialization in Java
permalink: /io/Untrusted Deserialization/Untrusted Deserialization in Java
parent: Untrusted Deserialization
nav_order: 4
---

### Untrusted Deserialization in Java  
<br/>

The application deserializes Java objects from an untrusted source. Because the source is untrusted, the application must consider that 
it may not be the expected type. An attacker could submit an object whose type is any Java class on the application's classpath.

Attackers could choose a class with a ```Serializable#readObject()``` method that can be re-purposed towards malicious ends. 
here have been several commonly available classes can be used to effect remote code execution.


### Prevention  
<br/>


If serialization must occur on user data, the ObjectInputStream must be hardened to ensure only the expected classes are being deserialized. 
Here is an example of **vulnerable** code:

```
InputStream untrustedStream = request.getInputStream();
ObjectInputStream in = new ObjectInputStream(untrustedStream);
Acme acmeObject = (Acme)in.readObject();
```

By overriding the ObjectInputStream#resolveClass() method, we can ensure that only the expected classes are deserialized. 

In the following **secure** example, only the Acme and String classes will be allowed to be deserialized. 
Anything else seen will cause a SecurityException to be found:

```
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

The only definite way to protect yourself against side-effects is to allow the types that Kryo is allowed to deserialize. 
This can be done by requiring registration, which is accomplished by adding one line of code: 


```
Kryo kryo = new Kryo();
kryo.setRegistrationRequired(true);
``` 

### XStream 

The only definite way to protect yourself against unwanted side-effects is to [specify](https://x-stream.github.io/security.html) the types 
that XStream is allowed to deserialize. This can be done by modifying the permissions. Here is an example from XStream's own documentation:



```
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

To prevent this issue from being reported again, please make sure the ```NoTypePermission.NONE``` permission is added to your XStream 
instance before it deserializes objects from untrusted sources.


