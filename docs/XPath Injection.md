---
layout: default
title: XPath Injection
nav_order: 10

---

# XPath Injection
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## XPath Injection

### Overview 
<br/>

When an XPath query is built dynamically with data from the user without validation or encoding, attackers can change the behavior of the query to retrieve other, possibly sensitive, information. 

The solution to this problem is to validate or encode the untrusted user data so that it can't change the underlying structure of the XPath query.

### Java  
<br/>

Here's an example of an `unsafe` query adapted from the OWASP WebGoat Project: 

```java
String username = request.getParameter("user");
String password = request.getParameter("pass");
String expression = "/employees/employee[loginID/text()='" + username + "' and passwd/text()='" + password + "']"; // Unsafe!
NodeList matchingEmployees = (NodeList) xPath.evaluate(expression, inputSource, XPathConstants.NODESET);
``` 


Here's an example of `safely` parameterizing an XPath query, which was adapted from the following [question](https://stackoverflow.com/questions/6749448/is-it-possible-parameterize-a-compiled-java-xpath-expression-ala-preparedstatement):

```java
// XPathParameterizingResolver.java
public class XPathParameterizingResolver implements XPathVariableResolver {

    Map<QName, Object> vars = new HashMap<QName, Object>();

    public void addVariable(QName name, Object value) {
        vars.put(name, value);
    }

    public Object resolveVariable(QName name) {
        return vars.get(name);
    }
}

// YourClass.java
String username = request.getParameter("user");
String password = request.getParameter("pass");

XPath xPath = XPathFactory.newInstance().newXPath();
XPathParameterizingResolver resolver = new XPathParameterizingResolver();
resolver.addVariable(new QName(null, "loginID"), username);
resolver.addVariable(new QName(null, "passwd"), password);
xPath.setXPathVariableResolver(resolver);
XPathExpression expr = xPath.compile("/employees/employee[@loginID=$username and @passwd=$password]");
NodeList matchingEmployees = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
``` 

The [library](https://owasp.org/www-project-enterprise-security-api/) offers a [function](https://github.com/esapi/esapi-java-legacy) to remove the need for parameter binding. This function allows some characters (like commas, periods, and others) and HTML encodes all other known entities. This might offer a lower-touch solution for addressing injection concerns.

### .NET 
<br/>

Here's an example of an `unsafe` query adapted from the OWASP WebGoat Project: 

```csharp
String username = Request.QueryString("username");
String password = Request.QueryString("password");

String expression = "/employees/employee[loginID/text()='"
    + username + "' and passwd/text()='"
    + password + "']";    // Unsafe!

// XmlDocument root = ...
XmlNodeList matchingEmployees = root.SelectNodes(expression);
```  

We recommend the use of a parameterized XPath interface, if one is available, or an encoding function to make dangerous characters safe. 
The .NET XPath library provides a parameterized interface when using the XPathNavigator and XPathExpression types. 
Note that this example requires an implementation of the abstract class XsltContext and interface IXsltContextVariable. These are named `CustomContext` and `XPathExtensionVariable` in the following examples, respectively. Documentation on how to properly implement these types can be found [here](https://docs.microsoft.com/en-us/dotnet/standard/data/xml/user-defined-functions-and-variables) 


```csharp
String username = Request.QueryString("username");
String password = Request.QueryString("password");

string expression = $"/employees/employee[loginID/text()=$username "
                  + $"and passwd/text()=$password']";
XPathExpression xpath = XPathExpression.Compile(expression);

XsltArgumentList argumentList = new XsltArgumentList();
argumentList.AddParam("username", string.Empty, username);
argumentList.AddParam("password", string.Empty, password);

CustomContext context = new CustomContext(argumentList);
xpath.SetContext(context);

// XmlDocument root = ...
XPathNavigator navigator = root.CreateNavigator();
XPathNodeIterator matchingEmployees = navigator.Select(xpath);
``` 


### .NET Core 
<br/>

Here's an example of an `unsafe` query adapted from the OWASP WebGoat Project: 

```csharp
// [FromQuery] string username
// [FromQuery] string password

String expression = "/employees/employee[loginID/text()='"
    + username + "' and passwd/text()='"
    + password + "']";    // Unsafe!

// XmlDocument root = ...
XmlNodeList matchingEmployees = root.SelectNodes(expression);
``` 

We recommend the use of a parameterized XPath interface, if one is available, or an encoding function to make dangerous characters safe. 
The .NET XPath library provides a parameterized interface when using the XPathNavigator and XPathExpression types. 
Note that this example requires an implementation of the abstract class XsltContext and interface IXsltContextVariable. These are named `CustomContext` and `XPathExtensionVariable` in the following examples, respectively. Documentation on how to properly implement these types can be found [here](https://docs.microsoft.com/en-us/dotnet/standard/data/xml/user-defined-functions-and-variables). 


```csharp
// [FromQuery] string username
// [FromQuery] string password

string expression = $"/employees/employee[loginID/text()=$username "
                  + $"and passwd/text()=$password']";
XPathExpression xpath = XPathExpression.Compile(expression);

XsltArgumentList argumentList = new XsltArgumentList();
argumentList.AddParam("username", string.Empty, username);
argumentList.AddParam("password", string.Empty, password);

CustomContext context = new CustomContext(argumentList);
xpath.SetContext(context);

// XmlDocument root = ...
XPathNavigator navigator = root.CreateNavigator();
XPathNodeIterator matchingEmployees = navigator.Select(xpath);
``` 

This method of performing the XPath query will be sufficient in most cases. Considerations should be made to correctly implement `CustomContext` and `XPathExtensionVariable` as these types can override default behaviors. The following is a basic example of these types: 


```csharp
public class CustomContext : XsltContext
{
    public override bool Whitespace => true;
    public XsltArgumentList ArgumentList { get; private set; }

    public CustomContext(XsltArgumentList argumentList) : base(new NameTable())
    {
        ArgumentList = argumentList;
    }

    public override int CompareDocument(string baseUri, string nextbaseUri) => 0;
    public override bool PreserveWhitespace(XPathNavigator node) => false;
    public override IXsltContextFunction ResolveFunction(string prefix, string name, XPathResultType[] ArgTypes) => null;

    public override IXsltContextVariable ResolveVariable(string prefix, string name)
    {
        return new XPathExtensionVariable(prefix, name);
    }
}

// and 

public class XPathExtensionVariable : IXsltContextVariable
{
    private string _prefix;
    private string _varName;

    public bool IsLocal => false;
    public bool IsParam => false;
    public XPathResultType VariableType => XPathResultType.Any;

    public XPathExtensionVariable(string prefix, string varName)
    {
        this._prefix = prefix;
        this._varName = varName;
    }

    public object Evaluate(XsltContext xsltContext)
    {
        XsltArgumentList vars = ((CustomContext)xsltContext).ArgumentList;
        return vars.GetParam(_varName, _prefix);
    }
}
``` 
 
### Ruby 
<br/>

Here's an example of an `unsafe` query adapted from the OWASP WebGoat Project: 

```ruby
username = params['username']
password = params['password']
find_user_xpath = "//Customer[UserName/text()='" + username + "' And Password/text()='" + password + "']" // Unsafe!
result = XPath.evaluate(find_user_xpath)
``` 

Be sure to avoid using string interpolation to pass parameters containing user input. Pass them as hash parameter values, or as parameterized statements instead. Depending on your web framework, text may automatically be properly escaped. For instance, as of Rails 3, html and javascript text is automatically properly escaped so it renders as plain text on the page instead of being interpreted as a language. In case input is not automatically escaped, here's an example of {{#goodConfig}}safely{{/goodConfig}} parameterizing an XPath query:

```ruby
username = params['username']
password = params['password']
find_user_xpath = "//Customer[UserName/text()='" + username.replace("'", "&apos;") + "' And Password/text()='" + password.replace("'", "&apos;") + "']"
result = XPath.evaluate(find_user_xpath)
```

You can also mitigate the risk of XPath Injection attacks by using an ORM. 


### Python  
<br/>

Untrusted user input should not be used to build an XPath query. For example, the following is not safe since user input is used to build the query string without sanitization: 

```python
name = request.GET.get("name")
query = ".//*[@name = '{}']".format(name)
result = lxml_node.xpath(query)
``` 

Instead, pass the user input as a parameter to the query:

```
name = request.GET.get("name")
result = lxml_node.xpath(".//*[@name = $name]", name=name)
```

The use of the standard `xml.etree` module is not recommended for XPath queries since it does not provide a way to pass parameters. Instead, the use of `lxml.etree` is recommended where possible. 

You can also mitigate the risk of XPath Injection attacks by using an ORM. 

### PHP   
<br/>

Untrusted user input should not be used to build an XPath query. For example, the following is not safe since user input is used to build the query string
without sanitization:


```php
$unsafeQuery = sprintf(".//*[@name = '%s']", $nameFromRequest);
$xpath = new \DOMXPath($xmlDocument);
$result = $xpath->query($unsafeQuery);
``` 

The standard XML libraries in PHP do not provide a way to safely pass parameters. The safest way to mitigate this vulnerability is to avoid the use of
untrusted data when generating queries. 

### Node  
<br/>

Untrusted user input should not be used to build an XPath query. For example, the following is not safe since user input is used to build the query string without sanitization. The user could potentially provide special characters or string sequences that change the meaning of the XPath expression to search for different values.: 

```js
const express = require('express');
const xpath = require('xpath');
const app = express();

app.get('/some/route', function(req, res) {
let userName = req.param("userName");

// User supplied data in an XPath expression makes this vulerable to XPath Injection
let vulnXPathExpr = xpath.parse("//users/user[login/text()='" + userName + "']/home_dir/text()");
vulnXPathExpr.select({
node: root
});
});
``` 

Instead, embed the user input using the variable replacement mechanism offered by xpath: 

```js
const express = require('express');
const xpath = require('xpath');
const app = express();

app.get('/some/route', function(req, res) {
let userName = req.param("userName");

// User supplied data is embedded using variables
let safeXPathExpr = xpath.parse("//users/user[login/text()=$userName]/home_dir/text()");
safeXPathExpr.select({
node: root,
variables: { userName: userName }
});
});
``` 

## How can Contrast help? 
<br/>

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect XPath vulnerabilities as they are tested by watching HTML output and encoding.
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect XPath vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.