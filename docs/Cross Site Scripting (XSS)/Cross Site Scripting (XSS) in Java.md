---
layout: page
title: Cross Site Scripting (XSS) in Java
permalink: /io/Cross Site Scripting (XSS)/Cross Site Scripting (XSS) in Java
parent: Cross Site Scripting (XSS)
nav_order: 3
---

## Cross Site Scripting (XSS) in Java


If the input or output of the parameter can be removed, it should. 
Otherwise, encode the parameter using the appropriate technique, based on where the parameter is rendered on the page:



| **Context**  | **Example**         | **Dangerous Characters** |     **Encoding**  |   **Notes**     |
|:-------------|:------------------|:------|:------|:------|
| HTML Entity  | ```<div>{untrusted}</div>``` | ```&<>”’/```  | ```&#xHH;```        |       |
| HTML Attribute | ```<input value="{untrusted}">```  | non alpha-numeric  | ```&#xHH;```      | This is not safe for complex attributes like ```href``` , ```src``` , ```style``` or event handlers like ```onclick``` . Strong allowlist validation must be performed to avoid unsafe URLs like ```javascript:``` or ```data:``` , along with and CSS expressions.      |
| URL Parameter          | ```<a href="/?name={untrusted}">```      | non alpha-numeric   | ```%HH```       |       |
| CSS           | ```	p { color : {untrusted} };``` | on alpha-numeric  | ```\HH```       | This is not safe for complex properties like ```url``` , ```behavior``` , and ```-moz-binding``` . Strong allowlist validation must be performed to avoid JavaScript URLs and CSS expressions.      |
| JavaScript        | ```var name = ‘{untrusted}’;``` | non alpha-numeric | ```\xHH;```       | Some JavaScript functions can never safely use untrusted data as input without allowlist validation.      |




### Using JSP

```
<c:out value=\"${userControlledValue}\"/>

... or ...

${fn:escapeXml(userControlledValue)}
```


### Recommendations for Spring tag 

Here's how you can output text safely with the Spring tag library:

```
<div>
<spring:escapeBody htmlEscape=\"true\">${userControlledValue}</spring:escapeBody> // for data in HTML context</div>
<script>
<!--
var str = \"<spring:escapeBody javaScriptEscape=\"true\">${userControlledValue}</spring:escapeBody>\"; // for data in JavaScript context
-->
</script>
```

Input validation helps, but many times the characters used in XSS attacks are necessary for the application's purpose. 
So, while we always recommend allowlist input validation, we recognize that it's not always possible to use this as a defense against XSS.

