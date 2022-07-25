---
layout: default
title: Forms Without Autocomplete
nav_order: 5
---

# Forms Without Autocomplete
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
## Forms Without Autocomplete 

### Overview
<br/>
Many applications have the ability to store information entered into HTML forms, for easier user experience.
When this setting is enabled, the data entered by the user can be stored locally on the user's device, or retrieved by the browser.  


### When Can It Affect My Application? 
<br/>

This weakeness can occur when application has a form that submits sensitive information to the server, andneither the ```<form>``` tag nor the sensitive ```<input>``` fields have autocomplete attribute disabled.



### Impact 
<br/>

Sensitive data may be captured by an attacke and comprimised. The risk of this can range from theft to takeover of user's device. 


### Prevention 
<br/>

Disabling `autocomplete` on form values is easy.  
All you have to do is add an ```autocomplete attribute
with a setting of `off`, as is shown in the password field of this example: 

```html
<form action="/login" method="POST">
    <input type="text" name="username">
    <input type="password" name="userpass" autocomplete="off">
</form>
```

For full protection, you should disable `autocomplete` on the entire
`<form>`, as shown here:

```html
<form action="/login" method="POST" autocomplete="off">
    <input type="text" name="username">
    <input type="password" name="userpass">
</form>
```

In the case of Ruby,if you are generating your forms with **Rails**, add the following section to your `form_for`:

```ruby
html: { autocomplete: "off" }
``` 

## How can Contrast help?
<br/>

- [Contrast Assess](https://www.contrastsecurity.com/contrast-assess) Contrast Assess can detect these vulnerabilities as you code.
- [Contrast Scan](https://www.contrastsecurity.com/contrast-scan) can detect these vulnerabilities in many applications by scanning code.
- [Contrast SCA](https://www.contrastsecurity.com/contrast-sca) can determine if you are using a vulnerable version of a library with this attack, and prioritze based on Runtime Library Usage.
