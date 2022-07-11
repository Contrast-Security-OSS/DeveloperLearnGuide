---
layout: page
title: Overview
permalink: /io/Forms Without Autocomplete/Overview
parent: Forms Without Autocomplete
nav_order: 1
---

## Forms Without Autocomplete 

### What Is It?

Many applications have the ability to store information entered into HTML forms, for easier user experience.
When this setting is enabled, the data entered by the user can be stored locally on the user's device, or retrieved by the browser.  




### When Can It Affect My Application? 


This weakeness can occur when application has a form that submits sensitive information to the server, andneither the ```<form>``` tag nor the sensitive ```<input>``` fields have autocomplete attribute disabled.



### Impact 


Sensitive data may be captured by an attacke and comprimised. The risk of this can range from theft to takeover of user's device. 


### Prevention 

Disabling ```autocomplete``` on form values is easy.  
All you have to do is add an ```autocomplete attribute
with a setting of ```off```, as is shown in the password field of this example: 

```
<form action="/login" method="POST">
    <input type="text" name="username">
    <input type="password" name="userpass" autocomplete="off">
</form>
```


However, to prevent Contrast from flagging the form, you should disable ```autocomplete``` on the entire
```&lt;form&gt;```, as shown here:

```
<form action="/login" method="POST" autocomplete="off">
    <input type="text" name="username">
    <input type="password" name="userpass">
</form>
```



In the case of Ruby,if you are generating your forms with **Rails**, add the following section to your ```form_for```:

```html: { autocomplete: "off" }```
