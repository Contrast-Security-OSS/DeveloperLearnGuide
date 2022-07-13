---
layout: page
title: Overview
permalink: /io/Client-side JSON injection/Overview
parent: Client-side JSON injection
nav_order: 1
---


## Client Side Injection 


### What Is It?

This attack occurs when data from an untrusted source is not sanitized sufficiently, and then parsed directly using the Javascript ```eval()``` function.

Let's walkthrough an vulnerable example. 
Here we have a web application that displays the user profile of airline passenger when viewing their profile photo,

The profile lists the travel tier of the selected user, but data user input is poorly sanitized. 

Upon visiting the profile data: https://airlinecarrier.com/api/users/update/profiledata.json, we receive the following response:

```
{
"Benefits": "Tier",

"Level": "Bronze"
}

var data = eval("(" + resp + ")");

document.getElementById("#Benefits").innerText = data.Benefits;

document.getElementById("#Level").innerText = data.Level;

```

Data is read (parsed) and inserted using the Json eval () function.


Using this flaw, the attacker can create a Client Side Injection attack by injecting the following code:

```
Platinum."});alert(1);({"Benefits":"Tier","Level":"Platinumn”.
```

When this argument is executed by the ```eval()``` function, the new output is as follows:

```
{
"Benefits": "Tier",

"Level": "Platinum."});alert(1);({"Benefits":"Tier","Level":"Platinum"
}
```

The user now has elevated their tier level for this airline.



### Impact

An attacker may be able to use this flaw in order to process unintended actions on behalf of another user.  

Vulnerabilities like this can also lead to other dangerous attacks, such as Cross Site Scripting (XSS).

### Prevention



The most effective method of preventing JSON injection is to avoid allowing strings containing data from any untrusted source to be parsed as JSON.

Additionally, ensure to not use the ```eval()``` function to evaluate JSON data, instead use ```JSON.parse()``` to safely parse JSON response data. 



