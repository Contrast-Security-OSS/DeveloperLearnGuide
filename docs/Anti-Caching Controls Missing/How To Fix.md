---
layout: page
title: How To Fix
permalink: /io/Anti-Caching Controls Missing/How To Fix
parent: Anti-Caching Controls Missing
nav_order: 3
---

## How To Fix 

#### Introduction   



There are a couple ways in the HTTP response to tell the browser and any intervening proxies to not cache this data. 
Given the ever increasing number of browser and proxy version permutations, keeping up to date with what browser or proxy requires
what cache control is hard, and thus our recommendation is to issue a combination of caching controls in
order to properly inform user agents of different types of the application's intentions.

Issuing only a subset of these controls guarantees that some version of some browser or proxy will retain the page data when it shouldn't.


### Java  



The easiest way to prevent this issue from occurring in Java EE applications is to add these ```setHeader()``` calls to a servlet filter for all sensitive content:

```
response.setHeader("Cache-Control","no-store, no-cache, must-revalidate"); //HTTP 1.1 controls
response.setHeader("Pragma","no-cache"); //HTTP 1.0 controls
response.setDateHeader("Expires", -1); //Prevents caching on proxy servers 
```


### Node  





The [http module](https://nodejs.org/api/http.html#http_class_http_serverresponse) class exposes a 
```
setHeader(name, value)
```
function which can be used to add these response headers to control caching:


```response.header('Cache-Control', 'private, no-store, no-cache, must-revalidate'); // HTTP 1.1 controls
response.header('Pragma', '-1'); // HTTP 1.0 controls
response.header('Expires', '-1'); // prevents caching on proxy servers
```


If using the Express framework, the [helmet](https://www.npmjs.com/package/helmet) middleware can be used to set an app's response headers:
```
var express = require('express');
var helmet = require('helmet');

var app = express();
app.use(helmet.noCache());
```


### Ruby  


The easiest way to prevent this issue from occurring in Rails applications is to add these
**default_headers** calls to the application configuration:


```config.action_dispatch.default_headers = {
  'Cache-Control' => 'no-store, no-cache, must-revalidate',
  'Pragma' => 'no-cache',
  'Expires' => -1
}
```

The approach for Sinatra is similar. Include the [rack protection](https://github.com/sinatra/sinatra/tree/master/rack-protection) gem and add the following to the application configuration extending ```Sinatra::Base```:
```cache_control :no_cache, :no_store, :must_revalidate
expires -1
```


If setting headers is difficult in your infrastructure, you can also simulate them via ```meta``` tags in the HTML sent to the browser

```<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="-1">
```

At a minimum, Contrast expects to see a ```Cache-Control``` setting that contains ```no-store``` and ```no-cache```. This will alleviate client-side browser caching concerns in modern browsers. This control can be delivered with a ```setHeader()``` call or a ```&lt;meta&gt;``` tag.

