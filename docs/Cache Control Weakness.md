# Cache Control Weakness
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Anti-Caching Controls Missing 

### Vulnerability 
<br/>

By default, web browsers and proxies aggressively cache web content, including pages as well as their static content, often for performance reasons.

However, applications and APIs can use headers to inform browsers and proxies that certain content is sensitive and should not be persisted.


### Impact 
<br/>
When caching heeaders are missing or malformed, attackers may be able to access sensitive information previously displayed to the user, such as passwords and bank details. The severity can vary depending on the sensitivity of the information cached.


## Anti-Caching Controls by Language
<br/>
There are several ways in the HTTP response to tell the browser and any intervening proxies to not cache this data. 
Given the ever increasing number of browser and proxy version permutations, keeping up to date with what browser or proxy requires which technique is difficult, and thus our recommendation is to issue a combination of caching controls in order to properly inform user agents of the application's intentions.

Issuing only a subset of these controls guarantees that some version of some browser or proxy will retain the page data when it shouldn't.
<br/>

### .NET  
<br/>


Under ASP.NET, unfortunately, [HttpContext.Response.Cache.SetCacheability](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcachepolicy.setcacheability?view=netframework-4.8) method only allows a single cache control directive to be added to the headers. Instead, directly call [HttpResponse.AppendHeader](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse.appendheader?view=netframework-4.8) to correctly set the caching headers you need.

Per [Microsoft's remarks](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse.appendheader?view=netframework-4.8#remarks) in the [HttpResponse.AppendHeader](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse.appendheader?view=netframework-4.8) documentation, it is best to avoid Microsoft's cache object model completely to avoid conflicting control mechanisms.



```csharp
Response.AppendHeader("Pragma","no-cache"); // HTTP 1.0 controls
Response.AppendHeader("Cache-Control","no-store, no-cache, must-revalidate"); // HTTP 1.1 controls
Response.AppendHeader("Expires", "-1"); //Prevents caching on proxy servers
```

Under ASP.NET Web API 2, where [HttpResponse](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse?view=netframework-4.8) is not accessible, [ActionFilterAttribute](https://docs.microsoft.com/en-us/dotnet/api/system.web.mvc.actionfilterattribute?view=aspnet-mvc-5.2) may be used. For example:


```csharp
public class DisableCacheControlAttribute : ActionFilterAttribute
{
    public override void OnActionExecuted(HttpActionExecutedContext context)
    {
        if (context.Response != null)
        {
            context.Response.Headers.Add("Pragma", "no-cache"); // // HTTP 1.0 controls
            context.Response.Headers.CacheControl = new CacheControlHeaderValue
            {
                MustRevalidate = true,
                NoStore = true,
                NoCache = true,
                MaxAge = TimeSpan.Zero
            }; // HTTP 1.1 controls
            context.Response.Headers.Add("Expires", "-1"); // Legacy HTTP 1.1 Clients
        }

        base.OnActionExecuted(context);
    }
}
```


[ActionFilterAttribute](https://docs.microsoft.com/en-us/dotnet/api/system.web.mvc.actionfilterattribute?view=aspnet-mvc-5.2) may be applied to either the controller or the individual actions, as required.



```csharp
[DisableCacheControl]
public class ValuesController : ApiController
{
    [DisableCacheControl]
    public IHttpActionResult GetValue()
    {
        return Ok();
    }
}
```





### .NET Core  
<br/>

ASP.NET Core provides several [mechanisms](https://docs.microsoft.com/en-us/aspnet/core/performance/caching/response?view=aspnetcore-6.0) to set cache control headers. The easiest way to prevent this issue is to specify a cache profile in ```Startup.ConfigureServices```


The ResponseCacheAttribute can be added to the actions of each controller to specify caching behavior:

```csharp
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
```


A cache profile can be created, which can be referenced in a ```ResponseCacheAttribute```. Note, that the method called on the ```IServiceCollection``` has changed between ASP.NET 2.X and 3.X:


```csharp
// ASP.NET Core 2.X
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc(options => {
        options.CacheProfiles.Add("NoCache",
            new CacheProfile
            {
                Duration = 0,
                Location = ResponseCacheLocation.None,
                NoStore = true
            });
    });
}

// ASP.NET Core 3.X
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews(options => {
        options.CacheProfiles.Add("NoCache",
            new CacheProfile
            {
                Duration = 0,
                Location = ResponseCacheLocation.None,
                NoStore = true
            });
    });
}
```

Then the cache profile can be used with the ```ResponseCacheAttribute```:

```csharp
[ResponseCache(CacheProfileName = "NoCache")]
```


The final way to use cache control is to set the cache headers in the Response object:

```csharp
Response.Headers.Add("Pragma","no-cache"); // HTTP 1.0 controls
Response.Headers.Add("Cache-Control","no-store, no-cache, must-revalidate"); // HTTP 1.1 controls
Response.Headers.Add("Expires", "-1"); //Prevents caching on proxy servers
``` 

### Java  
<br/>


The easiest way to prevent this issue from occurring in Java EE applications is to add these ```setHeader()``` calls to a servlet filter for all sensitive content:

```java
response.setHeader("Cache-Control","no-store, no-cache, must-revalidate"); //HTTP 1.1 controls
response.setHeader("Pragma","no-cache"); //HTTP 1.0 controls
response.setDateHeader("Expires", -1); //Prevents caching on proxy servers 
```


### Node  
<br/>

The [http module](https://nodejs.org/api/http.html#http_class_http_serverresponse) class exposes a 

```js
setHeader(name, value)
```

function which can be used to add these response headers to control caching:

```js
response.header('Cache-Control', 'private, no-store, no-cache, must-revalidate'); // HTTP 1.1 controls
response.header('Pragma', '-1'); // HTTP 1.0 controls
response.header('Expires', '-1'); // prevents caching on proxy servers
```

If using the Express framework, the [helmet](https://www.npmjs.com/package/helmet) middleware can be used to set an app's response headers:


```js
var express = require('express');
var helmet = require('helmet');

var app = express();
app.use(helmet.noCache());
```

### Ruby  
<br/>

The easiest way to prevent this issue from occurring in Rails applications is to add these
**default_headers** calls to the application configuration:

```ruby
config.action_dispatch.default_headers = {
  'Cache-Control' => 'no-store, no-cache, must-revalidate',
  'Pragma' => 'no-cache',
  'Expires' => -1
}
```

The approach for Sinatra is similar. Include the [rack protection](https://github.com/sinatra/sinatra/tree/master/rack-protection) gem and add the following to the application configuration extending ```Sinatra::Base```:

```ruby
cache_control :no_cache, :no_store, :must_revalidate
expires -1
```


If setting headers is difficult in your infrastructure, you can also simulate them via ```meta``` tags in the HTML sent to the browser

```xml
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="-1">
```

At a minimum, Contrast expects to see a ```Cache-Control``` setting that contains ```no-store``` and ```no-cache```. This will alleviate client-side browser caching concerns in modern browsers. This control can be delivered with a ```setHeader()``` call or a ```&lt;meta&gt;``` tag. 


## Anti-Caching Controls Disabled 


### Overview 
<br/>
Without proper cache controls, an attacker could learn any sensitive information contained in the victim's client-side browser cache. This sensitive information may include PII, authentication information such as usernames, or financial data such as account numbers. An attacker may gain access to a victim's browser cache through a number of different means such as: shared machine access, host OS exploits, browser exploits, browser plugin exploits, etc.

### How To Fix 
<br/>
The cache control header can be enabled by changing the `sendCacheControlHeader` value to `true`, as is shown in this example: 
	    
```xml
<httpRuntime sendCacheControlHeader="true" />
```






