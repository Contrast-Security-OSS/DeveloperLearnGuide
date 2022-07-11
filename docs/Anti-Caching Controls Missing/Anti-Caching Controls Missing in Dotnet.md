---
layout: page
title: Anti-Caching Controls Missing in Dotnet
permalink: /io/Anti-Caching Controls Missing/Anti-Caching Controls Missing in Dotnet
parent: Anti-Caching Controls Missing
nav_order: 4
---


## .NET  



Under ASP.NET, unfortunately, [HttpContext.Response.Cache.SetCacheability](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcachepolicy.setcacheability?view=netframework-4.8) method only allows a single cache control directive to be added to the headers. Instead, directly call [HttpResponse.AppendHeader](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse.appendheader?view=netframework-4.8) to correctly set the caching headers you need.

Per [Microsoft's remarks](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse.appendheader?view=netframework-4.8#remarks) in the [HttpResponse.AppendHeader](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse.appendheader?view=netframework-4.8) documentation, it is best to avoid Microsoft's cache object model completely to avoid conflicting control mechanisms.



```
Response.AppendHeader("Pragma","no-cache"); // HTTP 1.0 controls
Response.AppendHeader("Cache-Control","no-store, no-cache, must-revalidate"); // HTTP 1.1 controls
Response.AppendHeader("Expires", "-1"); //Prevents caching on proxy servers
```

Under ASP.NET Web API 2, where [HttpResponse](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpresponse?view=netframework-4.8) is not accessible, [ActionFilterAttribute](https://docs.microsoft.com/en-us/dotnet/api/system.web.mvc.actionfilterattribute?view=aspnet-mvc-5.2) may be used. For example:





```
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



```
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





## .NET Core  




ASP.NET Core provides several [mechanisms](https://docs.microsoft.com/en-us/aspnet/core/performance/caching/response?view=aspnetcore-6.0) to set cache control headers. The easiest way to prevent this issue is to specify a cache profile in ```Startup.ConfigureServices```


The ResponseCacheAttribute can be added to the actions of each controller to specify caching behavior:

```
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
```




A cache profile can be created, which can be referenced in a ```ResponseCacheAttribute```. Note, that the method called on the ```IServiceCollection``` has changed between ASP.NET 2.X and 3.X:


```
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

```
[ResponseCache(CacheProfileName = "NoCache")]
```


The final way to use cache control is to set the cache headers in the Response object:

```
Response.Headers.Add("Pragma","no-cache"); // HTTP 1.0 controls
Response.Headers.Add("Cache-Control","no-store, no-cache, must-revalidate"); // HTTP 1.1 controls
Response.Headers.Add("Expires", "-1"); //Prevents caching on proxy servers
```


