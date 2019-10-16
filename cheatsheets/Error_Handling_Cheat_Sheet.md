# Introduction

Error handling is a part of the overall security of an application. Except in movies, an attack always begin by a **Reconnaissance** phase in which the attacker will try to gather as much technical information (often *name* and *version* properties) as possible about the target, such as the application server, frameworks, libraries, etc.

Unhandled errors can assist an attacker in this initial phase, which is very important for the rest the attack.

The following [link](http://blog.cipher.com/the-6-primary-phases-of-penetration-/) provides a description of the different phases of an attack.

# Context

Issues at the error handling level can reveal a lot of information about the target and can also be used to identify injection points in the target's features.

Below is an example of the disclosure of a technology stack, here Struts2 and Tomcat version, via an exception rendered to the user:

```text
HTTP Status 500 - For input string: "null"

type Exception report

message For input string: "null"

description The server encountered an internal error that prevented it from fulfilling this request.

exception

java.lang.NumberFormatException: For input string: "null"
    java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
    java.lang.Integer.parseInt(Integer.java:492)
    java.lang.Integer.parseInt(Integer.java:527)
    sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
    sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:57)
    sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
    java.lang.reflect.Method.invoke(Method.java:606)
    com.opensymphony.xwork2.DefaultActionInvocation.invokeAction(DefaultActionInvocation.java:450)
    com.opensymphony.xwork2.DefaultActionInvocation.invokeActionOnly(DefaultActionInvocation.java:289)
    com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:252)
    org.apache.struts2.interceptor.debugging.DebuggingInterceptor.intercept(DebuggingInterceptor.java:256)
    com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:246)
    ...

note: The full stack trace of the root cause is available in the Apache Tomcat/7.0.56 logs.
```

Below is an example of disclosure of a SQL query error, along the site installation path, that is useful to identify an injection point:

```text
Warning: odbc_fetch_array() expects parameter /1 to be resource, boolean given 
in D:\app\index_new.php on line 188
```    

The [OWASP Testing Guide](https://www.owasp.org/index.php/Testing_Information_Gathering) provides different techniques to obtain technical information from an application.

# Objective

The article shows how to configure a global error handler at the configuration level when possible, otherwise at code level, in differents technologies, in order to ensure that if an unexpected error occurs then a generic response is returned by the application but the error is traced on server side for investigation.

The following schema shows the target approach:

![Overview](../assets/Error_Handling_Cheat_Sheet_Overview.png)

As most of the recent application topology are *API based*, we assume in this article that the backend exposes only a REST API and does not contain any user interface content.

About the error logging operation itself, the [logging cheat sheet](Logging_Cheat_Sheet.md) should be used, this article will focus on the error handling part.

# Proposition

For each technology, a setup will be proposed with configuration and code snippet.

## Java classic web application

For this kind of application, a global error handler can be configured at the **web.xml** deployment descriptor level.

We propose here a configuration that can be used from Servlet specification *version 2.5* and above.

With this configuration, any unexpected error will cause a redirection to the page **error.jsp** in which the error will be traced and a generic response will be returned.

Configuration of the redirection into the **web.xml** file:

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ns="http://java.sun.com/xml/ns/javaee" 
xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd" 
version="3.0">
...
    <error-page>
        <exception-type>java.lang.Exception</exception-type>
        <location>/error.jsp</location>
    </error-page>
...
</web-app>
```

Content of the **error.jsp** file:

``` java
<%@ page language="java" isErrorPage="true" contentType="application/json; charset=UTF-8" 
    pageEncoding="UTF-8"%>
<%
String errorMessage = exception.getMessage();
//Log the exception via the content of the implicit variable named "exception"
//...
//We build a generic response with a JSON format because we are in a REST API app context
//We also add an HTTP response header to indicate to the client app that the response is an error
response.setHeader("X-ERROR", "true");
response.setStatus(200);
%>
{"message":"An error occur, please retry"}
```

## Java SpringMVC/SpringBoot web application

With [SpringMVC](https://docs.spring.io/spring/docs/current/spring-framework-reference/web.html) or [SpringBoot](http://spring.io/projects/spring-boot), you can define a global error handler by simply implementing this kind of class into your project.

We indicate to the handler, via the annotation [@ExceptionHandler](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/bind/annotation/ExceptionHandler.html), to act when any exception extending the class *java.lang.Exception* is thrown by the application.

``` java
import net.minidev.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

/**
 * Global error handler in charge of returning a generic response in case of unexpected error situation.
 */
@ControllerAdvice
public class RestResponseEntityExceptionHandler {

    @ExceptionHandler(value = {Exception.class})
    public ResponseEntity<Object> handleGlobalError(RuntimeException exception, WebRequest request) {
        //Log the exception via the content of the parameter named "exception"
        //...
        //We build a generic response with a JSON format because we are in a REST API app context
        //We also add an HTTP response header to indicate to the client app that the response is an error
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_JSON);
        responseHeaders.set("X-ERROR", "true");
        JSONObject responseBody = new JSONObject();
        responseBody.put("message", "An error occur, please retry");
        ResponseEntity<JSONObject> response = new ResponseEntity<>(responseBody, responseHeaders, 
                                                                   HttpStatus.OK);
        return (ResponseEntity) response;
    }
}
```

References:

- [Exception handling with Spring](http://www.baeldung.com/exception-handling-for-rest-with-spring)
- [Exception handling with SpringBoot](https://www.toptal.com/java/spring-boot-rest-api-error-handling)

## ASP NET Core web application

With [ASP.NET Core](https://docs.microsoft.com/en-us/aspnet/core/?view=aspnetcore-2.2), you can define a global error handler by indicating that the exception handler is a dedicated API Controller.

Content of the API Controller dedicated to the error handling:

``` csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Net;

namespace MyProject.Controllers
{
    /// <summary>
    /// API Controller used to intercept and handle all unexpected exception
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class ErrorController : ControllerBase
    {
        /// <summary>
        /// Action that will be invoked for any call to this Controller in order to handle the current error
        /// </summary>
        /// <returns>A generic error formatted as JSON because we are in a REST API app context</returns>
        [HttpGet]
        [HttpPost]
        [HttpHead]
        [HttpDelete]
        [HttpPut]
        [HttpOptions]
        [HttpPatch]
        public JsonResult Handle()
        {
            //Get the exception that has implied the call to this controller
            Exception exception = HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error;
            //Log the exception via the content of the variable named "exception" if it is not NULL
            //...
            //We build a generic response with a JSON format because we are in a REST API app context
            //We also add an HTTP response header to indicate to the client app that the response 
            //is an error
            var responseBody = new Dictionary<String, String>{ {
                "message", "An error occur, please retry"
            } };
            JsonResult response = new JsonResult(responseBody);
            response.StatusCode = (int)HttpStatusCode.OK;
            Request.HttpContext.Response.Headers.Remove("X-ERROR");
            Request.HttpContext.Response.Headers.Add("X-ERROR", "true");
            return response;
        }
    }
}
```

Definition in the application **Startup.cs** file of the mapping of the exception handler to the dedicated error handling API controller:

``` csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyProject
{
    public class Startup
    {
...
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            //First we configure the error handler middleware!
            //We enable the global error handler in others environments than DEV 
            //because debug page are useful during implementation
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                //Our global handler is defined on "/api/error" URL so we indicate to the 
                //exception handler to call this API controller
                //on any unexpected exception raised by the application
                app.UseExceptionHandler("/api/error");
            }

            //We configure others middlewares, remember that the declaration order is important...
            app.UseMvc();
            //...
        }
    }
}
```

References:

- [Exception handling with ASP.Net Core](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/error-handling?view=aspnetcore-2.1)

## ASP NET Web API web application

With [ASP.NET Web API](https://www.asp.net/web-api) (from the standard .NET framework and not from the .NET Core framework), you can define and register handlers in order to trace and handle any error that occurs in the application.

Definition of the handler for the tracing of the error details:

``` csharp
using System;
using System.Web.Http.ExceptionHandling;

namespace MyProject.Security
{
    /// <summary>
    /// Global logger used to trace any error that occurs at application wide level
    /// </summary>
    public class GlobalErrorLogger : ExceptionLogger
    {
        /// <summary>
        /// Method in charge of the management of the error from a tracing point of view
        /// </summary>
        /// <param name="context">Context containing the error details</param>
        public override void Log(ExceptionLoggerContext context)
        {
            //Get the exception
            Exception exception = context.Exception;
            //Log the exception via the content of the variable named "exception" if it is not NULL
            //...
        }
    }
}
```

Definition of the handler for the management of the error in order to return a generic response:

``` csharp
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;

namespace MyProject.Security
{
    /// <summary>
    /// Global handler used to handle any error that occurs at application wide level
    /// </summary>
    public class GlobalErrorHandler : ExceptionHandler
    {
        /// <summary>
        /// Method in charge of handle the generic response send in case of error
        /// </summary>
        /// <param name="context">Error context</param>
        public override void Handle(ExceptionHandlerContext context)
        {
            context.Result = new GenericResult();
        }

        /// <summary>
        /// Class used to represent the generic response send
        /// </summary>
        private class GenericResult : IHttpActionResult
        {
            /// <summary>
            /// Method in charge of creating the generic response
            /// </summary>
            /// <param name="cancellationToken">Object to cancel the task</param>
            /// <returns>A task in charge of sending the generic response</returns>
            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                //We build a generic response with a JSON format because we are in a REST API app context
                //We also add an HTTP response header to indicate to the client app that the response 
                //is an error
                var responseBody = new Dictionary<String, String>{ {
                    "message", "An error occur, please retry"
                } };
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.Add("X-ERROR", "true");
                response.Content = new StringContent(JsonConvert.SerializeObject(responseBody), 
                                                     Encoding.UTF8, "application/json");
                return Task.FromResult(response);
            }
        }
    }
}
```

Registration of the both handlers in the application **WebApiConfig.cs** file:

``` csharp
using MyProject.Security;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;

namespace MyProject
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            //Register global error logging and handling handlers in first
            config.Services.Replace(typeof(IExceptionLogger), new GlobalErrorLogger());
            config.Services.Replace(typeof(IExceptionHandler), new GlobalErrorHandler());
            //Rest of the configuration
            //...
        }
    }
}
```

References:

- [Exception handling with ASP.Net Web API](https://exceptionnotfound.net/the-asp-net-web-api-exception-handling-pipeline-a-guided-tour/)

# Sources of the prototype

The source code of all the sandbox projects created to find the right setup to use is stored in this [GitHub repository](https://github.com/righettod/poc-error-handling).
