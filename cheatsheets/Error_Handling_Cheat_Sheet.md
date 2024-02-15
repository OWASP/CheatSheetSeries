# Error Handling Cheat Sheet

## Introduction

When you are managing the security of an application, proper error handling plays a key role in protecting that application from attacks. Almost all attackers will begin their efforts by initiating a **Reconnaissance** phase, in which they try to gther as much technical information as possible about your application, including attempts to identify the application server, frameworks, libraries, etc (with a focus on *name* and *version* properties). One of the most important sources of that technical information is error messages returned by the application.

(For more information about different phases of an attack, the following [link](https://cipher.com/blog/a-complete-guide-to-the-phases-of-penetration-testing/) will give you more information on how an attack occurs.)

**If you do not manage your errors so they yield as little information about your application as possible to attackers, those errors can provide them with a great deal of useful information that they will use to build their attack. Without the crucial information from unhandled errors, an attack is much more difficult. Tougher applications are less likely to be targeted by casual attackers.**

Index:

[How An Error Can Reveal Information to Attackers](#how-an-error-can-reveal-information-to-attackers)
[Objective: Create a Global Error Handler in Runtime Configuration](#objective-create-a-global-error-handler-in-runtime-configuration)
[Suggested Technology Stack Configurations for Global Error Handlers](#suggested-technology-stack-configurations-for-global-error-handlers)
[GitHub Repository for Source Code of Prototypes](#github-repository-for-source-code-of-prototypes)
[Appendix for HTML Errors](#appendix-for-http-errors)

## How An Error Can Reveal Information to Attackers

Here are two examples that demonstrates how error handling level can reveal information about the target. This information can be used to identify injection points.

### Error 1: Technology Stack Disclosure Reveals Information About Injection Points

In the first example, an error discloses a technology stack. As you can see, the Struts2 and Tomcat versions are revealed via an exception that is rendered to the user:

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

### Error 2: SQL Query Error Reveals Injection

The second example shows how how an SQL query error reveals the site installation path, which can be used to identify an injection point:

```text
Warning: odbc_fetch_array() expects parameter /1 to be resource, boolean given
in D:\app\index_new.php on line 188
```

If you want to know more about how attackers obtain technical information from an application, go to the [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/).

## Objective: Create A Global Error Handler in Runtime Configuration

To manage errors effectively, we suggest that you configure a global error handler as part of your application's runtime configuration. In some cases, it may be more efficient to define this error handler as part of your code. This error hander should deny critical information to attackers by returning a generic response to users when an unexpected error occurs, while logging the actual error details on the server side for further investigation.

This schema shows the target approach:

![Overview](../assets/Error_Handling_Cheat_Sheet_Overview.png)

Because recent application topologies are *API based*, here we assume that the backend exposes only a REST API and does not contain any user interface content. The application's error handler should respond to all possible failure modes, use 5xx errors only to indicate responses to requests that it cannot fulfill, but it should not reveal implementation details to the user. For that, [RFC 7807 - Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc7807) defines a document format. When you implement the error logging operation, you should refer to the [logging cheat sheet](Logging_Cheat_Sheet.md). This article focuses on the error handling part.

## Suggested Technology Stack Configurations for Global Error Handlers

For each technology stack, the following configuration options are suggested:

[Standard Java Web Application](#standard-java-web-application)
[Java SpringMVC/SpringBoot web application](#java-springmvcspringboot-web-application)
[ASP NET Core web application](#asp-net-core-web-application)
[ASP NET Web API web application](#asp-net-web-api-web-application)

### Standard Java Web Application

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
//Note that we're using an internal server error response
//In some cases it may be prudent to return 4xx error codes, when we have misbehaving clients
response.setStatus(500);
%>
{"message":"An error occur, please retry"}
```

### Java SpringMVC/SpringBoot web application

With [SpringMVC](https://docs.spring.io/spring/docs/current/spring-framework-reference/web.html) or [SpringBoot](https://spring.io/projects/spring-boot), you can define a global error handler by implementing the following class in your project. Spring Framework 6 introduced [the problem details based on RFC 7807](https://github.com/spring-projects/spring-framework/issues/27052).

We ask the handler, via the annotation [@ExceptionHandler](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/bind/annotation/ExceptionHandler.html), to act when any exception extending the class *java.lang.Exception* is thrown by the application. We also use the [ProblemDetail class](https://docs.spring.io/spring-framework/docs/6.0.0/javadoc-api/org/springframework/http/ProblemDetail.html) to create the response object.

``` java
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Global error handler in charge of returning a generic response in case of unexpected error situation.
 */
@RestControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = {Exception.class})
    public ProblemDetail handleGlobalError(RuntimeException exception, WebRequest request) {
        //Log the exception via the content of the parameter named "exception"
        //...
        //Note that we're using an internal server error response
        //In some cases it may be prudent to return 4xx error codes, if we have misbehaving clients
        //By specification, the content-type can be "application/problem+json" or "application/problem+xml"
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An error occur, please retry");
    }
}
```

References:

- [Exception handling with Spring](https://www.baeldung.com/exception-handling-for-rest-with-spring)
- [Exception handling with SpringBoot](https://www.toptal.com/java/spring-boot-rest-api-error-handling)

### ASP NET Core web application

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
            //Note that we're using an internal server error response
            //In some cases it may be prudent to return 4xx error codes, if we have misbehaving clients
            response.StatusCode = (int)HttpStatusCode.InternalServerError;
            Request.HttpContext.Response.Headers.Remove("X-ERROR");
            Request.HttpContext.Response.Headers.Add("X-ERROR", "true");
            return response;
        }
    }
}
```

The definition in the application **Startup.cs** file maps the exception handler to the dedicated error handling API controller:

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

                //To customize the response content type and text, use the overload of
                //UseStatusCodePages that takes a content type and format string.
                app.UseStatusCodePages("text/plain", "Status code page, status code: {0}");
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

### ASP NET Web API web application

If you are using [ASP.NET Web API](https://www.asp.net/web-api) (from the standard .NET framework and not from the .NET Core framework), you can define and register handlers that can trace and handle any error that occurs in the application.

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
                // Note that we're using an internal server error response
                // In some cases it may be prudent to return 4xx error codes, if we have misbehaving clients 
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
                response.Headers.Add("X-ERROR", "true");
                response.Content = new StringContent(JsonConvert.SerializeObject(responseBody),
                                                     Encoding.UTF8, "application/json");
                return Task.FromResult(response);
            }
        }
    }
}
```

How to register both handlers in the application **WebApiConfig.cs** file:

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

The customErrors section is set within the **Web.config** file (inside the ```csharp <system.web>``` node) as follows:

```csharp
<configuration>
    ...
    <system.web>
        <customErrors mode="RemoteOnly"
                      defaultRedirect="~/ErrorPages/Oops.aspx" />
        ...
    </system.web>
</configuration>
```

References:

- [Exception handling with ASP.Net Web API](https://exceptionnotfound.net/the-asp-net-web-api-exception-handling-pipeline-a-guided-tour/)

- [ASP.NET Error Handling](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/getting-started/getting-started-with-aspnet-45-web-forms/aspnet-error-handling)

## GitHub Repository for Source Code of Prototypes

The source code of all the sandbox projects created to find the right setup to use is stored in this [GitHub repository](https://github.com/righettod/poc-error-handling).

## Appendix for HTTP Errors

If you need a reference for HTTP errors, it can be found here at the IETF's guide [RFC 2616](https://www.ietf.org/rfc/rfc2616.txt). As said above, it is extremely important that your application respond to users with error messages that do not provide implementation details or else attackers will take advantage of information leakage. In general, consider using 4xx error codes for requests that are due to an error on the part of the HTTP client (e.g. unauthorized access, request body too large) and use 5xx to indicate errors that are triggered on server side, due to an unforeseen bug. Ensure that applications are monitored for 5xx errors which are normally a good indication of the application failing for some sets of inputs.
