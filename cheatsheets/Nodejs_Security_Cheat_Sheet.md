# NodeJS Security Cheat Sheet

## Introduction

This cheat sheet lists actions developers can take to develop secure Node.js applications. Each item has a brief explanation and solution that is specific to the Node.js environment.

## Context

Node.js applications are increasing in number and they are no different from other frameworks and programming languages. Node.js applications are prone to all kinds of web application vulnerabilities.

## Objective

This cheat sheet aims to provide a list of best practices to follow during development of Node.js applications.

## Recommendations

There are several recommendations to enhance security of your Node.js applications. These are categorized as:

- **Application Security**
- **Error & Exception Handling**
- **Server Security**
- **Platform Security**

### Application Security

#### Use flat Promise chains

Asynchronous callback functions are one of the strongest features of Node.js. However, increasing layers of nesting within callback functions can become a problem. Any multistage process can become nested 10 or more levels deep. This problem is referred to as a "Pyramid of Doom" or "Callback Hell". In such code, the errors and results get lost within the callback. Promises are a good way to write asynchronous code without getting into nested pyramids. Promises provide top-down execution while being asynchronous by delivering errors and results to next `.then` function.

Another advantage of Promises is the way Promises handle errors. If an error occurs in a Promise class, it skips over the `.then` functions and invokes the first `.catch` function it finds. This way Promises provide a higher assurance of capturing and handling errors. As a principle, you can make all your asynchronous code (apart from emitters) return promises. It should be noted that Promise calls can also become a pyramid. In order to completely stay away from "Callback Hell", flat Promise chains should be used. If the module you are using does not support Promises, you can convert base object to a Promise by using `Promise.promisifyAll()` function.

The following code snippet is an example of "Callback Hell":

```JavaScript
function func1(name, callback) {
  // operations that takes a bit of time and then calls the callback
}
function func2(name, callback) {
  // operations that takes a bit of time and then calls the callback
}
function func3(name, callback) {
  // operations that takes a bit of time and then calls the callback
}
function func4(name, callback) {
  // operations that takes a bit of time and then calls the callback
}

func1("input1", function(err, result1){
   if(err){
      // error operations
   }
   else {
      //some operations
      func2("input2", function(err, result2){
         if(err){
            //error operations
         }
         else{
            //some operations
            func3("input3", function(err, result3){
               if(err){
                  //error operations
               }
               else{
                  // some operations
                  func4("input 4", function(err, result4){
                     if(err){
                        // error operations
                     }
                     else {
                        // some operations
                     }
                  });
               }
            });
         }
      });
   }
});
```

The above code can be securely written as follows using a flat Promise chain:

```JavaScript
function func1(name) {
  // operations that takes a bit of time and then resolves the promise
}
function func2(name) {
  // operations that takes a bit of time and then resolves the promise
}
function func3(name) {
  // operations that takes a bit of time and then resolves the promise
}
function func4(name) {
  // operations that takes a bit of time and then resolves the promise
}

func1("input1")
   .then(function (result){
      return func2("input2");
   })
   .then(function (result){
      return func3("input3");
   })
   .then(function (result){
      return func4("input4");
   })
   .catch(function (error) {
      // error operations
   });
```

And using async/await:

```JavaScript
function async func1(name) {
  // operations that takes a bit of time and then resolves the promise
}
function async func2(name) {
  // operations that takes a bit of time and then resolves the promise
}
function async func3(name) {
  // operations that takes a bit of time and then resolves the promise
}
function async func4(name) {
  // operations that takes a bit of time and then resolves the promise
}

(async() => {
  try {
    let res1 = await func1("input1");
    let res2 = await func2("input2");
    let res3 = await func3("input2");
    let res4 = await func4("input2");
  } catch(err) {
    // error operations
  }
})();
```

#### Set request size limits

Buffering and parsing of request bodies can be a resource intensive task. If there is no limit on the size of requests, attackers can send requests with large request bodies that can exhaust server memory and/or fill disk space. You can limit the request body size for all requests using [raw-body](https://www.npmjs.com/package/raw-body).

```JavaScript
const contentType = require('content-type')
const express = require('express')
const getRawBody = require('raw-body')

const app = express()

app.use(function (req, res, next) {
  if (!['POST', 'PUT', 'DELETE'].includes(req.method)) {
    next()
    return
  }

  getRawBody(req, {
    length: req.headers['content-length'],
    limit: '1kb',
    encoding: contentType.parse(req).parameters.charset
  }, function (err, string) {
    if (err) return next(err)
    req.text = string
    next()
  })
})
```

However, fixing a request size limit for all requests may not be the correct behavior, since some requests may have a large payload in the request body, such as when uploading a file. Also, input with a JSON type is more dangerous than a multipart input, since parsing JSON is a blocking operation. Therefore, you should set request size limits for different content types. You can accomplish this very easily with express middleware as follows:

```JavaScript
app.use(express.urlencoded({ extended: true, limit: "1kb" }));
app.use(express.json({ limit: "1kb" }));
```

It should be noted that attackers can change the `Content-Type` header of the request and bypass request size limits. Therefore, before processing the request, data contained in the request should be validated against the content type stated in the request headers. If content type validation for each request affects the performance severely, you can only validate specific content types or request larger than a predetermined size.

#### Do not block the event loop

Node.js is very different from common application platforms that use threads. Node.js has a single-thread event-driven architecture. By means of this architecture, throughput becomes high and the programming model becomes simpler. Node.js is implemented around a non-blocking I/O event loop. With this event loop, there is no waiting on I/O or context switching. The event loop looks for events and dispatches them to handler functions. Because of this, when CPU intensive JavaScript operations are executed, the event loop waits for them to finish. This is why such operations are called "blocking". To overcome this problem, Node.js allows assigning callbacks to IO-blocked events. This way, the main application is not blocked and callbacks run asynchronously. Therefore, as a general principle, all blocking operations should be done asynchronously so that the event loop is not blocked.

Even if you perform blocking operations asynchronously, your application may still not serve as expected. This happens if there is a code outside the callback that relies on the code within the callback to run first. For example, consider the following code:

```JavaScript
const fs = require('fs');
fs.readFile('/file.txt', (err, data) => {
  // perform actions on file content
});
fs.unlinkSync('/file.txt');
```

In the above example, `unlinkSync` function may run before the callback, which will delete the file before the desired actions on the file content is done. Such race conditions can also affect the security of your application. An example would be a scenario where authentication is performed in a callback and authenticated actions are run synchronously. In order to eliminate such race conditions, you can write all operations that rely on each other in a single non-blocking function. By doing so, you can guarantee that all operations are executed in the correct order. For example, above code example can be written in a non-blocking way as follows:

```JavaScript
const fs = require('fs');
fs.readFile('/file.txt', (err, data) => {
  // perform actions on file content
  fs.unlink('/file.txt', (err) => {
    if (err) throw err;
  });
});
```

In the above code, call to unlink the file and other file operations are within the same callback. This provides the correct order of operations.

#### Perform input validation

Input validation is a crucial part of application security. Input validation failures can result in many types of application attacks. These include SQL Injection, Cross-Site Scripting, Command Injection, Local/Remote File Inclusion, Denial of Service, Directory Traversal, LDAP Injection and many other injection attacks. In order to avoid these attacks, input to your application should be sanitized first. The best input validation technique is to use a list of accepted inputs. However, if this is not possible, input should be first checked against expected input scheme and dangerous inputs should be escaped. In order to ease input validation in Node.js applications, there are some modules like [validator](https://www.npmjs.com/package/validator) and [express-mongo-sanitize](https://www.npmjs.com/package/express-mongo-sanitize).
For detailed information on input validation, please refer to [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

JavaScript is a dynamic language and depending on how the framework parses a URL, the data seen by the application code can take many forms. Here are some examples after parsing a query string in express.js:

| URL | Content of request.query.foo in code |
| --- | --- |
| `?foo=bar` | `'bar'` (string) |
| `?foo=bar&foo=baz` | `['bar', 'baz']` (array of string) |
| `?foo[]=bar` | `['bar']` (array of string) |
| `?foo[]=bar&foo[]=baz` | `['bar', 'baz']` (array of string) |
| `?foo[bar]=baz` | `{ bar : 'baz' }` (object with a key) |
| `?foo[]baz=bar` | `['bar']` (array of string - postfix is lost) |
| `?foo[][baz]=bar` | `[ { baz: 'bar' } ]` (array of object) |
| `?foo[bar][baz]=bar` | `{ foo: { bar: { baz: 'bar' } } }` (object tree) |
| `?foo[10]=bar&foo[9]=baz` | `[ 'baz', 'bar' ]` (array of string - notice order) |
| `?foo[toString]=bar` | `{}` (object where calling `toString()` will fail) |

#### Perform output escaping

In addition to input validation, you should escape all HTML and JavaScript content shown to users via application in order to prevent cross-site scripting (XSS) attacks. You can use [escape-html](https://github.com/component/escape-html) or [node-esapi](https://github.com/ESAPI/node-esapi) libraries to perform output escaping.

#### Perform application activity logging

Logging application activity is an encouraged good practice. It makes it easier to debug any errors encountered during application runtime. It is also useful for security concerns, since it can be used during incident response. In addition, these logs can be used to feed Intrusion Detection/Prevention Systems (IDS/IPS). In Node.js, there are modules such as [Winston](https://www.npmjs.com/package/winston), [Bunyan](https://www.npmjs.com/package/bunyan), or [Pino](https://www.npmjs.com/package/pino) to perform application activity logging. These modules enable streaming and querying logs, and they provide a way to handle uncaught exceptions.

With the following code, you can log application activities in both console and a desired log file:

```JavaScript
const logger = new (Winston.Logger) ({
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: 'application.log' })
    ],
    level: 'verbose'
});
```

You can provide different transports so that you can save errors to a separate log file and general application logs to a different log file. Additional information on security logging can be found in [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

#### Monitor the event loop

When your application server is under heavy network traffic, it may not be able to serve its users. This is essentially a type of [Denial of Service (DoS)](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) attack. The [toobusy-js](https://www.npmjs.com/package/toobusy-js) module allows you to monitor the event loop. It keeps track of the response time, and when it goes beyond a certain threshold, this module can indicate your server is too busy. In that case, you can stop processing incoming requests and send them `503 Server Too Busy` message so that your application stay responsive. Example use of the [toobusy-js](https://www.npmjs.com/package/toobusy-js) module is shown here:

```JavaScript
const toobusy = require('toobusy-js');
const express = require('express');
const app = express();
app.use(function(req, res, next) {
    if (toobusy()) {
        // log if you see necessary
        res.status(503).send("Server Too Busy");
    } else {
    next();
    }
});
```

#### Take precautions against brute-forcing

[Brute-forcing](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks
) is a common threat to all web applications. Attackers can use brute-forcing as a password guessing attack to obtain account passwords. Therefore, application developers should take precautions against brute-force attacks especially in login pages.  Node.js has several modules available for this purpose. [Express-bouncer](https://libraries.io/npm/express-bouncer), [express-brute](https://libraries.io/npm/express-brute) and [rate-limiter](https://libraries.io/npm/rate-limiter) are just some examples. Based on your needs and requirements, you should choose one or more of these modules and use accordingly. [Express-bouncer](https://libraries.io/npm/express-bouncer) and [express-brute](https://libraries.io/npm/express-brute) modules work similarly. They increase the delay for each failed request and can be arranged for a specific route. These modules can be used as follows:

```JavaScript
const bouncer = require('express-bouncer');
bouncer.whitelist.push('127.0.0.1'); // allow an IP address
// give a custom error message
bouncer.blocked = function (req, res, next, remaining) {
    res.status(429).send("Too many requests have been made. Please wait " + remaining/1000 + " seconds.");
};
// route to protect
app.post("/login", bouncer.block, function(req, res) {
    if (LoginFailed){  }
    else {
        bouncer.reset( req );
    }
});
```

```JavaScript
const ExpressBrute = require('express-brute');

const store = new ExpressBrute.MemoryStore(); // stores state locally, don't use this in production
const bruteforce = new ExpressBrute(store);

app.post('/auth',
    bruteforce.prevent, // error 429 if we hit this route too often
    function (req, res, next) {
        res.send('Success!');
    }
);
```

Apart from [express-bouncer](https://libraries.io/npm/express-bouncer) and [express-brute](https://libraries.io/npm/express-brute), the [rate-limiter](https://libraries.io/npm/rate-limiter) module can also help to prevent brute-forcing attacks. It enables specifying how many requests a specific IP address can make during a specified time period.

```JavaScript
const limiter = new RateLimiter();
limiter.addLimit('/login', 'GET', 5, 500); // login page can be requested 5 times at max within 500 seconds
```

[CAPTCHA usage](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html#captcha) is also another common mechanism used against brute-forcing. There are modules developed for Node.js CAPTCHAs. A common module used in Node.js applications is [svg-captcha](https://www.npmjs.com/package/svg-captcha). It can be used as follows:

```JavaScript
const svgCaptcha = require('svg-captcha');
app.get('/captcha', function (req, res) {
    const captcha = svgCaptcha.create();
    req.session.captcha = captcha.text;
    res.type('svg');
    res.status(200).send(captcha.data);
});
```

[Account lockout](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-lockout) is a recommended solution to keep attackers away from your valid users. Account lockout is possible with many modules like [mongoose](https://www.npmjs.com/package/mongoose). You can refer to [this blog post](http://devsmash.com/blog/implementing-max-login-attempts-with-mongoose) to see how account lockout is implemented in mongoose.

#### Use Anti-CSRF tokens

[Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) aims to perform authorized actions on behalf of an authenticated user, while the user is unaware of this action. CSRF attacks are generally performed for state-changing requests like changing a password, adding users or placing orders. [Csurf](https://www.npmjs.com/package/csurf) is an express middleware that has been used to mitigate CSRF attacks. But a security hole in this package has been recently discovered. The team behind the package has not fixed the discovered vulnerability and they have marked the package as deprecated, recommending using any other CSRF protection package.

For detailed information on cross-site request forgery (CSRF) attacks and prevention methods, you can refer to [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

#### Remove unnecessary routes

A web application should not contain any page that is not used by users, as it may increase the attack surface of the application. Therefore, all unused API routes should be disabled in Node.js applications. This occurs especially in frameworks like [Sails](https://sailsjs.com) and [Feathers](https://feathersjs.com), as they automatically generate REST API endpoints. For example, in [Sails](https://sailsjs.com), if a URL does not match a custom route, it may match one of the automatic routes and still generate a response. This situation may lead to results ranging from information leakage to arbitrary command execution. Therefore, before using such frameworks and modules, it is important to know the routes they automatically generate and remove or disable these routes.

#### Prevent HTTP Parameter Pollution

[HTTP Parameter Pollution(HPP)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.html) is an attack in which attackers send multiple HTTP parameters with the same name and this causes your application to interpret them unpredictably. When multiple parameter values are sent, Express populates them in an array. In order to solve this issue, you can use [hpp](https://www.npmjs.com/package/hpp) module. When used, this module will ignore all values submitted for a parameter in `req.query` and/or `req.body` and just select the last parameter value submitted. You can use it as follows:

```JavaScript
const hpp = require('hpp');
app.use(hpp());
```

#### Only return what is necessary

Information about the users of an application is among the most critical information about the application. User tables generally include fields like id, username, full name, email address, birth date, password and in some cases social security numbers. Therefore, when querying and using user objects, you need to return only needed fields as it may be vulnerable to personal information disclosure. This is also correct for other objects stored on the database. If you just need a certain field of an object, you should only return the specific fields required. As an example, you can use a function like the following whenever you need to get information on a user. By doing so, you can only return the fields that are needed for your specific operation. In other words, if you only need to list names of the users available, you are not returning their email addresses or credit card numbers in addition to their full names.

```JavaScript
exports.sanitizeUser = function(user) {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName
  };
};
```

#### Use object property descriptors

Object properties include three hidden attributes: `writable` (if false, property value cannot be changed), `enumerable` (if false, property cannot be used in for loops) and `configurable` (if false, property cannot be deleted). When defining an object property through assignment, these three hidden attributes are set to true by default. These properties can be set as follows:

```JavaScript
const o = {};
Object.defineProperty(o, "a", {
    writable: true,
    enumerable: true,
    configurable: true,
    value: "A"
});
```

Apart from these, there are some special functions for object attributes. `Object.preventExtensions()` prevents new properties from being added to the object.

#### Use access control lists

Authorization prevents users from acting outside of their intended permissions. In order to do so, users and their roles should be determined with consideration of the principle of least privilege. Each user role should only have access to the resources they must use. For your Node.js applications, you can use the [acl](https://www.npmjs.com/package/acl) module to provide ACL (access control list) implementation. With this module, you can create roles and assign users to these roles.

### Error & Exception Handling

#### Handle uncaughtException

Node.js behavior for uncaught exceptions is to print current stack trace and then terminate the thread. However, Node.js allows customization of this behavior. It provides a global object named process that is available to all Node.js applications. It is an EventEmitter object and in case of an uncaught exception, uncaughtException event is emitted and it is brought up to the main event loop. In order to provide a custom behavior for uncaught exceptions, you can bind to this event. However, resuming the application after such an uncaught exception can lead to further problems. Therefore, if you do not want to miss any uncaught exception, you should bind to uncaughtException event and cleanup any allocated resources like file descriptors, handles and similar before shutting down the process. Resuming the application is strongly discouraged as the application will be in an unknown state. It is important to note that when displaying error messages to the user in case of an uncaught exception, detailed information like stack traces should not be revealed to the user. Instead, custom error messages should be shown to the users in order not to cause any information leakage.

```JavaScript
process.on("uncaughtException", function(err) {
    // clean up allocated resources
    // log necessary error details to log files
    process.exit(); // exit the process to avoid unknown state
});
```

#### Listen to errors when using EventEmitter

When using EventEmitter, errors can occur anywhere in the event chain. Normally, if an error occurs in an EventEmitter object, an error event that has an Error object as an argument is called. However, if there are no attached listeners to that error event, the Error object that is sent as an argument is thrown and becomes an uncaught exception. In short, if you do not handle errors within an EventEmitter object properly, these unhandled errors may crash your application. Therefore, you should always listen to error events when using EventEmitter objects.

```JavaScript
const events = require('events');
const myEventEmitter = function(){
    events.EventEmitter.call(this);
}
require('util').inherits(myEventEmitter, events.EventEmitter);
myEventEmitter.prototype.someFunction = function(param1, param2) {
    //in case of an error
    this.emit('error', err);
}
const emitter = new myEventEmitter();
emitter.on('error', function(err){
    //Perform necessary error handling here
});
```

#### Handle errors in asynchronous calls

Errors that occur within asynchronous callbacks are easy to miss. Therefore, as a general principle first argument to the asynchronous calls should be an Error object. Also, express routes handle errors itself, but it should be always remembered that errors occurred in asynchronous calls made within express routes are not handled, unless an Error object is sent as a first argument.

Errors in these callbacks can be propagated as many times as possible. Each callback that the error has been propagated to can ignore, handle or propagate the error.

### Server Security

#### Set cookie flags appropriately

Generally, session information is sent using cookies in web applications. However, improper use of HTTP cookies can render an application to several session management vulnerabilities. Some flags can be set for each cookie to prevent these kinds of attacks. `httpOnly`, `Secure` and `SameSite` flags are very important for session cookies. `httpOnly` flag prevents the cookie from being accessed by client-side JavaScript. This is an effective counter-measure for XSS attacks. `Secure` flag lets the cookie to be sent only if the communication is over HTTPS. `SameSite` flag can prevent cookies from being sent in cross-site requests that helps protect against Cross-Site Request Forgery (CSRF) attacks. Apart from these, there are other flags like domain, path and expires. Setting these flags appropriately is encouraged, but they are mostly related to cookie scope not the cookie security. Sample usage of these flags is given in the following example:

```JavaScript
const session = require('express-session');
app.use(session({
    secret: 'your-secret-key',
    name: 'cookieName',
    cookie: { secure: true, httpOnly: true, path: '/user', sameSite: true}
}));
```

#### Use appropriate security headers

There are several [HTTP security headers](https://owasp.org/www-project-secure-headers/) that can help you prevent some common attack vectors.
The [helmet](https://www.npmjs.com/package/helmet) package can help to set those headers:

```Javascript
const express = require("express");
const helmet = require("helmet");

const app = express();

app.use(helmet()); // Add various HTTP headers
```

The top-level `helmet` function is a wrapper around 14 smaller middlewares.
Bellow is a list of HTTP security headers covered by `helmet` middlewares:

- **[Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)**: [HTTP Strict Transport Security (HSTS)](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) dictates browsers that the application can only be accessed via HTTPS connections. In order to use it in your application, add the following codes:

```JavaScript
app.use(helmet.hsts()); // default configuration
app.use(
  helmet.hsts({
    maxAge: 123456,
    includeSubDomains: false,
  })
); // custom configuration
```

- **[X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options):** determines if a page can be loaded via a `<frame>` or an `<iframe>` element. Allowing the page to be framed may result in [Clickjacking](https://owasp.org/www-community/attacks/Clickjacking) attacks.

```JavaScript
app.use(helmet.frameguard()); // default behavior (SAMEORIGIN)
```

- **[X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection):** stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. This header has been deprecated by modern browsers and its use can introduce additional security issues on the client side. As such, it is recommended to set the header as **X-XSS-Protection: 0** in order to disable the XSS Auditor, and not allow it to take the default behavior of the browser handling the response.

```JavaScript
app.use(helmet.xssFilter()); // sets "X-XSS-Protection: 0"
```

For moderns browsers, it is recommended to implement a strong **Content-Security-Policy** policy, as detailed in the next section.

- **[Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy):** Content Security Policy is developed to reduce the risk of attacks like [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) and [Clickjacking](https://owasp.org/www-community/attacks/Clickjacking). It allows content from a list that you decide. It has several directives each of which prohibits loading specific type of a content. You can refer to [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) for detailed explanation of each directive and how to use it. You can implement these settings in your application as follows:

```JavaScript
app.use(
  helmet.contentSecurityPolicy({
    // the following directives will be merged into the default helmet CSP policy
    directives: {
      defaultSrc: ["'self'"],  // default value for all directives that are absent
      scriptSrc: ["'self'"],   // helps prevent XSS attacks
      frameAncestors: ["'none'"],  // helps prevent Clickjacking attacks
      imgSrc: ["'self'", "'http://imgexample.com'"],
      styleSrc: ["'none'"]
    }
  })
);
```

As this middleware performs very little validation, it is recommended to rely on CSP checkers like [CSP Evaluator](https://csp-evaluator.withgoogle.com/) instead.

- **[X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options):** Even if the server sets a valid `Content-Type` header in the response, browsers may try to sniff the MIME type of the requested resource. This header is a way to stop this behavior and tell the browser not to change MIME types specified in `Content-Type` header. It can be configured in the following way:

```JavaScript
app.use(helmet.noSniff());
```

- **[Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control) and [Pragma](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma):** Cache-Control header can be used to prevent browsers from caching the given responses. This should be done for pages that contain sensitive information about either the user or the application. However, disabling caching for pages that do not contain sensitive information may seriously affect the performance of the application. Therefore, caching should only be disabled for pages that return sensitive information. Appropriate caching controls and headers can be set easily using the [nocache](https://www.npmjs.com/package/nocache) package:

```JavaScript
const nocache = require("nocache");

app.use(nocache());
```

The above code sets Cache-Control, Surrogate-Control, Pragma and Expires headers accordingly.

- **X-Download-Options:** This header prevents Internet Explorer from executing downloaded files in the site's context. This is achieved with noopen directive. You can do so with the following piece of code:

```JavaScript
app.use(helmet.ieNoOpen());
```

- **[Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT):** Certificate Transparency is a new mechanism developed to fix some structural problems regarding current SSL infrastructure. Expect-CT header may enforce certificate transparency requirements. It can be implemented in your application as follows:

```JavaScript
const expectCt = require('expect-ct');
app.use(expectCt({ maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123, reportUri: 'http://example.com'}));
```

- **X-Powered-By:** X-Powered-By header is used to inform what technology is used in the server side. This is an unnecessary header causing information leakage, so it should be removed from your application. To do so, you can use the `hidePoweredBy` as follows:

```JavaScript
app.use(helmet.hidePoweredBy());
```

Also, you can lie about the technologies used with this header. For example, even if your application does not use PHP, you can set X-Powered-By header to seem so.

```JavaScript
app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }));
```

### Platform Security

#### Keep your packages up-to-date

Security of your application depends directly on how secure the third-party packages you use in your application are. Therefore, it is important to keep your packages up-to-date. It should be noted that [Using Components with Known Vulnerabilities](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities) is still in the OWASP Top 10. You can use [OWASP Dependency-Check](https://jeremylong.github.io/DependencyCheck/analyzers/nodejs.html) to see if any of the packages used in the project has a known vulnerability. Also, you can use [Retire.js](https://github.com/retirejs/retire.js/) to check JavaScript libraries with known vulnerabilities.

Starting with version 6, `npm` introduced `audit`, which will warn about vulnerable packages:

```bash
npm audit
```

`npm` also introduced a simple way to upgrade the affected packages:

```bash
npm audit fix
```

There are several other tools you can use to check your dependencies. A more comprehensive list can be found in [Vulnerable Dependency Management CS](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html#tools).

#### Do not use dangerous functions

There are some JavaScript functions that are dangerous and should only be used where necessary or unavoidable. The first example is the `eval()` function. This function takes a string argument and executes it as any other JavaScript source code. Combined with user input, this behavior inherently leads to remote code execution vulnerability. Similarly, calls to `child_process.exec` are also very dangerous. This function acts as a bash interpreter and sends its arguments to /bin/sh. By injecting input to this function, attackers can execute arbitrary commands on the server.

In addition to these functions, some modules require special care when being used. As an example, `fs` module handles filesystem operations. However, if improperly sanitized user input is fed into this module, your application may become vulnerable to file inclusion and directory traversal vulnerabilities. Similarly, `vm` module provides APIs for compiling and running code within V8 Virtual Machine contexts. Since it can perform dangerous actions by nature, it should be used within a sandbox.

It would not be fair to say that these functions and modules should not be used whatsoever, however, they should be used carefully especially when they use with user input. Also, there are [some other functions](https://github.com/wisec/domxsswiki/wiki/Direct-Execution-Sinks) that may render your application vulnerable.

#### Stay away from evil regexes

The Regular expression Denial of Service (ReDoS) is a Denial of Service attack, that exploits the fact that most Regular Expression implementations may reach extreme situations that cause them to work very slowly (exponentially related to input size). An attacker can then cause a program using a Regular Expression to enter these extreme situations and then hang for a very long time.

[The Regular Expression Denial of Service (ReDoS)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) is a type of Denial of Service attack that uses regular expressions. Some Regular Expression (Regex) implementations cause extreme situations that makes the application very slow. Attackers can use such regex implementations to cause application to get into these extreme situations and hang for a long time.  Such regexes are called evil if application can be stuck on crafted input.  Generally, these regexes are exploited by grouping with repetition and alternation with overlapping. For example, the following regular expression `^(([a-z])+.)+[A-Z]([a-z])+$` can be used to specify Java class names. However, a very long string (aaaa...aaaaAaaaaa...aaaa) can also match with this regular expression. There are some tools to check if a regex has a potential for causing denial of service. One example is [vuln-regex-detector](https://github.com/davisjam/vuln-regex-detector).

#### Run security linters

When developing code, keeping all security tips in mind can be really difficult. Also, keeping all team members obey these rules is nearly impossible. This is why there are Static Analysis Security Testing (SAST) tools. These tools do not execute your code, but they simply look for patterns that can contain security risks. As JavaScript is a dynamic and loosely-typed language, linting tools are really essential in the software development life cycle. The linting rules should be reviewed periodically and the findings should be audited. Another advantage of these tools is the feature that you can add custom rules for patterns that you may see dangerous. [ESLint](https://eslint.org/) and [JSHint](http://jshint.com/) are commonly used SAST tools for JavaScript linting.

#### Use strict mode

JavaScript has a number of unsafe and dangerous legacy features that should not be used. In order to remove these features, ES5 included a strict mode for developers. With this mode, errors that were silent previously are thrown. It also helps JavaScript engines perform optimizations. With strict mode, previously accepted bad syntax causes real errors. Because of these improvements, you should always use strict mode in your application. In order to enable strict mode, you just need to write `"use strict";` on top of your code.

The following code will generate a `ReferenceError: Can't find variable: y` on the console, which will not be displayed unless strict mode is used:

```JavaScript
"use strict";

func();
function func() {
  y = 3.14;   // This will cause an error (y is not defined)
}
```

#### Adhere to general application security principles

This list mainly focuses on issues that are common in Node.js applications, with recommendations and examples. In addition to these, there are general [security by design principles](https://wiki.owasp.org/index.php/Security_by_Design_Principles) that apply to web applications regardless of technologies used in application server. You should also keep those principles in mind while developing your applications. You can always refer to [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) to learn more about web application vulnerabilities and mitigation techniques used against them.

## Additional resources about Node.js security

[Awesome Node.js Security resources](https://github.com/lirantal/awesome-nodejs-security)
