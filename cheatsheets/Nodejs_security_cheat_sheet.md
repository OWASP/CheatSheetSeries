# Introduction

This cheat sheet lists the things one can use when developing secure Node.js applications. Each item has a brief explanation and solution that is specific to Node.js environment.

# Context

Node.js applications are increasing in number and they are no different from other frameworks and programming languages. Node.js applications are also prone to all kinds of web application vulnerabilities.

# Objective

This cheat sheet aims to provide a list of best practices to follow during development of Node.js applications.

# Proposition

## Keep your packages up-to-date

Security of your application depends directly on how secure the third-party packages you use in your application are. Therefore, it is important to keep your packages up-to-date. It should be noted that [Using Components with Known Vulnerabilities](https://www.owasp.org/index.php/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities) is still in the OWASP Top 10. You can use [OWASP Dependency-Check](https://jeremylong.github.io/DependencyCheck/analyzers/nodejs.html) to see if any of the packages used in the project has a knwon vulnerability. Also you can use [Retire.js](https://github.com/retirejs/retire.js/) to check JavaScript libraries with known vulnerabilities. In order to use it, you can run the following commands in the source code folder of your application:

```bash
npm install -g retire
retire
```

## Use appropriate security headers

There are several different HTTP headers that can help you prevent some common attack vectors. These are listed below:

- **Strict-Transport-Security**: [HTTP Strict Transport Security (HSTS)](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) dictates browsers that the application can only be accessed via HTTPS connections. This header takes two parameters:  `max-age` to determine how long this configuration will be valid and `includeSubDomains` to state if subdomains are to be treated in the same way. In order to use it in your application, add the following codes:

```JavaScript
app.use(helmet.hsts()); // default configuration
app.use(helmet.hsts("<max-age>", "<includeSubdomains>")); // custom configuration
```

- **X-Frame-Options:** determines if a page can be loaded via a \<frame> or an \<iframe> element. Allowing the page to be framed may result in clickjacking attacks which aims to manipulate users into clicking on a different element instead of the one they intend to. This header has 3 directives: DENY to never allow framing, SAMEORIGIN to only allow framing within the same origin and ALLOW-FROM to only allow framing from specified URIs. These behaviors can be achieved with helmet module as follows:

```JavaScript
app.use(hemlet.xframe()); // default behavior (DENY)
helmet.xframe(‘sameorigin’); // SAMEORIGIN
helmet.xframe(‘allow-from’, ‘http://alloweduri.com’); //ALLOW-FROM uri
```

- **X-XSS-Protection:** As described in [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#bonus-rule-4-use-the-x-xss-protection-response-header), this header enables browsers to stop loading pages when browsers detect reflected cross-site scripting attacks. In order to implement this header in your application, you can use the following code:

```JavaScript
var xssFilter = require('x-xss-protection');
app.use(xssFilter());
```

- **X-Content-Type-Options:** Even if the server sets a valid Content-Type header in the response, browsers may try to sniff the MIME type of the requested resource. This header is a way to stop this behavior and tell the browser not to change MIME types specified in Content-Type header. It can be configured in the following way:

```JavaScript
app.use(helmet.noSniff());
```

- **Content-Security-Policy:** Content Security Policy is developed to reduce the risk of attacks like XSS and Clickjacking. Basically, it allows content from a whitelist you decide. Other content from different sources is not accepted if Content-Security-Policy headers are set correctly. It has several directives each of which prohibits loading specific type of a content. These are `connect-src`, `font-src`, `frame-src`, `img-src`, `media-src`, `object-src`, `script-src`, `style-src` and `default-src`. These can be assigned to self, none, unsafe-inline or unsafe-eval. You can implement these settings in your application as follows:

```JavaScript
const csp = require('helmet-csp')
app.use(csp({
   directives: {
       scriptSrc: ["'self'", "'unsafe-inline'"],   // helps prevent XSS attacks
       frame-ancestors: ["'none'"],  // helps prevent Clickjacking attacks
       img-src: ["'self'", "'http://imgexample.com'"],
       style-src: ["'none'"]
    }
}))
```

Also for further information on the usage of CSP directives, you can always refer to the [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).

- **Cache-Control and Pragma:** Cache-Control header can be used to prevent browsers from caching the given responses. This should be done for pages which contains sensitive information about either the user or the application. However, disabling caching for pages that do not contain sensitive information may seriously affect the performance of the application. Therefore, caching should only be disabled for pages that return sensitive information. Appropriate caching controls and headers can be used easily by the following code:

```JavaScript
app.use(helmet.noCache());
```

The above code sets Cache-Control, Surrogate-Control, Pragma and Expires headers accordingly.

- **X-Download-Options:** This header prevents Internet Explorer from executing downloaded files in the site’s context. This is achieved with noopen directive. You can do so with the following piece of code:

```JavaScript
app.use(helmet.ieNoOpen());
```

- **Expect-CT:** Certificate Transparency is a new mechanism developed to fix some structural problems regarding current SSL infrastructure. It has three directives. The `enforce` directive dictates if the policy should be enforced or be used in report-only mode. The `max-age` directive specifies how long this setting will be valid. Finally, the `report-uri` directive specifies where the browser should send invalid CT information reports. These can be implemented in your application as follows:

```JavaScript
var expectCt = require(‘expect-ct’);
app.use(expectCt({ maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123, reportUri: ‘http://example.com’}));
```

- **Public-Key-Pins:** This header increases the security of HTTPS. With this header, a specific cryptographic public key is associated with a specific web server. If the server does not use the pinned keys in future, the browser regards the responses as illegitimate. It has 2 optional (`reportUri`, `includeSubDomains`) and 2 required (`pin-sha256`, `max-age`) directives. These can be used as follows:

```JavaScript
app.use(helmet.hpkp({
    maxAge: 123,
    sha256s: [‘Ab3Ef123=’, ‘ZyxawuV45=’],
    reportUri: ‘http://example.com’,
    includeSubDomains: true
}));
```

As discussed in [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html#consider-using-public-key-pinning), the decision to use public key pinning should be made with careful consideration, since it may cause locking out users for a long time if used incorrectly.

- **X-Powered-By:** X-Powered-By header is used to inform what technology is used in the server side. This is an unnecessary header causing information leakage, so it should be removed from your application. To do so, you can use the `hidePoweredBy` as follows:

```JavaScript
app.use(helmet.hidePoweredBy());
```

Also, you can lie about the technologies used with this header. For example, even if your application does not use PHP, you can set X-Powered-By header to seem so.

```JavaScript
app.use(helmet.hidePoweredBy({ setTo: ‘PHP 4.2.0’ }));
```

## Take precautions against brute-forcing

Brute-forcing is a common threat to all web applications. Attackers can use brute-forcing as a password guessing attack to obtain account passwords. Therefore, application developers should take precautions against brute-force attacks especially in login pages.  Node.js has several modules available for this purpose. Here is the express-bouncer module and its simple usage:

```JavaScript
var bouncer = require(‘express-bouncer’);
bouncer.whitelist.push(‘127.0.0.1’); // whitelist an IP address
// give a custom error message
bouncer.blocked = function (req, res, next, remaining) {
    res.send(429, “Too many requests have been made. Please wait “ + remaining/1000 + “ seconds.”);
};
// route to protect
app.post(“/login”, bouncer.block, function(req, res) {
    if (LoginFailed){  }
    else {
        bouncer.reset( req );
    }
});
```

Apart from express-bouncer modules, there are several other modules that aims to mitigate brute-forcing. Ratelimiter and express-brute are examples of these modules.
CAPTCHA usage is also another common mechanism used against brute-forcing. There are modules developed for Node.js CAPTCHAs. A common module used in Node.js applications is svg-captcha. It can be used as follows:

```JavaScript
var svgCaptcha = require(‘svg-captcha’);
app.get(‘/captcha’, function (req, res) {
    var captcha = svgCaptcha.create();
    req.session.captcha = captcha.text;
    res.type(‘svg’);
    res.status(200).send(captcha.data);
});
```

Also, account lockout is a recommended solution to keep attackers away from your valid users. Account lockout is possible with many modules like mongoose. You can refer to [this blog post](http://devsmash.com/blog/implementing-max-login-attempts-with-mongoose) to see how account locking is implemented in mongoose.

## Set cookie flags appropriately

Generally, session information is sent over cookies in web applications. However, the usage of cookies can eliminate some attack vectors related to session management. There are some flags that can be set for each cookie. For session cookies, httpOnly, Secure and SameSite flags are very important. httpOnly flag prevents the cookie from being accessed by client-side JavaScript. This is an effective counter-measure for XSS attacks. Secure flag lets the cookie to be sent only if the communication is over HTTPS. SameSite flag can prevent cookies from being sent in cross-site requests which helps protect against Cross-Site Request Forgery (CSRF) attacks. Apart from these, there are other flags like domain, path and expires. Setting these flags appropriately is encouraged, but they are mostly related to cookie scope not the cookie security. Sample usage of these flags is given in the following example:

```JavaScript
var session = require(‘express-session’);
app.use(session({
    secret: ‘your-secret-key’,
    key: ‘cookieName’,
    cookie: { secure: true, httpOnly: true, path: ‘/user’, sameSite: true}
}));
```

## Use Anti-CSRF tokens

Cross-Site Request Forgery (CSRF) aims to perform authorized actions on behalf of an authenticated user, while the user is unaware of this action. CSRF attacks are generally performed for state-changing requests like password change, adding users or placing orders. Csurf is an express middleware that can be used to mitigate CSRF attacks. It can be used as follows:

```JavaScript
var csrf = require(‘csurf’);
csrfProtection = csrf({ cookie: true });
app.get(‘/form’, csrfProtection, function(req, res) {
    res.render(‘send’, { csrfToken: req.csrfToken() })
})
app.post(‘/process’, parseForm, csrfProtection, function(req, res) {
    res.send(‘data is being processed’);
});
```

After writing this code, you also need to add csrfToken to your HTML form, which can be easily done as follows:

```JavaScript
<input type=”hidden” name=”_csrf” value=”{{ csrfToken }}”>
```

## Do not use dangerous functions

There are some JavaScript functions that are too dangerous to use. To the fullest possible extent, use of such functions and modules should be avoided. The first example is the eval() function. This function takes a string argument and executes it as any other JavaScript source code. This behavior inherently leads to remote code execution vulnerability. Similarly, calls to child_process.exec are also very dangerous. This function acts as a bash interpreter and sends its arguments to /bin/sh. By injecting input to this function, attackers can execute arbitrary commands on the server. Therefore, its use is highly discouraged.

In addition to these functions, there are some modules that require special attention when being used. As an example, fs module handles filesystem operations. However, if improperly sanitized user input is fed into this module, your server’s content can be tampered. Similarly, vm module provides APIs for compiling and running code within V8 Virtual Machine contexts. Since it can perform dangerous actions by nature, it should be used within a sandbox.

## Stay away from evil regexes

Denial of Service (DoS) attack aims to make one or more of an application’s resources or services unavailable for its legitimate users. Some Regular Expression (Regex) implementations cause extreme situations that makes the application very slow. Attackers can use such regex implementations to cause application to get into these extreme situations and hang for a long time.  Such regexes are called evil if application can be stuck on crafted input.  Generally, these regexes are exploited by grouping with repetition and alternation with overlapping. (a+)+, (a|a?)+ are some examples of evil regexes. Fortunately, there is a Node.js module that can be used to check if a specific regex is evil or not. However, as it is stated in the module’s Github page, you cannot “be absolutely sure that this module will catch all exponential-time cases”. Its usage is as simple as follows:

```JavaScript
node safe.js <regex>
node safe.js '(x+x+)+y'
```

## Remove unnecessary routes

A web application should not contain any page that is not used by users. Leaving such pages on the website can bring advantage to attackers. Such pages may increase the attack surface of the application. This principle is also valid for Node.js applications. All unused API routes should be disabled in Node.js applications. This occurs especially in frameworks like Sails and Feathers, as they automatically generate REST API endpoints. For example, in Sails, if a URL does not match a custom route, it may match one of the automatic routes and still generate a response. This situation may lead to results ranging from information leakage to arbitrary command execution. Therefore, before using such frameworks and modules, it is important to know the routes they automatically generate and remove or disable these routes.

## Check authorization at each step

Authentication does not suffice to say an application is secure. Malicious users can still go through authentication and perform malicious activities in the application. In every application, principle of least privilege should be followed and regarding roles and users must be determined. Each user role should have access to the resources they must use. For your Node.js applications, you can use acl module to provide ACL (access control list) implementation. With this module, you can create roles and assign users to these roles.

## Do not block the event loop

Node.js is very different from common application platforms that use threads. Node.js has a single-thread event-driven architecture. By means of this architecture, throughput becomes high and programming model becomes simpler. Node.js is implemented around a non-blocking I/O event loop. With this event loop, there is no waiting on I/O or context switching. The event loop looks for events and dispatches them to handler functions. Because of this, when CPU intensive JavaScript operations are done, the event loop waits for them to finish. This is why such operations are called blocking. To overcome this problem, Node.js allows assigning callbacks to IO-blocked events. This way, the main application is not blocked and callbacks run asynchronously. Therefore, as a general principle, all blocking operations should be done asynchronously so that the event loop is not blocked.

Even if you perform blocking operations asynchronously, it is still possible that your application may not serve as expected. This happens if there is a code outside the callback which relies on the code within the callback to run first. For example, consider the following code:

```JavaScript
const fs = require(‘fs’);
fs.readFile(‘/file.txt’, (err, data) => {
  // perform actions on file content
});
fs.unlinkSync(‘/file.txt’);
```

In the above example, unlinkSync function may run before the callback, which will delete the file before the desired actions on the file content is done. Such race conditions can also impact the security of your application. An example would be a scenario where authentication is performed in callback and authenticated actions are run synchronously. In order to eliminate such race conditions, you can write all operations that rely on each other in a single non-blocking function. By doing so, you can guarantee that all operations are executed in the correct order.

## Prevent HTTP Parameter Pollution

HTTP Parameter Pollution(HPP) is an attack in which attackers send multiple HTTP parameters with the same name and this causes your application to interpret them in an unpredictable way. When multiple parameter values are sent, Express populates them in an array. In order to solve this issue, you can use hpp module. This module puts array parameters in req.query and/or req.body aside and just selects the last parameter value. You can use it as follows:

```JavaScript
var hpp = require('hpp');
app.use(hpp());
```

## Prefer certified modules

Security of a Node.js application depends on security of packages it makes use of. Therefore, packages should be chosen after a careful inspection. Because, a vulnerability in one of these packages may make your application open to any attacker. In order to use packages securely, you first need to know which packages you need to use and see if there are other packages installed apart from them. You should do this periodically, since your code changes in time and that may make some previously required packages unnecessary. Also, it is important to check if the package you are about to use is commonly used within Node.js developers. If a package is preferred by most developers, chance to find a security whole in the package and fix it also increases. You can use the download rate of packages, which can be seen using npm-stat.com, to decide whether to use them or not. Another indication for a good package candidate is the last time it was updated. The more often a package is updated, the more secure it becomes.  

A better way to ensure security of your packages is to use certified modules. [NodeSource](https://github.com/nodesource/certified) provides packages that are monitored for security vulnerabilities. It provides a trust score for each package. This can be a good strategy when choosing third-party packages.

## Run security linters periodically

When developing code, keeping all security tips in mind can be really difficult. Also keeping all team members obey these rules is nearly impossible. This is why there are Static Analysis Security Testing (SAST) tools. These tools do not execute your code, but they simply look for patterns that can contain security risks. As JavaScript is a dynamic and loosely-typed language, linting tools are really essential in the software development life cycle. These tools should be run periodically and the findings should be audited. Another advantage of these tools is the feature that you can add custom rules for patterns that you may see dangerous. [ESLint](https://eslint.org/) and [JSHint](http://jshint.com/) are commonly used SAST tools for JavaScript linting.

## Use flat Promise chains

Asynchronous callback functions are one of the strongest features of Node.js. However, increasing layers of nesting within callback functions can become a problem. Any multistage process can become nested 10 or more levels deep. This problem is called as Pyramid of Doom or Callback Hell. In such a code, the errors and results get lost within the callback. Promises are a good way to write asynchronous code without getting into nested pyramids. Promises provide top-down execution while being asynchronous by delivering errors and results to next .then function. Another advantage of Promises is the way Promises handle the errors. If an error occurs in a Promise class, it skips over the .then functions and invokes the first .catch function it finds. This way Promises bring a higher assurance of capturing and handling errors. As a principle, you can make all your asynchronous code(apart from emitters) return promises. However, it should be noted that Promise calls can also become a pyramid. In order to completely stay away from callback hells, flat Promise chains should be used. If the module you are using does not support Promises, you can convert base object to a Promise by using Promise.promisifyAll() function.

## Return sanitized user objects

Information about the users of an application is among the most critical information about the application. Therefore, user information should be stored on a different database. User tables generally include fields like id, username, full name, email address, birth date, credit card number and in some cases social security numbers. Therefore, when querying and using user objects, you need to return only needed fields as it may be vulnerable to personal information disclosure. This is also correct for other objects stored on the database. If you just need a certain field of an object, you should never return it with all of its fields. As an example, you can use a function like the following whenever you need to get information on a user. By doing so, you can only return the fields that are needed for your specific operation. In other words, if you only need to list names of the users available, you are not returning their email addresses or credit card numbers in addition to their full names.

```JavaScript
exports.sanitizeUser = function(user) {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName
  };
};
```

## Set request size limits

Buffering and parsing of request bodies can be cumbersome for the server. If there is no limit on the size of requests, attackers can send request with large request bodies so that they can exhaust server memory or fill disk space. However, fixing a request size limit for all requests may not be the correct behavior, since some requests like those for uploading a file to the server have more content to carry on the request body. Also, input with a JSON type is more dangerous than a multipart input, since parsing JSON is a blocking operation. Therefore, you should set request size limits for different content types. You can accomplish this very easily with express middlewares as follows:

```JavaScript
app.use(express.urlencoded({ limit: “1kb” }));
app.use(express.json({ limit: “1kb” }));
app.use(express.multipart({ limit:”10mb” }));
app.use(express.limit(“5kb”)); // this will be valid for every other content type
```

## Use strict mode

JavaScript has some unsafe features that lies within the language itself. In order to remove these features, ES5 included a strict mode for developers. With this mode, errors that were silent previously are thrown. It also restricted optimizations for JavaScript engines. With strict mode, previously accepted bad syntax causes real errors. use "use strict". Because of these improvements, you should always use strict mode in your application. In order to enable strict mode, you just need to write _‘use strict’;_ on top of your code.

## Use object property descriptors

Object properties include 3 hidden attributes: writable (if false, property value cannot be changed), enumerable (if false, property cannot be used in for loops) and configurable (if false, property cannot be deleted). When defining an object property through assignment, these three hidden attributes are set to true by default. These properties can be set as follows:

```JavaScript
var o = {};
Object.defineProperty(o, “a”, {
    writable: true,
    enumerable: true,
    configurable: true,
    value: “A”
});
```

Apart from these, there are some special functions for object attributes. Object.preventExtensions() prevents new properties from being added to the object.

## Handle errors in asynchronous calls

Errors that occur within asynchronous callbacks can be easily forgettable. Therefore, as a general principle first argument to the asynchronous calls should be an Error object. Also, express routes handle errors itself, but it should be always remembered that errors occurred in asynchronous calls made within express routes are not handled, unless an Error object is sent as a first argument.

Errors in these callbacks can be propagated as many times as possible. Each callback that the error has been propagated to can ignore, handle or propagate the error.

## Listen to errors when using EventEmitter

When using EventEmitter, errors can occur anywhere in the event chain. Normally, if an error occurs in an EventEmitter object, an error event with an Error object as its argument is called. However, if there are no attached listeners to that error event, the Error object that is sent as argument is thrown and becomes an uncaught exception. In short, if you do not handle errors within an EventEmitter object properly, these unhandled errors may crash your application. Therefore, you should always listen to error events when using EventEmitter objects.

```JavaScript
var events = require(‘events’);
var myEventEmitter = function(){
    events.EventEmitter.call(this);
}
require(‘util’).inherits(myEventEmitter, events.EventEmitter);
myEventEmitter.prototype.someFunction = function(param1, param2) {
    //in case of an error
    this.emit(‘error’, err);
}
var emitter = new myEventEmitter();
emitter.on(‘error’, function(err){
    //Perform necessary error handling here
});
```

## Handle uncaughtException

Node.js behavior for uncaught exceptions is to print current stack trace and then terminate the thread. However, Node.js allows customization of this behavior. It provides a global object named process which is available to all Node.js applications. It is an EventEmitter object  and in case of an uncaught exception, “uncaughtException” event gets emitted and it is brought up to the main event loop. In order to provide a custom behavior for uncaught exceptions, you can bind to this event. However, resuming the application after such an uncaught exception can lead to further problems. Therefore, if you do not want to miss any uncaught exception, you should bind to uncaughtException event and cleanup any allocated resources like file descriptors, handles and similar before shutting down the process. Resuming the application is strongly discouraged as the application will be in an unknown state.

```JavaScript
process.on(“uncaughtException”, function(err) {
    // clean up allocated resources
    // log necessary error details to log files
    process.exit(); // exit the process to avoid unknown state
});
```

## Monitor the event loop

When your application server is under heavy network traffic, it may not be able to serve its users. This is essentially a type of Denial of Service (DoS) attack. Toobusy module allows you to monitor the event loop. It keeps track of lags and when it goes beyond a certain threshold, this module can indicate your server is too busy. In that case, you can stop processing incoming requests and send them 503 Server Too Busy message so that your application stay responsive. Sample use of toobusy module is shown here:

```JavaScript
var toobusy = require(‘toobusy’);
var express = require(‘express’);
var app = express();
app.use(function(req, res, next) {
    if (toobusy()) {
        // log if you see necessary
        res.send(503, “Server Too Busy”);
    } else {
    next();
    }
});
```

## Perform application activity logging

Logging application activity is an encouraged good practice. It makes it easier to debug any errors encountered during application runtime. It is also useful for security concerns, since it can be used during incident response. Also, these logs can be used to feed Intrusion Detection/Prevention Systems (IDS/IPS). In Node.js, there are some modules like Winston or Bunyan to perform application activity logging. These modules enable streaming and querying logs. Also, they provide a way to handle uncaught exceptions. With the following code, you can log application activities in both console and a desired log file.

```JavaScript
var logger = new (Winston.Logger) ({
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: ‘application.log’ })
    ],
    level: ‘verbose’
});
```

Also, you can provide different transports so that you can save errors to a separate log file and general application logs to a different log file.

## Perform input validation

Input validation is a crucial part of application security. Input validation failures can result in many different types of application attacks. These include SQL Injection, Cross-Site Scripting, Command Injection, Local/Remote File Inclusion, Denial of Service, Directory Traversal, LDAP Injection and many other injection attacks. In order to avoid these attacks, input to your application should be sanitized first. The best input validation technique is to use a white list of accepted inputs. However, if this is not possible, input should be first checked against expected input scheme and dangerous inputs should be escaped. In order to ease input validation in Node.js applications, there are some modules like validator and mongo-express-sanitize. Also, you should escape all HTML and JavaScript content shown to users via application. You can use [escape-html](https://github.com/component/escape-html) or [node-esapi](https://github.com/ESAPI/node-esapi) libraries to perform output escaping.

## Adhere to general application security principles

This list has mainly focused on issues that are common in Node.js applications. Also, recommendations against these issues are given specific to Node.js environment. Apart from these, there are general principles that apply to web applications regardless of technologies used in application server. You should also keep those principles in mind while developing your applications. A very good reference document on these principles is developed and maintained by OWASP. You can always refer to [OWASP Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet) to learn about vulnerabilities that may exist in your application.
