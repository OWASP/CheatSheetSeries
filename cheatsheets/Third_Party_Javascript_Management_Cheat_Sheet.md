# Third Party JavaScript Management Cheat Sheet

## Introduction

Tags, aka marketing tags, analytics tags etc. are small bits of JavaScript on a web page. They can also be HTML image elements when JavaScript is disabled. The reason for them is to collect data on the web user actions and browsing context for use by the web page owner in marketing.

Third party vendor JavaScript tags (hereinafter, **tags**) can be divided into two types:

- User interface tags.
- Analytic tags.

User interface tags have to execute on the client because they change the DOM; displaying a dialog or image or changing text etc.

Analytics tags send information back to a marketing information database; information like what user action was just taken, browser metadata, location information, page metadata etc. The rationale for analytics tags is to provide data from the user's browser DOM to the vendor for some form of marketing analysis. This data can be anything available in the DOM. The data is used for user navigation and clickstream analysis, identification of the user to determine further content to display etc., and various marketing analysis functions.

The term **host** refers to the original site the user goes to, such as a shopping or news site, that contains or retrieves and executes third party JavaScript tag for marketing analysis of the user actions.

## Major risks

The single greatest risk is a compromise of the third party JavaScript server, and the injection of malicious JavaScript into the original tag JavaScript. This has happened in 2018 and likely earlier.

The invocation of third-party JS code in a web application requires consideration for 3 risks in particular:

1. The loss of control over changes to the client application,
2. The execution of arbitrary code on client systems,
3. The disclosure or leakage of sensitive information to 3rd parties.

### Risk 1: Loss of control over changes to the client application

This risk arises from the fact that there is usually no guaranty that the code hosted at the third-party will remain the same as seen from the developers and testers: new features may be pushed in the third-party code at any time, thus potentially breaking the interface or data-flows and exposing the availability of your application to its users/customers.

Typical defenses include, but are not restricted to: in-house script mirroring (to prevent alterations by 3rd parties), sub-resource integrity (to enable browser-level interception) and secure transmission of the third-party code (to prevent modifications while in-transit). See below for more details.

### Risk 2: Execution of arbitrary code on client systems

This risk arises from the fact that third-party JavaScript code is rarely reviewed by the invoking party prior to its integration into a website/application. As the client reaches the hosting website/application, this third-party code gets executed, thus granting the third-party the exact same privileges that were granted to the user (similar to [XSS attacks](https://owasp.org/www-community/attacks/xss/)).

Any testing performed prior to entering production loses some of its validity, including `AST testing` ([IAST](https://www.veracode.com/security/interactive-application-security-testing-iast), [RAST](https://www.veracode.com/sites/default/files/pdf/resources/whitepapers/what-is-rasp.pdf), [SAST](https://www.sqreen.com/web-application-security/what-is-sast), [DAST](https://www.sqreen.com/web-application-security/what-is-dast), etc.).

While it is widely accepted that the probability of having rogue code intentionally injected by the third-party is low, there are still cases of malicious injections in third-party code after the organization's servers were compromised (ex: Yahoo, January 2014).

This risk should therefore still be evaluated, in particular when the third-party does not show any documentation that it is enforcing better security measures than the invoking organization itself, or at least equivalent. Another example is that the domain hosting the third-party JavaScript code expires because the company maintaining it is bankrupt or the developers have abandoned the project. A malicious actor can then re-register the domain and publish malicious code.

Typical defenses include, but are not restricted to:

- In-house script mirroring (to prevent alterations by 3rd parties),
- [Sub-resource integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) (to enable browser-level interception),
- Secure transmission of the third-party code (to prevent modifications while in-transit) and various types of sandboxing. See below for more details.
- ...

### Risk 3: Disclosure of sensitive information to 3rd parties

When a third-party script is invoked in a website/application, the browser directly contacts the third-party servers. By default, the request includes all regular HTTP headers. In addition to the originating IP address of the browser, the third-party also obtains other data such as the referrer (in non-https requests) and any cookies previously set by the 3rd party, for example when visiting another organization's website that also invokes the third-party script.

In many cases, this grants the third-party primary access to information on the organization's users / customers / clients. Additionally, if the third-party is sharing the script with other entities, it also collects secondary data from all the other entities, thus knowing who the organization's visitors are but also what other organizations they interact with.

A typical case is the current situation with major news/press sites that invoke third-party code (typically for ad engines, statistics and JavaScript APIs): any user visiting any of these websites also informs the 3rd parties of the visit. In many cases, the third-party also gets to know what news articles each individual user is clicking specifically (leakage occurs through the HTTP referrer field) and thus can establish deeper personality profiles.

Typical defenses include, but are not restricted to: in-house script mirroring (to prevent leakage of HTTP requests to 3rd parties). Users can reduce their profiling by random clicking links on leaking websites/applications (such as press/news websites) to reduce profiling. See below for more details.

## Third-party JavaScript Deployment Architectures

There are three basic deployment mechanisms for **tags**. These mechanisms can be combined with each other.

### Vendor JavaScript on page

This is where the vendor provides the host with the JavaScript and the host puts it on the host page. To be secure the host company must review the code for any vulnerabilities like [XSS attacks](https://owasp.org/www-community/attacks/xss/) or malicious actions such as sending sensitive data from the DOM to a malicious site. This is often difficult because the JavaScript is commonly obfuscated.

```html
<!-- Some host, e.g. foobar.com, HTML code here -->
<html>
<head></head>
    <body>
        ...
        <script type="text/javascript">/* 3rd party vendor javascript here */</script>
    </body>
</html>
```

### JavaScript Request to Vendor

This is where one or a few lines of code on the host page each request a JavaScript file or URL directly from the vendor site. When the host page is being created, the developer includes the lines of code provided by the vendor that will request the vendor JavaScript. Each time the page is accessed the requests are made to the vendor site for the javascript, which then executes on the user browser.

```html
<!-- Some host, e.g. foobar.com, HTML code here -->`
<html>
    <head></head>
    <body>
        ...
        <!-- 3rd party vendor javascript -->
        <script src="https://analytics.vendor.com/v1.1/script.js"></script>
        <!-- /3rd party vendor javascript -->
    </body>
</html>
```

### Indirect request to Vendor through Tag Manager

This is where one or a few lines of code on the host page each request a JavaScript file or URL from a tag aggregator or **tag manager** site; not from the JavaScript vendor site. The tag aggregator or tag manager site returns whatever third party JavaScript files that the host company has configured to be returned. Each file or URL request to the tag manager site can return lots of other JavaScript files from multiple vendors.

The actual content that is returned from the aggregator or manager (i.e. the specific JavaScript files as well as exactly what they do) can be dynamically changed by host site employees using a graphical user interface for development, hosted on the tag manager site that non-technical users can work with, such as the marketing part of the business.

The changes can be either:

1. Get a different JavaScript file from the third-party vendor for the same request.
2. Change what DOM object data is read, and when, to send to the vendor.

The tag manager developer user interface will generate code that does what the marketing functionality requires, basically determining what data to get from the browser DOM and when to get it. The tag manager always returns a **container** JavaScript file to the browser which is basically a set of JavaScript functions that are used by the code generated by the user interface to implement the required functionality.

Similar to java frameworks that provide functions and global data to the developer, the container JavaScript executes on the browser and lets the business user use the tag manager developer user interface to specify high level functionality without needing to know JavaScript.

```html
<!-- Some host, e.g. foobar.com, HTML code here -->
 <html>
   <head></head>
     <body>
       ...
       <!-- Tag Manager -->
       <script>(function(w, d, s, l, i){
         w[l] = w[l] || [];
         w[l].push({'tm.start':new Date().getTime(), event:'tm.js'});
         var f = d.getElementsByTagName(s)[0],
         j = d.createElement(s),
         dl = l != 'dataLayer' ? '&l=' + l : '';
         j.async=true;
         j.src='https://tagmanager.com/tm.js?id=' + i + dl;
         f.parentNode.insertBefore(j, f);
       })(window, document, 'script', 'dataLayer', 'TM-FOOBARID');</script>
       <!-- /Tag Manager -->
   </body>
</html>`
```

#### Security Problems with requesting Tags

The previously described mechanisms are difficult to make secure because you can only see the code if you proxy the requests or if you get access to the GUI and see what is configured. The JavaScript is generally obfuscated so even seeing it is usually not useful. It is also instantly deployable because each new page request from a browser executes the requests to the aggregator which gets the JavaScript from the third party vendor. So as soon as any JavaScript files are changed on the vendor, or modified on the aggregator, the next call for them from any browser will get the changed JavaScript. One way to manage this risk is with the *Subresource Integrity* standard described below.

### Server Direct Data Layer

The tag manager developer user interface can be used to create JavaScript that can get data from anywhere in the browser DOM and store it anywhere on the page. This can allow vulnerabilities because the interface can be used to generate code to get unvalidated data from the DOM (e.g. URL parameters) and store it in some page location that would execute JavaScript.

The best way to make the generated code secure is to confine it to getting DOM data from a host defined data layer.

The data layer is either:

1. a DIV object with attribute values that have the marketing or user behavior data that the third-party wants
2. a set of JSON objects with the same data. Each variable or attribute contains the value of some DOM element or the description of a user action. The data layer is the complete set of values that all vendors need for that page. The data layer is created by the host developers.

When specific events happen that the business has defined, a JavaScript handler for that event sends values from the data layer directly to the tag manager server. The tag manager server then sends the data to whatever third party or parties is supposed to get it. The event handler code is created by the host developers using the tag manager developer user interface. The event handler code is loaded from the tag manager servers on every page load.

**This is a secure technique** because only your JavaScript executes on your users browser, and only the data you decide on is sent to the vendor.

This requires cooperation between the host, the aggregator or tag manager and the vendors.

The host developers have to work with the vendor in order to know what type of data the vendor needs to do their analysis. Then the host programmer determines what DOM element will have that data.

The host developers have to work with the tag manager or aggregator to agree on the protocol to send the data to the aggregator: what URL, parameters, format etc.

The tag manager or aggregator has to work with the vendor to agree on the protocol to send the data to the vendor: what URL, parameters, format etc. Does the vendor have an API?

## Security Defense Considerations

### Server Direct Data Layer

The server direct mechanism is a good security standard for third party JavaScript management, deployment and execution. A good practice for the host page is to create a data layer of DOM objects.

The data layer can perform any validation of the values, especially values from DOM objects exposed to the user like URL parameters and input fields, if these are required for the marketing analysis.

An example statement for a corporate standard document is 'The tag JavaScript can only access values in the host data layer. The tag JavaScript can never access a URL parameter.

You the host page developer have to agree with the third-party vendors or the tag manager what attribute in the data layer will have what value so they can create the JavaScript to read that value.

User interface tags cannot be made secure using the data layer architecture because their function (or one of their functions) is to change the user interface on the client, not to send data about the user actions.

Analytics tags can be made secure using the data layer architecture because the only action needed is to send data from the data layer to the third party. Only first party code is executed; first to populate the data layer (generally on page load); then event handler JavaScript sends whatever data is needed from that page to the third party database or tag manager.

This is also a very scalable solution. Large ecommerce sites can easily have hundreds of thousands of URL and parameter combinations, with different sets of URLs and parameters being included in different marketing analysis campaigns. The marketing logic could have 30 or 40 different vendor tags on a single page.

For example user actions in pages about specified cities, from specified locations on specified days should send data layer elements 1, 2 and 3. User actions in pages about other cities should send data layer elements 2 and 3 only. Since the event handler code to send data layer data on each page is controlled by the host developers or marketing technologists using the tag manager developer interface, the business logic about when and what data layer elements are sent to the tag manager server, can be changed and deployed in minutes. No interaction is needed with the third parties; they continue getting the data they expect but now it comes from different contexts that the host marketing technologists have chosen.

Changing third party vendors just means changing the data dissemination rules at the tag manager server, no changes are needed in the host code. The data also goes directly only to the tag manager so the execution is fast. The event handler JavaScript does not have to connect to multiple third party sites.

### Indirect Requests

For indirect requests to tag manager/aggregator sites that offer the GUI to configure the javascript, they may also implement:

- Technical controls such as only allowing the JavaScript to access the data layer values, no other DOM element
- Restricting the tag types deployed on a host site, e.g. disabling of custom HTML tags and JavaScript code

The host company should also verify the security practices of the tag manager site such as access controls to the tag configuration for the host company. It also can be two-factor authentication.

Letting the marketing folks decide where to get the data they want can result in XSS because they may get it from a URL parameter and put it into a variable that is in a scriptable location on the page.

### Sandboxing Content

Both of these tools be used by sites to sandbox/clean DOM data.

- [DOMPurify](https://github.com/cure53/DOMPurify) is a fast, tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify works with a secure default, but offers a lot of configurability and hooks.
- [MentalJS](https://github.com/hackvertor/MentalJS) is a JavaScript parser and sandbox. It allow-lists JavaScript code by adding a "$" suffix to variables and accessors.

### Subresource Integrity

[Subresource Integrity](https://www.w3.org/TR/SRI/) will ensure that only the code that has been reviewed is executed. The developer generates integrity metadata for the vendor javascript, and adds it to the script element like this:

```javascript
<script src="https://analytics.vendor.com/v1.1/script.js"
   integrity="sha384-MBO5IDfYaE6c6Aao94oZrIOiC7CGiSNE64QUbHNPhzk8Xhm0djE6QqTpL0HzTUxk"
   crossorigin="anonymous">
</script>
```

It is important to know that in order for SRI to work, the vendor host needs [CORS](https://www.w3.org/TR/cors/) enabled. Also it is good idea to monitor vendor JavaScript for changes in regular way. Because sometimes you can get **secure** but **not working** third-party code when the vendor decides to update it.

### Keeping JavaScript libraries updated

[OWASP Top 10 2013 A9](https://wiki.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) describes the problem of using components with known vulnerabilities. This includes JavaScript libraries. JavaScript libraries must be kept up to date, as previous version can have known vulnerabilities which can lead to the site typically being vulnerable to [Cross Site Scripting](https://owasp.org/www-community/attacks/xss/). There are several tools out there that can help identify such libraries. One such tool is the free open source tool [RetireJS](https://retirejs.github.io)

### Sandboxing with iframe

You can also put vendor JavaScript into an iframe from different domain (e.g. static data host). It will work as a "jail" and vendor JavaScript will not have direct access to the host page DOM and cookies.

The host main page and sandbox iframe can communicate between each other via the [postMessage mechanism](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage).

Also, iframes can be secured with the iframe [sandbox attribute](http://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/).

For high risk applications, consider the use of [Content Security Policy (CSP)](https://www.w3.org/TR/CSP2/) in addition to iframe sandboxing. CSP makes hardening against XSS even stronger.

```html
<!-- Some host, e.g. somehost.com, HTML code here -->
 <html>
   <head></head>
     <body>
       ...
       <!-- Include iframe with 3rd party vendor javascript -->
       <iframe
       src="https://somehost-static.net/analytics.html"
       sandbox="allow-same-origin allow-scripts">
       </iframe>
   </body>
 </html>

<!-- somehost-static.net/analytics.html -->
 <html>
   <head></head>
     <body>
       ...
       <script>
       window.addEventListener("message", receiveMessage, false);
       function receiveMessage(event) {
         if (event.origin !== "https://somehost.com:443") {
           return;
         } else {
         // Make some DOM here and initialize other
        //data required for 3rd party code
         }
       }
       </script>
       <!-- 3rd party vendor javascript -->
       <script src="https://analytics.vendor.com/v1.1/script.js"></script>
       <!-- /3rd party vendor javascript -->
   </body>
 </html>
```

### Virtual iframe Containment

This technique creates iFrames that run asynchronously in relation to the main page. It also provides its own containment JavaScript that automates the dynamic implementation of the protected iFrames based on the marketing tag requirements.

### Vendor Agreements

You can have the agreement or request for proposal with the 3rd parties require evidence that they have implemented secure coding and general corporate server access security. But in particular you need to determine the monitoring and control of their source code in order to prevent and detect malicious changes to that JavaScript.

## MarTechSec

Marketing Technology Security

This refers to all aspects of reducing the risk from marketing JavaScript. Controls include

1. Contractual controls for risk reduction; the contracts with any MarTech company should include a requirement to show evidence of code security and code integrity monitoring.
2. Contractual controls for risk transference: the contracts with any MarTech company could include a penalty for serving malicious JavaScript
3. Technical controls for malicious JavaScript execution prevention; Virtual Iframes,
4. Technical controls for malicious JavaScript identification; [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).
5. Technical controls including client side JavaScript malicious behavior in penetration testing requirements.

## MarSecOps

Marketing Security Operations

This refers to the operational requirements to maintain some of the technical controls. This involves possible cooperation and information exchange between the marketing team, the martech provider and the run or operations team to update the information in the page controls (SRI hash change, changes in pages with SRI), the policies in the Virtual iFrames, tag manager configuration, data layer changes etc.

The most complete and preventive controls for any site containing non-trivial marketing tags are -

1. A data layer that calls the marketing server or tag manager APIs , so that only your code executes on your page (inversion of control).

2. [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).

3. Virtual frame Containment.

The MarSecOps requirements to implement technical controls at the speed of change that marketing wants or without a significant number of dedicated resources, can make data layer and Subresource Integrity controls impractical.

## References

- [Widespread XSS Vulnerabilities in Ad Network Code Affecting Top Tier Publishers, Retailers](https://randywestergren.com/widespread-xss-vulnerabilities-ad-network-code-affecting-top-tier-publishers-retailers/).
- [Inside and Beyond Ticketmaster: The Many Breaches of Magecart](https://www.riskiq.com/blog/labs/magecart-ticketmaster-breach/).
- [Magecart – a malicious infrastructure for stealing payment details from online shops](https://www.clearskysec.com/magecart/).
- [Compromised E-commerce Sites Lead to "Magecart"](https://www.riskiq.com/blog/labs/magecart-keylogger-injection/)
- [Inbenta, blamed for Ticketmaster breach, admits it was hacked](https://www.zdnet.com/article/inbenta-blamed-for-ticketmaster-breach-says-other-sites-not-affected/).
