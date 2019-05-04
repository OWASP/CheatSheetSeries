# Mandatory markdown format rules

# Introduction

The objective of the cheat sheet is to provide advices regarding the protection against [Server Side Request Forgery](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/) attack.

**S**erver **S**ide **R**equest **F**orgery will be named **SSRF** in the rest of the cheat sheet.

This cheat sheet will focus on the defense point of view and will not explains how to perform this attack. This [talk](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf) from the security researcher [Orange Tsai](https://twitter.com/orange_8361) provides deep advices about how to perform this kind of attack.

# Context

Sometime, an application need to perform request to another application, often located on other network, to perform a specific task. Depending of the business case, it can happen that information from the user are needed to perform the action.

*Example:* 

We can imagine an web application that receive and use the information coming a user like the firstname/lastname/birthdate/email/SSN to create a profile into an HR system via a request to this HR system. 

Basically, the user cannot reach the HR system directly but if the web application in charge of receiving the user information is vulnerable to SSRF then the user can leverage it to access the HR system. 

The user use the web application as a proxy to the HR system, jumping accross the different networks in which the web application and the HR system are located.

Overview of an SSRF common flow:

![SSRFCommonFlow](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Common_Flow.png)

*Note:* SSRF is not limited to HTTP protocol, even if often the first request performed by the attacker leverage the HTTP protocol, the second request (performed by the vulnerable application, the SSRF in fact) can use different protocol like HTTP, FTP, SMTP, SMB and so on...It depends on the technical need of the vulnerable application to perform the normal expected job on the other application on which the request is sent.

# Available protections

```text
In the rest of this section, we assume that we application absolutely need that the application 
to use a information from the user to perform a valid request to another application to do 
the expected job.
```

Several protections measures are possible at Application and Network layers, both layers will be addressed in this cheat sheet in order to apply the *defense in deph* principle.

## Application layer

The first level of protection that come to mind is [Input validation](Input_Validation_Cheat_Sheet.md). 

It's a good point but then this question appear: *How to perform this input validation?*

As [Orange Tsai](https://twitter.com/orange_8361) show in his [talk](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf) , depending on the programming language used, parser can be abused. One possible countermeasure is to apply the [whitelisting approach](Input_Validation_Cheat_Sheet.md#whitelisting-vs-blacklisting) when input validation is used because, most of the time, the format of the information expected from the user is globally know.

We can identify the following kind of information that we can receive from a user and that will use to create the request that will be sent to the final application:
* String containing business data.
* IP address (V4 or V6).
* Domain name.
* URL

### String

A [regex](https://www.regular-expressions.info/) can be used to ensure that data receive are valid from a security point of view.

Example:

```java
if(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput)){
    //Continue the processing
}else{
    //Stop the processing and reject the request
}
```

### IP address

In the context of an SSRF, there is 2 validation to perform:

1. Ensure that the data provided is a valid IP V4 or V6 address.
2. There 2 options possible:
    * If you want to forbid call to internal assets then ensure that this IP is **NOT** part of your internal infrastructure. Note that this check will allow call to external assets (Internet). Here the list of your internal IP ranges is used to build a blacklist.
    * If you want to only allow call to a specific set of IP addresses (external and/or internal) then ensure that the IP in part of the IP addresses whitelisted.

The first validation can be performed using one of this libraries depending on your technologies (libray option is proposed here in order to delegate the managing of the IP address format and leverage battle tested validation function):

* **JAVA:** Method [InetAddressValidator.isValid](http://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/InetAddressValidator.html#isValid(java.lang.String)) from the [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/) library.
* **.NET**: Method [IPAddress.TryParse](https://docs.microsoft.com/en-us/dotnet/api/system.net.ipaddress.tryparse?view=netframework-4.8) from the SDK. 
* **JavaScript**: Library [ip-address](https://www.npmjs.com/package/ip-address).
* **Python**: Module [ipaddress](https://docs.python.org/3/library/ipaddress.html) from the SDK.
* **Ruby**: Class [IPAddr](https://ruby-doc.org/stdlib-2.0.0/libdoc/ipaddr/rdoc/IPAddr.html) from the SDK.

Once you are sure that the value is a valid IP address then you can perform the second validation. So, depending on the options chosen either:
* Verify that the IP address is not part of your IP ranges.
* Verify that the IP is into the whitelist.

### Domain name

TODO:

### URL

Do not accept complete URL from the user because URL are difficult to validate and parser can be abused depending on the technology used.

## Network layer

TODO:

# Authors and Primary Editors

Firstname Lastname - email@email.com

# Tools and code used for schemas

* [Mermaid Online Editor](https://mermaidjs.github.io/mermaid-live-editor).
* [Mermaid documentation](https://mermaidjs.github.io/).

Mermaid code for SSRF common flow (printscreen are used to capture PNG image inserted into this cheat sheet):

```text
sequenceDiagram
    participant Attacker
    participant VulnerableApplication
    participant TargetedApplication
    Attacker->>VulnerableApplication: Crafted HTTP request
    VulnerableApplication->>TargetedApplication: Request (HTTP, FTP...)
    Note left of TargetedApplication: Use paylaod included<br>into the request to<br>VulnerableApplication
    TargetedApplication->>VulnerableApplication: Response 
    VulnerableApplication->>Attacker: Response
    Note left of VulnerableApplication: Include response<br>from the<br>TargetedApplication
```