# Introduction

The objective of the cheat sheet is to provide advices regarding the protection against [Server Side Request Forgery](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/) attack.

**S**erver **S**ide **R**equest **F**orgery will be named **SSRF** in the rest of the cheat sheet.

This cheat sheet will focus on the defense point of view and will not explains how to perform this attack. This [talk](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf) from the security researcher [Orange Tsai](https://twitter.com/orange_8361) as well as this [document](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf) provides deep advices about how to perform this kind of attack.

# Context

Server-Side Request Forgery is a way to force application to make a malicious network request. It can happen when user can control the URL to an external resource like: 
- Image on external server (e.g. user enter URL of the avatar, then the application will download this file and display some feedback like image itself or error).
- Custom [WebHook](https://en.wikipedia.org/wiki/Webhook) (user have to specify WebHook handlers, Callback URLs).
- Request to another application, often located on other network, to perform a specific task. Depending of the business case, it can happen that information from the user are needed to perform the action.

Overview of an SSRF common flow:

![SSRFCommonFlow](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Common_Flow.png)

*Note:* SSRF is not limited to HTTP protocol, even if often the first request performed by the attacker leverage the HTTP protocol, the second request (performed by the vulnerable application, the SSRF in fact) can use different protocol like HTTP, FTP, SMTP, SMB and so on...It depends on the technical need of the vulnerable application to perform the normal expected job on the other application on which the request is sent.

# Cases

Depending on application functionality and requirements there are two basic cases when SSRF can happen:
* Application should send request only to **identified and trusted applications**: *Case when [whitelist](https://en.wikipedia.org/wiki/Whitelisting) approach is available*.
* Application can send requests to **ANY other IP address or domain name**: *Case when [whitelist](https://en.wikipedia.org/wiki/Whitelisting) approach is not available*.

Because these two cases are very different this document will describe defences against them separately.

# Case 1 - Application should send request only to identified and trusted applications

Sometime, an application need to perform request to another application, often located on other network, to perform a specific task. Depending of the business case, it can happen that information from the user are needed to perform the action.

*Example:* 

 > We can imagine an web application that receive and use the information coming a user like the firstname/lastname/birthdate/... to create a profile into an HR system via a request to this HR system. 

 > Basically, the user cannot reach the HR system directly but if the web application in charge of receiving the user information is vulnerable to SSRF then the user can leverage it to access the HR system. 

 > The user use the web application as a proxy to the HR system, jumping accross the different networks in which the web application and the HR system are located.

Whitelist approach can be used here because the application called by the *VulnerableApplication* is clearly identified in the technical/business flow. So, the goal here is to ensure that every call is targeted to one of the identified and trusted applications.

## Available protections

 > In the rest of this section, we assume that we application absolutely need that the application to use a information from the user to perform a valid request to another application to do the expected job.

Several protections measures are possible at Application and Network layers, both layers will be addressed in this cheat sheet in order to apply the *defense in deph* principle.

### Application layer

The first level of protection that come to mind is [Input validation](Input_Validation_Cheat_Sheet.md). 

It's a good point but then this question appear: *How to perform this input validation?*

As [Orange Tsai](https://twitter.com/orange_8361) show in his [talk](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf), depending on the programming language used, parser can be abused. One possible countermeasure is to apply the [whitelisting approach](Input_Validation_Cheat_Sheet.md#whitelisting-vs-blacklisting) when input validation is used because, most of the time, the format of the information expected from the user is globally know.

We can identify the following kind of information that we can receive from a user and that will use to create the request that will be sent to the final application:
* String containing business data.
* IP address (V4 or V6).
* Domain name.
* URL

**Note:** Disable the support for the following of the [redirection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections) in your web client in order to prevent the bypass of the input validation described in the section `Exploitation tricks > Bypassing restrictions > Input validation > Unsafe redirect` of this [document](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf).

#### String

In the context of an SSRF, we can simply ensure that the provided string respect the business/technical format expected. A [regex](https://www.regular-expressions.info/) can be used to ensure that data receive is valid from a security point of view. We assume here that the expected data is a non-network related data like firstname/lastname/birthdate/...

Example:

```java
if(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput)){
    //Continue the processing because the input data is valid
}else{
    //Stop the processing and reject the request
}
```

#### IP address

In the context of an SSRF, there is 2 validation to perform:

1. Ensure that the data provided is a valid IP V4 or V6 address.
2. Ensure that the IP address provided belong to the one of the IP addresses of the identified and trusted applications (the whitelisting come to action here).

The first validation can be performed using one of this libraries depending on your technologies (library option is proposed here in order to delegate the managing of the IP address format and leverage battle tested validation function):

> Verification of the proposed libraries has been performed regarding the exposure to bypass (Hex, Octal, Dword, URL and Mixed encoding) described in this [article](https://medium.com/@vickieli/bypassing-ssrf-protection-e111ae70727b).

* **JAVA:** Method [InetAddressValidator.isValid](http://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/InetAddressValidator.html#isValid(java.lang.String)) from the [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/) library.
    * **It is NOT exposed** to bypass using Hex, Octal, Dword, URL and Mixed encoding.
* **.NET**: Method [IPAddress.TryParse](https://docs.microsoft.com/en-us/dotnet/api/system.net.ipaddress.tryparse?view=netframework-4.8) from the SDK.
    * **It is exposed** to bypass using Hex, Octal, Dword and Mixed encoding but **NOT** the URL encoding.
    * As whitelisting is used here, any bypass tentative will be blocked during the comparison against the allowed list of IP addresses.
* **JavaScript**: Library [ip-address](https://www.npmjs.com/package/ip-address).
    * **It is NOT exposed** to bypass using Hex, Octal, Dword, URL and Mixed encoding.
* **Python**: Module [ipaddress](https://docs.python.org/3/library/ipaddress.html) from the SDK.
    * **It is NOT exposed** to bypass using Hex, Octal, Dword, URL and Mixed encoding.
* **Ruby**: Class [IPAddr](https://ruby-doc.org/stdlib-2.0.0/libdoc/ipaddr/rdoc/IPAddr.html) from the SDK.
    * **It is NOT exposed** to bypass using Hex, Octal, Dword, URL and Mixed encoding.

> **Use the output value of the method/library as the IP address to compare against the whitelist.**

Once you are sure that the value is a valid IP address then you can perform the second validation. Here, as a whitelist has been built with all the IP addresses (**V4 + V6** in order to avoid bypass using one of the 2 IP type) of every identified and trusted applications, then a verification can be made to ensure that the IP address provided is part of this whitelist (string strict comparison with case sensitive).

#### Domain name

When validation of a domain name come to mind, the first idea is to do a DNS resolution in order to see if the domain exists, it's not a bad idea but it bring some problems depending on the configuration of the application regarding the DNS servers to use for the resolution:
* It can disclose information to external DNS resolvers.
* It can be used by an attacker to bind a legit domain name to an internal IP address. See the section `Exploitation tricks > Bypassing restrictions > Input validation > DNS pinning` of this [document](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf).
* It can be used, by an attacker, to deliver a malicious payload to the internal DNS resolvers as well as to the API (SDK or third-party) used by the application to handle the DNS communication and then, potentially, trigger a vulnerability in one of these both components.

In the context of an SSRF, there is 2 validation to perform:

1. Ensure that the data provided is a valid domain name.
2. Ensure that the domain name provided belong to the one of the domain name of the identified and trusted applications (the whitelisting come to action here).

Like for IP address, the first validation can be performed using one of this libraries depending on your technologies (library option is proposed here in order to delegate the managing of the domain name format and leverage battle tested validation function), proposed functions do not perform any DNS resolution query:

* **JAVA:** Method [DomainValidator.isValid](https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/DomainValidator.html#isValid(java.lang.String)) from the [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/) library.
* **.NET**: Method [Uri.CheckHostName](https://docs.microsoft.com/en-us/dotnet/api/system.uri.checkhostname?view=netframework-4.8) from the SDK. 
* **JavaScript**: Library [is-valid-domain](https://www.npmjs.com/package/is-valid-domain).
* **Python**: Module [validators.domain](https://validators.readthedocs.io/en/latest/#module-validators.domain).
* **Ruby**: **FIXME: Find a Gem**.

Once you are sure that the value is a valid domain name then you can perform the second validation. As we are, here, in a context where whitelist is possible then we can apply this approach:

1. Build a whitelist with all the domain names of every identified and trusted applications.
2. Verify that the domain name received is part of this whitelist (string strict comparison with case sensitive).

Unfortunately here, the application is still vulnerable to the bypass described in the section `Exploitation tricks > Bypassing restrictions > Input validation > DNS pinning` of this [document](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf). To address that issue, the following action must be taken in addition of the validation on the domain name:
1. Ensure that the domains that are part of your organization are resolved by the your internal DNS server first in the DNS resolver chain.
2. Monitor the whitelist of domains in order to detect if any of them change to resolve to an:
    * Local IP address (V4 + V6).
    * Internal IP of your organization (expected to be in private IP ranges) for the domain that are not part of your organization.

The following Python3 script can be used, as a starting point, for the monitoring mentioned above:

```python
# Dependencies: pip install ipaddress dnspython
import ipaddress
import dns.resolver

# Configure the whitelist to check
DOMAINS_WHITELIST = ["owasp.org", "labslinux"]

# Configure the DNS resolver to use for all DNS queries
DNS_RESOLVER = dns.resolver.Resolver()
DNS_RESOLVER.nameservers = ["1.1.1.1"]

def verify_dns_records(domain, records, type):
    """
    Verify if one of the DNS records resolve to a non public IP address.
    Return a boolean indicating if any error has been detected.
    """
    error_detected = False
    if records is not None:
        for record in records:
            value = record.to_text().strip()
            try:
                ip = ipaddress.ip_address(value)
                # See https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address.is_global
                if not ip.is_global:
                    print("[!] DNS record type '%s' for domain name '%s' resolve to 
                    a non public IP address '%s'!" % (type, domain, value))
                    error_detected = True
            except ValueError:
                error_detected = True
                print("[!] '%s' is not valid IP address!" % value)
    return error_detected
            
def check():
    """
    Perform the check of the whitelist of domains.
    Return a boolean indicating if any error has been detected.
    """
    error_detected = False
    for domain in DOMAINS_WHITELIST:    
        # Get the IPs of the curent domain
        # See https://en.wikipedia.org/wiki/List_of_DNS_record_types
        try:
            # A = IPv4 address record        
            ip_v4_records = DNS_RESOLVER.query(domain, "A")
        except Exception as e:
            ip_v4_records = None            
            print("[i] Cannot get A record for domain '%s': %s\n" % (domain,e))        
        try:
            # AAAA = IPv6 address record
            ip_v6_records = DNS_RESOLVER.query(domain, "AAAA")
        except Exception as e:
            ip_v6_records = None
            print("[i] Cannot get AAAA record for domain '%s': %s\n" % (domain,e))
        # Verify the IPs obtained
        if verify_dns_records(domain, ip_v4_records, "A") 
        or verify_dns_records(domain, ip_v6_records, "AAAA"):
            error_detected = True
    return error_detected

if __name__== "__main__":
    if check():
        exit(1)
    else:
        exit(0)
```

#### URL

Do not accept complete URL from the user because URL are difficult to validate and parser can be abused depending on the technology used like demonstrated by the [talk](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf) of [Orange Tsai](https://twitter.com/orange_8361). 

If network related information is really nedded then only accept an valid IP address or domain name.

### Network layer

The objective here is to prevent that the *VulnerableApplication* performs call to arbitrary applications, so, only the expected *routes* will be opened at network level.

The Firewall component, as a specific device or using the one provided within the operating system, will be used here define the legitimate flows. 

In the schema below we show the goal that we want the achieve by leveraging the Firewall component, using this way, even if an application is vulnerable to SSRF, the attacker can only call applications that are part of legitimate flows:

![Case 1 for Network layer protection about flows that we want to prevent](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Case1_NetworkLayer_PreventFlow.png)

[Network segregation](https://www.mwrinfosecurity.com/our-thinking/making-the-case-for-network-segregation) (see this set of [implementation advices](https://www.cyber.gov.au/publications/network-segmentation-and-segregation)) can also be leveraged and **is highly recommanded in order to block not legit call directly at network level itself**.

# Case 2 - Application can send requests to ANY external IP address or domain name

This case happen when user can control an URL to an **External** resource and application makes a request to this URL (e.g. in case of [WebHooks](https://en.wikipedia.org/wiki/Webhook)). Whitelist cannot be used here because the list of IPs/domains is often unknown upfront and is dynamically changing. 

We talk here about the notion of **External** in way that, at the opposite the of the case n°1 in which we know all the call flow, here the *VulnerableApplication* can, by design, call any target IP/domain. 

We assume that if in the design of the application it should only perform call to IP/domain that are located inside the company's global network then whitelist approach can be used and then we apply the case n°1. 

Thus **External** here refer to any IP/domain *located outside* the company's global network. So, the goal here is to ensure that every call initiated by the *VulnerableApplication*:
* **Is NOT** targeting one of the IP/domain *located inside* the company's global network.
* Use a convention defined between the *VulnerableApplication* and the expected IP/domain in order to *proof* that the call has been legitimately initiated.

## Challenges in blocking URLs at application layer

Based on the description of the context of application of this case, we see that will use the blacklist approach. It is know in security industry that blacklisting is very hard and prone to errors. 

Below is described why filtering URLs is very hard at application layer.

* It imply that the application must be able to detect, at code level, that the provided IP (**V4 + V6**) is not in official [private networks ranges](https://en.wikipedia.org/wiki/Private_network) including also `localhost` and IPv4 Link-Local addresses `169.254.0.0-169.254.255.255` (that is all not-routable IP addresses). Not every SDK provide a built-in feature for this kind of verification so it made this task a hard one.
* Same remark for domain name: The company must maintains a list of all internal domain names and provide a centralized service to allow an application to verify if a provided domain name is an internal one. For this verification, an internal DNS resolver can be queried by the application but this internal DNS resolver must not resolve external domain name (*must only resolve internal domain name*). 
    * **FIXME: Not sure about my proposal here about DNS and if i'm not wrong then this point is in fact easy to check**

## Notes from Jakub

 > In that case system should blok all IPs/domains that are in private network including localhost and IPv4 Link-Local addresses 169.254.0.0-169.254.255.255 (that is all not-routable ip addresses). In practice it is a hard task.

 > Random notes for Case 2: When whitelist approach is not available, attacker can try to forge requests to two types of internal applications: 1. applications that normally are not requested by this application - and here attacker should be stopped by authentication 2. applications that normally are exchanging data thus vulnerable application is allowed to make requests. Here are couple of options like adding custom header to all requests that maybe controlled by attacker and rejecting them in internal applications. In this attack attacker typically can control URL but not headers etc

 > Random notes Application layer: it cannot be done only on app layer but on that layer we can do scheme:// white-listing + logging

## Notes from Dom for discussion

> Usage of a custom header with a shared secret do not prevent SSRF triggering if it is the *VulnerableApplication* that add the custom header with the shared secret during the building of the request because the attacker can use the SSRF and the secret will be automatically added.

> Same remark regarding authentication if it's the *VulnerableApplication* that add the authentication information during the building of the request.

> To be effective, it must be a secret that is not automatically added by the application during the creation of the request but expliclty added by the user based on a secret generated and received/validated by the targeted application during a kind of "enrolement" phase in which a communication convention is defined between the *VulnerableApplication* and the targeted application. Unfortunately it imply that the *VulnerableApplication* let the request be send and it's up to the targeted application to verify the presence and validity of the secret.

> *VulnerableApplication* must prevent these things: User must NOT be able to pass custom parameters to the targeted application or arbitrary choose the protocol used by the request (selection in a allowed list of protocols). For HTTP protocol, the user must not be able to arbitrary choose the VERB used for the request (it ix fixed by the *VulnerableApplication*). Using this way, the request is sent by the user have limited surface of action on it because it control only the destination and the value of the shared secret (not the name of the parameter). 

> Depending on the destination it can happen case in which the user must be able to set the param name but this point can be tackled by the *VulnerableApplication* by proposing integration with the targeted application and then fix the parameter name in order to prevent to open the name to user input influence.

## Notes from Elie

> ...

## Available protections

We take the same assumption than for the case n°1 regarding the application user input data needed and the *defense in deph* principle.

### Application layer

Like for the case n°1, we assume that we need `String`, `IP address` or `domain name` to create the request that will be sent to the final application.

The input data first validation presented in the case n°1 on the 3 types of data will be the same for this case **BUT the second validation will differ**, indeed, here we must use the blacklist approach.

> **Regarding the proof of legitimacy of the request**: The *TargetedApplication* that will receive the request must generate a random token (ex: alphanumeric of 20 characters) that is expected to be passed by the caller (in body via a parameter for which the name is also defined by the application itself and only allow characters set `[a-z]{1,10}`) to perform a valid request. The reception endpoint must only accept **HTTP POST** request.

Validation flow - if one the validation step fail then the request is rejected:
1. Receive the IP address or domain name of the *TargetedApplication* and apply input data first validation.
2. Blacklist second validation against the IP address or domain name of the *TargetedApplication*:
    * For IP address: Verify that is a public one.
    * For domain name: Verify that is a public one by trying to resolve the domain name against the DNS server that only resolve internal domain name. Here, it must return a response indicating that it do not know the provided domain.
3. Receive the protocol to use for the request via a dedicated input parameter for which you verify the value against a allowed list of protocols (`HTTP` or `HTTPS`).
4. Receive the parameter name for the token to pass to the *TargetedApplication* via a dedicated input parameter for which you only allow characters set `[a-z]{1,10}`.
5. Receive the token itself via a dedicated input parameter for which you only allow characters set `[a-zA-Z0-9]{20}`.
6. Receive and validate any business data needed to perform a valid call from a business point of view.
7. Build the HTTP POST request **using only validated informations** and send it (*do not forget to disable the support for [redirection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections) in the web client used*).

TODO: Show how to technically perform the step 2

### Network layer

Same like for the case n°1.

# References

Online version of the [SSRF bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM) (PDF version is used in this cheat sheet).

Article about [Bypassing SSRF Protection](https://medium.com/@vickieli/bypassing-ssrf-protection-e111ae70727b).

# Tools and code used for schemas

* [Mermaid Online Editor](https://mermaidjs.github.io/mermaid-live-editor) and [Mermaid documentation](https://mermaidjs.github.io/).
* [Draw.io Online Editor](https://www.draw.io/).

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

Draw.io schema XML code for the "[case 1 for network layer protection about flows that we want to prevent](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Case1_NetworkLayer_PreventFlow.xml)" schema (printscreen are used to capture PNG image inserted into this cheat sheet).