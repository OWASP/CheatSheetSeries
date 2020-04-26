---
title: Web Service Security Testing Cheat Sheet
permalink: /Web_Service_Security_Testing_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
{\\| style="padding: 0;margin:0;margin-top:10px;text-align:left;" \\|- \\| valign="top" style="border-right: 1px dotted gray;padding-right:25px;" \\|
Last revision (mm/dd/yy): **//**

`__TOC__`

Web Services Security Testing Cheat Sheet Introduction
======================================================

As Web Services are incorporated into application environments, having a good checklist while performing security assessments can help a penetration tester better identify web service related vulnerabilities and associated risk.

Purpose
-------

This document is intended to be an easy to use checklist while performing assessments against web services. The penetration tester is advised to incorporate this into his or her corporate testing methodology as a supplemental checklist or is free to use this checklist as the sole testing guideline.

Checklist
---------

### Pre-Assessment

-   For a Black Box assessment, at the very least, the penetration tester will need the Web Service Description Language (WSDL) file
-   For a Grey Box assessment, the penetration tester will need sample requests for each method employed by the web service(s), along with the Web Service Description Language (WSDL) file

### Information Gathering

-   Black Box
    \* Google hacking
    \*\* Inurl:jws?wsdl
    \*\* Inurl:asmx?wsdl
    \*\* Inurl:aspx?wsdl
    \*\* Inurl:ascx?wsdl
    \*\* Inurl:ashx?wsdl
    \*\* Inurl:dll?wsdl
    \*\* Inurl:exe?wsdl
    \*\* Inurl:php?wsdl
    \*\* Inurl:pl?wsdl
    \*\* Inurl:?wsdl
    \*\* Filetype:jws
    \*\* Filetype:asmx
    \*\* Filetype:ascx
    \*\* Filetype:aspx
    \*\* Filetype:ashx
    \*\* Filetype:dll
    \*\* Filetype:exe
    \*\* Filetype:php
    \*\* Filetype:pl
    \* WSDL file contents
    \*\* Methods
    \*\* Data Types
    \* UDDI
    \*\* Web Service Discovery (If no WSDL provided)
    \* Authentication Type Discovery
    \* REST vs. SOAP
    \* Baseline Requests
-   Grey Box
    \* WSDL file contents
    \*\* Methods
    \*\* Data Types
    \* Sample/Baseline Requests
    \*\* Methods
    \*\* Data Types
    \*\* Types of Information Being Requested/Consumed
    \* Authentication Type Discovery
    \* REST vs. SOAP

### Testing Phase

-   Baseline Tests
    \* Normal Request(s)/Response(s) for Each Method
-   Automated Tests
    \* Tools
    \*\* SoapUI Pro
    \*\* OWASP ZAP
    \*\* IBM AppScan
    \*\* HP Webinspect
    \*\* WSBang
    \*\* WSMap
-   Vulnerability Discovery
    \* Debug output
    \* Fuzzing
    \* XSS
    \* SQLi
    \* Malformed XML
    \* Malicious Attachment/File Upload
    \* Xpath Injection
    \* Improper Boundary Checking
    \* XML Bomb (DoS)
    \* Basic Authentication
    \* SAML/OAuth/OpenID authentication
    \*\* Authentication based attacks
    \*\*\* Replay attacks
    \*\*\* Session fixation
    \*\*\* XML Signature wrapping
    \*\*\* Inadequate session timeout settings
    \*\* Improper implementation
    \* SSL/TLS Use
    \* Host Cipher Support
    \* Valid Certificate
    \* Protocol Support
    \* Hashing Algorithm Support
    \* Deprecated cipher suites that are offered
    \*\* External resources
    \*\*\* SSL Labs
    \*\* Internal resources
    \*\*\* SSLscan
    \*Authorization Bypass
    \* Schema Implementation Weaknesses
    \* Non-encoded Output
-   Manual Tests
    \* Tools
    \*\* Soap UI Free
    \*\* Burp Suite Pro
    \*\*\* Suggested extensions:
    \*\*\*\* SAML Editor
    \*\*\*\* SAML Encoder / Decoder
    \*\*\*\* WSDL Wizard
    \*\*\*\* Wsdler
    \*\* SOA Client
    \*\* WSDigger (deprecated)
    \* Vulnerability Discovery
    \*\* Debug output
    \* Fuzzing
    \*\* XSS
    \*\* SQLi
    \*\* Malformed XML
    \*\* Malicious Attachment/File Upload
    \*\* Xpath Injection
    \*\* Improper Boundary Checking
    \*\* XML Bomb (DoS)
    \*\* Basic Authentication
    \*\* SSL/TLS Fallback

Testing REST Based Web Services
-------------------------------

There is already a great cheat sheet on how to properly test the security of REST based web services. You can find the guide at the following location:
[1](../cheatsheets/REST_Assessment_Cheat_Sheet.md) <https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html>

Testing Summary
---------------

While using automated tools, the penetration tester will need to validate all reported findings manually and perform due diligence false positive analysis for each vulnerability reported. During the manual phase of testing, the penetration tester will look for the existence of vulnerabilities missed by the automated tools and will validate automated tool output as necessary.

References
----------

[2](http://www.securestate.com/Insights/Documents/WhitePapers/Dont-Drop-the-SOAP-Whitepaper.pdf) <http://www.securestate.com/Insights/Documents/WhitePapers/Dont-Drop-the-SOAP-Whitepaper.pdf>
[3](http://resources.infosecinstitute.com/web-services/) <http://resources.infosecinstitute.com/web-services/>
[4](http://resources.infosecinstitute.com/web-services-penetration-testing-part-1/) <http://resources.infosecinstitute.com/web-services-penetration-testing-part-1/>
[5](http://resources.infosecinstitute.com/web-services-penetration-testing-part-2-automated-approach-soapui-pro/) <http://resources.infosecinstitute.com/web-services-penetration-testing-part-2-automated-approach-soapui-pro/>
[6](http://resources.infosecinstitute.com/web-services-pen-test-part-3-automation-appscan-webinspect/) <http://resources.infosecinstitute.com/web-services-pen-test-part-3-automation-appscan-webinspect/>
[7](https://www.youtube.com/watch?v=J-uO0ELZ2rk) <https://www.youtube.com/watch?v=J-uO0ELZ2rk>
[8](http://www-01.ibm.com/support/docview.wss?uid=swg21404788) <http://www-01.ibm.com/support/docview.wss?uid=swg21404788>
[9](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html) <https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html>
[10](http://www.pushtotest.com/blogs/60-the-cohen-blog/697-web-security-test-solutions-with-testmaker-and-soapui.html) <http://www.pushtotest.com/blogs/60-the-cohen-blog/697-web-security-test-solutions-with-testmaker-and-soapui.html>
[11](https://msdn.microsoft.com/en-us/library/ff650168.aspx) <https://msdn.microsoft.com/en-us/library/ff650168.aspx>
[12](http://www.soapui.org/security-testing/overview-of-security-scans.html) <http://www.soapui.org/security-testing/overview-of-security-scans.html>
[13](https://owasp.org/www-project-web-security-testing-guide/) <https://owasp.org/www-project-web-security-testing-guide/>
[14](http://resources.infosecinstitute.com/web-services-pen-test-part-4-manual-testing-soa-client/) <http://resources.infosecinstitute.com/web-services-pen-test-part-4-manual-testing-soa-client/>
[15](http://projects.webappsec.org/w/page/13247002/XML%20Entity%20Expansion) <http://projects.webappsec.org/w/page/13247002/XML%20Entity%20Expansion>
[16](https://wiki.owasp.org/index.php/Testing_WSDL_%28OWASP-WS-002%29) <https://wiki.owasp.org/index.php/Testing_WSDL_%28OWASP-WS-002%29>
[17](https://www.youtube.com/watch?v=QLKM4USUlZs) <https://www.youtube.com/watch?v=QLKM4USUlZs>
[18](https://www.youtube.com/watch?v=RHIkb9yEV1k) <https://www.youtube.com/watch?v=RHIkb9yEV1k>
[19](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf) <https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf>
[20](http://resources.infosecinstitute.com/saml-oauth-openid/) <http://resources.infosecinstitute.com/saml-oauth-openid/>
[21](http://blog.sendsafely.com/post/69590974866/web-based-single-sign-on-and-the-dangers-of-saml) <http://blog.sendsafely.com/post/69590974866/web-based-single-sign-on-and-the-dangers-of-saml>
[22](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf) <https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf>

Additional Resources
--------------------

Below are resources to help the tester learn and refine their ability to effectively test various web services.

<h3>
Virtual Machines

</h3>
-   OWASP Mutillidae
-   PenTester Lab: Axis2 Web Service and Tomcat Manager
-   DVWS
-   OWASP WebGoat

<h3>
Online Resources

</h3>
-   [23](http://www-01.ibm.com/support/docview.wss?uid=swg21288823) <http://www-01.ibm.com/support/docview.wss?uid=swg21288823>
-   [24](http://zero.webappsecurity.com/) <http://zero.webappsecurity.com/>
-   [25](https://media.blackhat.com/bh-us-11/Johnson/BH_US_11_JohnsonEstonAbraham_Dont_Drop_the_SOAP_WP.pdf) <https://media.blackhat.com/bh-us-11/Johnson/BH_US_11_JohnsonEstonAbraham_Dont_Drop_the_SOAP_WP.pdf>
-   [26](http://www.securitytube.net/video/11695) <http://www.securitytube.net/video/11695>
-   [27](http://www.securitytube.net/video/8462) <http://www.securitytube.net/video/8462>
-   [28](http://www.securitytube.net/video/1113) <http://www.securitytube.net/video/1113>
-   [29](http://resources.infosecinstitute.com/web-services-pen-test-part-4-manual-testing-soa-client/) <http://resources.infosecinstitute.com/web-services-pen-test-part-4-manual-testing-soa-client/>
-   [30](../cheatsheets/REST_Assessment_Cheat_Sheet.md) <https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html>

Primary Author
--------------

-   Michael Born

Contributing Editors/Authors
----------------------------

-   John Rogers
-   Zac Fowler
-   Fred Donovan
-   Rob Temple
-   Andrew Freeborn
-   Sai Uday Shankar Korlimarla
-   Robert Nordstrom
-   Justin Williams

Other Cheatsheets
-----------------

\\|}

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")