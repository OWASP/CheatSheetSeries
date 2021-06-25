---
title: Web Application Security Testing Cheat Sheet
permalink: /Web_Application_Security_Testing_Cheat_Sheet/
---

Introduction
============

This cheat sheet provides a checklist of tasks to be performed during blackbox security testing of a web application.

Purpose
=======

This checklist is intended to be used as a memory aid for experienced pentesters. It should be used in conjunction with the [OWASP Testing Guide](/:Category:OWASP_Testing_Project\ "wikilink"). It will be updated as the [Testing Guide v4](/OWASP_Application_Testing_guide_v4\ "wikilink") progresses.

The intention is that this guide will be available as an XML document, with scripts that convert it into formats such as PDF, MediaWiki markup, HTML, and so forth. This will allow it to be consumed within security tools as well as being available in a format suitable for printing.

All feedback or offers of help will be appreciated. If you have specific changes you think should be made, please log in and make suggestions.

The Checklist
=============

Information Gathering
---------------------

*Rendered Site Review*

-   Manually explore the site
-   [Spider/crawl](/Testing:_Spidering_and_googling_\ "wikilink") for missed or hidden content
-   [Check the webserver metafiles](/Review_Webserver_Metafiles_for_Information_Leakage_(OTG-INFO-003)\ "wikilink") for information leakage files that expose content, such as robots.txt, sitemap.xml, and .DS_Store
-   [Check the caches of major search engines for publicly accessible sites](/Conduct_search_engine_discovery/reconnaissance_for_information_leakage_(OTG-INFO-001)\ "wikilink")
-   Check for differences in content based on user agent (e.g. mobile sites, accessing as a search engine crawler)
-   [Check webpage comments and metadata for information leakage](/Review_webpage_comments_and_metadata_for_information_leakage_(OTG-INFO-005)_\ "wikilink")

*Development Review*

-   [Check the web application framework](/Fingerprint_Web_Application_Framework_(OTG-INFO-008)_\ "wikilink")
-   [Perform web application fingerprinting](/Fingerprint_Web_Server_(OTG-INFO-002)\ "wikilink")
-   Identify technologies used
-   [Identify user roles](/Test_Role_Definitions_(OTG-IDENT-001)\ "wikilink")
-   [Identify application entry points](/Identify_application_entry_points_(OTG-INFO-006)_\ "wikilink")
-   Identify client-side code
-   Identify multiple versions/channels (e.g. web, mobile web, mobile app)

*Hosting and Platform Review*

-   [Identify web services](/Web_Services_\ "wikilink")
-   Identify co-hosted and related applications
-   Identify all hostnames and ports
-   Identify third-party hosted content

Configuration Management
------------------------

-   Check for commonly used application and administrative URLs
-   [Check for old, backup, and unreferenced files](/4.3.4_Review_Old,_Backup_and_Unreferenced_Files_for_Sensitive_Information_(OTG-CONFIG-004)_\ "wikilink")
-   [Check HTTP methods supported and Cross Site Tracing (XST)](/Test_HTTP_Methods_(OTG-CONFIG-006)_\ "wikilink")
-   [Test file extensions handling](/4.3.3_Test_File_Extensions_Handling_for_Sensitive_Information_(OTG-CONFIG-003)_\ "wikilink")
-   [Test RIA cross domain policy](/Test_RIA_cross_domain_policy_(OTG-CONFIG-008)_\ "wikilink")
-   Test for [security HTTP headers](/List_of_useful_HTTP_headers_\ "wikilink") (e.g. CSP, X-Frame-Options, HSTS)
-   Test for policies (e.g. Flash, Silverlight, robots)
-   Check for sensitive data in client-side code (e.g. API keys, credentials)

Secure Transmission
-------------------

*Protocols and Encryption*

-   [Check SSL version, algorithms, and key length](/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)_\ "wikilink")
-   Check for digital certificate validity (duration, signature, and CN)
-   Check that credentials are only delivered over HTTPS
-   Check that the login form is delivered over HTTPS
-   Check that session tokens are only delivered over HTTPS
-   [Check if HTTP Strict Transport Security (HSTS) in use](/Test_HTTP_Strict_Transport_Security_(OTG-CONFIG-009)_\ "wikilink")
-   [Test ability to forge requests](/Test_Ability_to_forge_requests_(OTG-BUSLOGIC-002)_\ "wikilink")
-   [Test web messaging (HTML5)](/Test_Web_Messaging_(OTG-CLIENT-011)\ "wikilink")
-   [Check CORS implementation (HTML5)](/Test_Cross_Origin_Resource_Sharing_(OTG-CLIENT-007)\ "wikilink")

*Web Services and REST*

-   [Test for web service issues](/Web_Service_Security_Testing_Cheat_Sheet_\ "wikilink")
-   [Test REST](/REST_Assessment_Cheat_Sheet_\ "wikilink")

Authentication
--------------

*Application Password Functionality*

-   [Test password quality rules](/Testing_for_Weak_password_policy_(OTG-AUTHN-007)\ "wikilink")
-   Test remember me functionality
-   Test password reset and/or recovery
-   Test password change process
-   Test CAPTCHA
-   Test multi-factor authentication
-   Test for logout functionality presence
-   Test for default logins
-   Test for out-of-channel notification of account lockouts and successful password changes
-   Test for consistent authentication across applications with shared authentication schema/SSO and alternative channels
-   Test for weak security question/answer

*Additional Authentication Functionality*

-   [Test for user enumeration](/Testing_for_User_Enumeration_and_Guessable_User_Account_(OWASP-AT-002)_\ "wikilink")
-   [Test for authentication bypass](/Testing_for_Bypassing_Authentication_Schema_(OTG-AUTHN-004)_\ "wikilink")
-   [Test for brute force protection](/Testing_for_Brute_Force_(OWASP-AT-004)_\ "wikilink")
-   [Test for credentials transported over an encrypted channel](/Testing_for_Credentials_Transported_over_an_Encrypted_Channel_(OTG-AUTHN-001)\ "wikilink")
-   Test for cache management on HTTP (eg Pragma, Expires, Max-age)
-   Test for user-accessible authentication history

Session Management
------------------

-   Establish how session management is handled in the application (eg, tokens in cookies, token in URL)
-   [Check session tokens for cookie flags (httpOnly and secure)](/Testing_for_cookies_attributes_(OTG-SESS-002)\ "wikilink")
-   [Check session cookie scope (path and domain)](/Testing_for_cookies_attributes_(OTG-SESS-002)\ "wikilink")
-   Check session cookie duration (expires and max-age)
-   [Check session termination after a maximum lifetime](/Test_Session_Timeout_(OTG-SESS-007)\ "wikilink")
-   [Check session termination after relative timeout](/Test_Session_Timeout_(OTG-SESS-007)\ "wikilink")
-   [Check session termination after logout](/Testing_for_logout_functionality_(OTG-SESS-006)\ "wikilink")
-   Test to see if users can have multiple simultaneous sessions
-   [Test session cookies for randomness](/Testing_for_Session_Management_Schema_(OTG-SESS-001)#Session_ID_Predictability_and_Randomness_\ "wikilink")
-   Confirm that new session tokens are issued on login, role change, and logout
-   Test for consistent session management across applications with shared session management
-   Test for session puzzling
-   Test for CSRF and clickjacking

Authorization
-------------

-   [Test for path traversal](/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001)\ "wikilink")
-   [Test for vertical access control problems (a.k.a. privilege escalation)](/Testing_for_Privilege_escalation_(OTG-AUTHZ-003)\ "wikilink")
-   Test for horizontal access control problems (between two users at the same privilege level)
-   [Test for missing authorization](/Testing_for_Bypassing_Authorization_Schema_(OTG-AUTHZ-002)\ "wikilink")
-   [Test for insecure direct object references](/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)\ "wikilink")

Cryptography
------------

-   [Check if data which should be encrypted is not](/Testing_for_Sensitive_information_sent_via_unencrypted_channels_(OTG-CRYPST-003)\ "wikilink")
-   Check for wrong algorithms usage depending on context
-   [Check for weak algorithms usage](/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)\ "wikilink")
-   [Check for proper use of salting](/Password_Storage_Cheat_Sheet#Use_a_cryptographically_strong_credential-specific_salt_\ "wikilink")
-   [Check for randomness functions](/Insecure_Randomness_\ "wikilink")

Data Validation
---------------

*Injection*

-   Test for HTML Injection
-   [Test for SQL Injection](/Testing_for_SQL_Injection_(OTG-INPVAL-005)\ "wikilink")
-   Test for LDAP Injection
-   [Test for ORM Injection](/Testing_for_ORM_Injection_(OTG-INPVAL-007)\ "wikilink")
-   [Test for XML Injection](/Testing_for_XML_Injection_(OTG-INPVAL-008)\ "wikilink")
-   Test for XXE Injection
-   [Test for SSI Injection](/Testing_for_SSI_Injection_(OTG-INPVAL-009)\ "wikilink")
-   [Test for XPath Injection](/Testing_for_XPath_Injection_(OTG-INPVAL-010)\ "wikilink")
-   Test for XQuery Injection
-   [Test for IMAP/SMTP Injection](/Testing_for_IMAP/SMTP_Injection_(OTG-INPVAL-011)\ "wikilink")
-   [Test for Code Injection](/Testing_for_Code_Injection_(OTG-INPVAL-012)\ "wikilink")
-   Test for Expression Language Injection
-   [Test for Command Injection](/Testing_for_Command_Injection_(OTG-INPVAL-013)\ "wikilink")
-   Test for NoSQL injection

*Other*

-   [Test for Reflected Cross Site Scripting](/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001)\ "wikilink")
-   [Test for Stored Cross Site Scripting](/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002)\ "wikilink")
-   [Test for DOM based Cross Site Scripting](/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001)\ "wikilink")
-   Test for Cross Site Flashing
-   Test for Overflow ([Stack](/Testing_for_Stack_Overflow\ "wikilink"), [Heap](/Testing_for_Heap_Overflow\ "wikilink") and Integer)
-   [Test for Format String](/Testing_for_Format_String\ "wikilink")
-   Test for incubated vulnerabilities
-   [Test for HTTP Splitting/Smuggling](/Testing_for_HTTP_Splitting/Smuggling_(OTG-INPVAL-016)\ "wikilink")
-   Test for HTTP Verb Tampering
-   [Test for Open Redirection](/Top_10_2013-A10-Unvalidated_Redirects_and_Forwards\ "wikilink")
-   [Test for Local File Inclusion](/Testing_for_Local_File_Inclusion\ "wikilink")
-   [Test for Remote File Inclusion](/Testing_for_Remote_File_Inclusion\ "wikilink")
-   Compare client-side and server-side validation rules
-   Test for HTTP parameter pollution
-   Test for auto-binding
-   Test for Mass Assignment
-   Test for NULL/Invalid Session Cookie
-   [Test for integrity of data](/Test_integrity_checks_(OTG-BUSLOGIC-003)_\ "wikilink")
-   [Test for the Circumvention of Work Flows](/Testing_for_the_Circumvention_of_Work_Flows_(OTG-BUSLOGIC-009)_\ "wikilink")
-   [Test Defenses Against Application Mis-use](/Test_defenses_against_application_mis-use_(OTG-BUSLOGIC-011)_\ "wikilink")
-   [Test That a Function or Feature Cannot Be Used Outside Of Limits](/Test_number_of_times_a_function_can_be_used_limits_(OTG-BUSLOGIC-007)_\ "wikilink")
-   [Test for Process Timing](/Test_for_Process_Timing_(OTG-BUSLOGIC-007)_\ "wikilink")
-   [Test for Web Storage SQL injection (HTML5)](/Test_Local_Storage_(OTG-CLIENT-012)\ "wikilink")
-   [Check Offline Web Application](/HTML5_Security_Cheat_Sheet#Offline_Applications_\ "wikilink")

Denial of Service
-----------------

-   Test for anti-automation
-   [Test for account lockout](/Testing_for_Weak_lock_out_mechanism_(OTG-AUTHN-003)\ "wikilink")
-   Test for HTTP protocol DoS
-   Test for SQL wildcard DoS

Specific Risky Functionality
----------------------------

*File Uploads*

-   [Test that acceptable file types are allowed and non-allowed types are rejected](/Test_Upload_of_Unexpected_File_Types_(OTG-BUSLOGIC-008)\ "wikilink")
-   Test that file size limits, upload frequency and total file counts are defined and are enforced
-   Test that file contents match the defined file type
-   [Test that all file uploads have anti-virus scanning in place](/Test_Upload_of_Malicious_Files_(OTG-BUSLOGIC-009)\ "wikilink")
-   [Test upload of malicious files](/Test_Upload_of_Malicious_Files_(OTG-BUSLOGIC-016)_\ "wikilink")
-   Test that unsafe filenames are sanitized
-   Test that uploaded files are not directly accessible within the web root
-   Test that uploaded files are not served on the same hostname/port
-   Test that files and other media are integrated with the authentication and authorization schemas

*Payments*

-   Test for known vulnerabilities and configuration issues on Web Server and Web Application
-   Test for default or guessable password
-   [Test for Injection vulnerabilities](/Injection_Flaws_\ "wikilink")
-   [Test for Buffer Overflows](/Testing_for_Buffer_Overflow_(OTG-INPVAL-014)_\ "wikilink")
-   [Test for Insecure Cryptographic Storage](/Top_10_2010-A7-Insecure_Cryptographic_Storage_\ "wikilink")
-   [Test for Insufficient Transport Layer Protection](/Top_10_2010-A9-Insufficient_Transport_Layer_Protection_\ "wikilink")
-   [Test for Improper Error Handling](/Web_Application_Security_Testing_Cheat_Sheet#Error_Handling\ "wikilink")
-   Test for all vulnerabilities with a CVSS v2 score &gt; 4.0
-   Test for Authentication and Authorization issues
-   [Test for CSRF](/Testing_for_CSRF_(OTG-SESS-005)\ "wikilink")

Error Handling
--------------

-   [Check for Error Codes](/Testing_for_Error_Code_(OTG-ERR-001)\ "wikilink")
-   [Check for Stack Traces](/Testing_for_Stack_Traces_(OTG-ERR-002)\ "wikilink")

Other Formats
=============

-   DradisPro template format [on github](https://github.com/raesene/OWASP_Web_App_Testing_Cheatsheet_Converter/blob/master/OWASP_Web_Application_Testing_Cheat_Sheet.xml)
-   Asana template on [Templana](http://templana.com/templates/owasp-website-security-checklist/) (thanks to Bastien Siebman)

Authors and contributors
========================

[Simon Bennetts](/User:Simon_Bennetts\ "wikilink")
[Rory McCune](/User:Raesene\ "wikilink")
Colin Watson
Simone Onofri
[Amro AlOlaqi](/User:Amro_Ahmed\ "wikilink")

All above are authors of the [Testing Guide v3](/OWASP_Testing_Guide_v3_Table_of_Contents_\ "wikilink")

[Ryan Dewhurst](/User:Ryan_Dewhurst\ "wikilink")
[Frank Catucci](/User:Frank.catucci_\ "wikilink")
[Vin Miller](/User:VinMiller_\ "wikilink")

Related articles
================

-   OWASP [Testing Guide](/:Category:OWASP_Testing_Project\ "wikilink")
-   Mozilla [Web Security Verification](https://wiki.mozilla.org/WebAppSec/Web_Security_Verification)

Other Cheatsheets
=================

[Category:Cheatsheets](/Category:Cheatsheets "wikilink") [Category:OWASP_Breakers](/Category:OWASP_Breakers "wikilink")
