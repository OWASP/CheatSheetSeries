---
title: Denial of Service Cheat Sheet
permalink: /Denial_of_Service_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
Last revision (mm/dd/yy): **//**

DRAFT CHEAT SHEET - WORK IN PROGRESS
====================================

Introduction
============

__TOC__

This article is focused on providing clear, simple, actionable defense guidance for preventing denial of service in your web applications. Denial of Service attacks are very common due to two factors :

1.  The significant prevalence of cloud and web services
2.  Easy to get testing tools to cause denial of service attacks.

Because it's very simple to launch the DOS attack, any web services don't have Anti-DOS defenses mitigation in place will be vulnerable to DOS attacks.

To avoid and mitigate DOS attack, both developers and operations engineering will need to have layered of defenses in place:

a) Service: When the service is built, it's developed with anti-DOS in mind such Input validation, Resource handling, Size or Length validation.

b) Web Host: Every Web server such Apache, NginX or Linux host provides the configuration of connection. Properly configure these network configuration may also help to mitigate the DOS attacks.

c) Infrastructure: Signature-based or behavior detection firewalls, load balance, fail-over, cloud anti-DDoS service

This objective of the article is to provide a list of common techniques for preventing DOS attack regardless of technology and platforms.

Coding/Design Defenses
======================

### Mitigation 1: Input validation

### Mitigation 2: Resource

### Mitigation 3: Limit length and size

### Mitigation 4: API rate limits

### Typical Denial Of Service Cases

-   CVE-2002-0298 Server allows remote attackers to cause a denial of service via certain HTTP GET requests containing a %2e%2e (encoded dot-dot), several "/../" sequences, or several "../" in a URI.
-   CVE-2000-0655 Chat client allows remote attackers to cause a denial of service or execute arbitrary commands via a JPEG image containing a comment with an illegal field length of 1.
-   CVE-2001-1186 Web server allows remote attackers to cause a denial of service via an HTTP request with a content-length value that is larger than the size of the request, which prevents server from timing out the connection.
-   CVE-2004-0095 Policy manager allows remote attackers to cause a denial of service (memory consumption and crash) and possibly execute arbitrary code via an HTTP POST request with an invalid Content-Length value.
-   CVE-2004-0774 Server allows remote attackers to cause a denial of service (CPU and memory exhaustion) via a POST request with a Content-Length header set to -1.
-   CVE-2002-1023 Server allows remote attackers to cause a denial of service (crash) via an HTTP GET request without a URI.
-   CVE-2002-1077 Crash in HTTP request without a Content-Length field.
-   CVE-2004-0276 Server earlier allows remote attackers to cause a denial of service (crash) via an HTTP request with a sequence of "%" characters and a missing Host field.

Web Services Defenses
=====================

General web services protection against DOS can be listed as 3 main approach

1.  Max connection per IP address
2.  Max size of every HTTP request
3.  Timeout value of each HTTP request connection

NginX secure configuration
--------------------------

#### 1. Max Connection

`# Connection limit configurations`
`limit_conn ip_limit_zone 64;`

`# Keep Alive connection will help every http request connection to reuse the same TCP connection.`
`keepalive_requests    100;`

<http://nginx.org/en/docs/http/ngx_http_core_module.html>

#### 2. Request Size

Limit the size of http request to mitigate the buffer overflow attack

`client_body_buffer_size  100K;`
`client_header_buffer_size 1k;`
`client_max_body_size 100k;`
`large_client_header_buffers 2 1k;`

#### 3. Connection Timeout

Define the connection timeout value.

`client_body_timeout   10;`
`client_header_timeout 10;`
`keepalive_timeout     5 5;`
`keepalive_requests    100;`
`send_timeout          10;`

Apache secure configuration
---------------------------

#### 1. Max Connection

\#Define the max Http requests connection is allowed per TCP connection.

`MaxKeepAliveRequests 100`

\# Reuses the same TCP port per client connection.

`KeepAlive On`

\#Timeout value per connection to free up the server resources.

#### 2. Request Size

\#Limit the size of request Body (100K)

`LimitRequestBody 102400`

http://httpd.apache.org/docs/2.4/mod/core.html\#limitrequestbody 

#### 3. Connection Timeout 

\#Define the general timeout value of every connection.

`Timeout 10`

http://httpd.apache.org/docs/2.4/mod/core.html\#timeout

`KeepAliveTimeout 15`

http://httpd.apache.org/docs/2.4/mod/core.html\#keepalive

Network Infrastructure Defenses
===============================

Deployment of layered anti-DDOS defenses.

### SSL Configuraiton

### Load Balance

### Firewall

-   IP Whitelist or Blacklist

### Cloud-based Anti-DDOS services

Related Articles
================

<https://cwe.mitre.org/data/index.html>

<https://www.securecoding.cert.org/>

Authors and Primary Editors
===========================

[Tony Hsu](/User:Tony_Hsu_HsiangChih\ "wikilink") - hsiang_chih\[at\]yahoo.com
== Other Cheatsheets ==

[Category:Cheatsheets](/Category:Cheatsheets "wikilink") [Category:Popular](/Category:Popular "wikilink")