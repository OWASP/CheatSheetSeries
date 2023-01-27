# Network segmentation Cheat Sheet

## Introduction

Network segmentation is the core of multi-layer defense in depth for modern services. Segmentation slow down an attacker if he cannot implement attacks such as:

- SQL-injections, see [SQL Injection Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md);
- compromise of workstations of employees with elevated privileges;
- compromise of another server in the perimeter of the organization;
- compromise of the target service through the compromise of the LDAP directory, DNS server, and other corporate services and sites published on the Internet.

The main goal of this cheat sheet is to show the basics of network segmentation to effectively counter attacks by building a secure and maximally isolated service network architecture.

Segmentation will avoid the following situations:

- executing arbitrary commands on a public web server (NginX, Apache, Internet Information Service) prevents an attacker from gaining direct access to the database;
- having unauthorized access to the database server, an attacker cannot access CnC on the Internet.

## Content

- Schematic symbols;
- Three-layer network architecture;
- Interservice interaction;
- Network security policy;
- Useful links.

## Schematic symbols

Elements used in network diagrams:

![Schematic symbols](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_Schematic_symbols.drawio.png)

Crossing the border of the rectangle means crossing the firewall:
![Traffic passes through two firewalls](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_firewall_1.drawio.png)

In the image above, traffic passes through two firewalls with the names FW1 and FW2

![Traffic passes through one firewall](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_firewall_2.drawio.png)

In the image above, traffic passes through one firewall, behind which there are two VLANs

Further, the schemes do not contain firewall icons so as not to overload the schemes

## Three-layer network architecture

By default, developed information systems should consist of at least three components (**security zones**):

1. [FRONTEND](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md#FRONTEND);
2. [MIDDLEWARE](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md#MIDDLEWARE);
3. [BACKEND](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md#BACKEND).

### FRONTEND

FRONTEND - A frontend is a set of segments with the following network elements:

- balancer;
- application layer firewall;
- web server;
- web cache.

![FRONTEND](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_FRONTEND.drawio.png)

### MIDDLEWARE

MIDDLEWARE - a set of segments to accommodate the following network elements:

- web applications that implement the logic of the information system (processing requests from clients, other services of the company and external services; execution of requests);
- authorization services;
- analytics services;
- message queues;
- stream processing platform.

![MIDDLEWARE](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_MIDDLEWARE.drawio.png)

### BACKEND

BACKEND - a set of network segments to accommodate the following network elements:

- SQL database;
- LDAP directory (Domain controller);
- storage of cryptographic keys;
- file server.

![BACKEND](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_BACKEND.drawio.png)

### Example of Three-layer network architecture

![BACKEND](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_TIER_Example.drawio.png)
The following example shows an organization's local network. The organization is called "Сontoso".

The edge firewall contains 2 VLANs of **FRONTEND** security zone:

- _DMZ Inbound_ - a segment for hosting services and applications accessible from the Internet, they must be protected by WAF;
- _DMZ Outgoing_ - a segment for hosting services that are inaccessible from the Internet, but have access to external networks (the firewall does not contain any rules for allowing traffic from external networks).

The internal firewall contains 4 VLANs:

- **MIDDLEWARE** security zone contains only one VLAN with name _APPLICATIONS_ - a segment designed to host information system applications that interact with each other (interservice communication) and interact with other services;
- **BACKEND** security zone contains:
    - _DATABASES_ - a segment designed to delimit various databases of an automated system;
    - _AD SERVICES_ - segment designed to host various Active Directory services, in the example only one server with a domain controller Contoso.com is shown;
    - _LOGS_ - segment, designed to host servers with logs, servers centrally store application logs of an automated system.

## Interservice interaction

Usually some information systems of the company interact with each other. It is important to define a firewall policy for such interactions.
The base allowed interactions are indicated by the green arrows in the image below:
![Interservice interaction](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_interservice.drawio.png)
The image above also shows the allowed access from the FRONTEND and MIDDLEWARE segments to external networks (the Internet, for example).

From this image follows:

1. Access between FRONTEND and MIDDLEWARE segments of different information systems is prohibited;
2. Access from the MIDDLEWARE segment to the BACKEND segment of another service is prohibited (access to a foreign database bypassing the application server is prohibited).

Forbidden accesses are indicated by red arrows in the image below:
![Prohibited Interservice Communication](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_interservice_deny.drawio.png)

### Many applications on the same network

If you prefer to have fewer networks in your organization and host more applications on each network, it is acceptable to host the load balancer on those networks. This balancer will balance traffic to applications on the network.
In this case, it will be necessary to open one port to such a network, and balancing will be performed, for example, based on the HTTP request parameters.
An example of such segmentation:
![Interservice Communication with balancing](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_interservice_balancer.drawio.png)

As you can see, there is only one incoming access to each network, access is opened up to the balancer in the network. However, in this case, segmentation no longer works, access control between applications from different network segments is performed at the 7th level of the OSI model using a balancer.

## Network security policy

The organization must define a "paper" policy that describes firewall rules and basic allowed network access.
This policy is at least useful:

- network administrators;
- security representatives;
- IT auditors;
- architects of information systems and software;
- developers;
- IT administrators.

It is convenient when the policy is described by similar images. The information is presented as concisely and simply as possible.

### Examples of individual policy provisions

Examples in the network policy will help colleagues quickly understand what access is potentially allowed and can be requested.

#### Permissions for CI/CD

The network security policy may define, for example, the basic permissions allowed for the software development system. Let's look at an example of what such a policy might look like:
![CI-CD](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_repo.drawio.png)

#### Secure logging

It is important that in the event of a compromise of any information system, its logs are not subsequently modified by an attacker. To do this, you can do the following: copy the logs to a separate server, for example, using the syslog protocol, which does not allow an attacker to modify the logs, syslog only allows you to add new events to the logs.
The network security policy for this activity looks like this:
![Logging](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_logs.drawio.png)
In this example, we are also talking about application logs that may contain security events, as well as potentially important events that may indicate an attack.

#### Permissions for monitoring systems

Suppose a company uses Zabbix as an IT monitoring system. In this case, the policy might look like this:
![Zabbix-Example](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_Monitoring.drawio.png)

## Useful links

- Full network segmentation cheat sheet by [sergiomarotco](https://github.com/sergiomarotco): [link](https://github.com/sergiomarotco/Network-segmentation-cheat-sheet).
