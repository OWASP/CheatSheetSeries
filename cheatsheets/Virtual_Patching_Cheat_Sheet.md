# Virtual Patching Cheat Sheet

## Introduction

The goal with this cheat Sheet is to present a concise virtual patching framework that organizations can follow to maximize the timely implementation of mitigation protections.

## Definition: Virtual Patching

**A security policy enforcement layer which prevents and reports the exploitation attempt of a known vulnerability.**

The virtual patch works when the security enforcement layer analyzes transactions and intercepts attacks in transit, so malicious traffic never reaches the web application. The resulting impact of virtual patching is that, while the actual source code of the application itself has not been modified, the exploitation attempt does not succeed.

## Why Not Just Fix the Code

From a purely technical perspective, the number one remediation strategy would be for an organization to correct the identified vulnerability within the source code of the web application. This concept is universally agreed upon by both web application security experts and system owners. Unfortunately, in real world business situations, there arise many scenarios where updating the source code of a web application is not easy such as:

- **Lack of resources** - Devs are already allocated to other projects.
- **Third-party Software** - Code can not be modified by the user.
- **Outsourced App Dev** - Changes would require a new project.

The important point is this - **Code level fixes and Virtual Patching are NOT mutually exclusive**. They are processes that are executed by different team (OWASP Builders/Devs vs. OWASP Defenders/OpSec) and can be run in tandem.

## Value of Virtual Patching

The two main goals of Virtual Patching are:

- **Minimize Time-to-Fix** - Fixing application source code takes time. The main purpose of a virtual patch is to implement a mitigation for the identified vulnerability as soon as possible. The urgency of this response may be different: for example if the vulnerability was identified in-house through code reviews or penetration testing vs. finding a vulnerability as part of live incident response.
- **Attack Surface Reduction** - Focus on minimizing the attack vector. In some cases, such as missing positive security input validation, it is possible to achieve 100% attack surface reduction. In other cases, such with missing output encoding for XSS flaws, you may only be able to limit the exposures. Keep in mind - 50% reduction in 10 minutes is better than 100% reduction in 48 hrs.

## Virtual Patching Tools

Notice that the definition above did not list any specific tool as there are a number of different options that may be used for virtual patching efforts such as:

- Intermediary devices such as a WAF or IPS appliance
- Web server plugin such as ModSecurity
- Application layer filter such as ESAPI WAF

For example purposes, we will show virtual patching examples using the open source [ModSecurity WAF tool](http://www.modsecurity.org).

## A Virtual Patching Methodology

Virtual Patching, like most other security processes, is not something that should be approached haphazardly. Instead, a consistent, repeatable process should be followed that will provide the best chances of success. The following virtual patching workflow mimics the industry accepted practice for conducting IT Incident Response and consists of the following phases:

1. Preparation.
2. Identification.
3. Analysis.
4. Virtual Patch Creation.
5. Implementation/Testing.
6. Recovery/Follow Up.

## Example Public Vulnerability

Let's take the following [SQL Injection vulnerability](https://packetstormsecurity.com/files/119217/WordPress-Shopping-Cart-8.1.14-Shell-Upload-SQL-Injection.html) as our example for the remainder of this article:

```text
WordPress Shopping Cart Plugin for WordPress
/wp-content/plugins/levelfourstorefront/scripts/administration/exportsubscribers.php
reqID Parameter prone to SQL Injection.
```

**Description**:

WordPress Shopping Cart Plugin for WordPress contains a flaw that may allow an attacker to carry out an SQL injection attack.

The issue is due to the `/wp-content/plugins/levelfourstorefront/scripts/administration/exportsubscribers.php` script not properly sanitizing user-supplied input to the `reqID` parameter.

This may allow an attacker to inject or manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.

## Preparation Phase

The importance of properly utilizing the preparation phase with regards to virtual patching cannot be overstated. You need to do a number of things to setup the virtual patching processes and framework **prior** to actually having to deal with an identified vulnerability, or worse yet, react to a live web application intrusion. The point is that during a live compromise is not the ideal time to be proposing installation of a web application firewall and the concept of a virtual patch. Tension is high during real incidents and time is of the essence, so lay the foundation of virtual patching when the waters are calm and get everything in place and ready to go when an incident does occur.

Here are a few critical items that should be addressed during the preparation phase:

- **Public/Vendor Vulnerability Monitoring** - Ensure that you are signed up for all vendor alert mail-lists for commercial software that you are using. This will ensure that you will be notified in the event that the vendor releases vulnerability information and patching data.
- **Virtual Patching Pre-Authorization** – Virtual Patches need to be implemented quickly so the normal governance processes and authorizations steps for standard software patches need to be expedited. Since virtual patches are not actually modifying source code, they do not require the same amount of regression testing as normal software patches. Categorizing virtual patches in the same group as Anti-Virus updates or Network IDS signatures helps to speed up the authorization process and minimize extended testing phases.
- **Deploy Virtual Patching Tool In Advance** - As time is critical during incident response, it would be a poor time to have to get approvals to install new software. For instance, you can install ModSecurity WAF in embedded mode on your Apache servers, or an Apache reverse proxy server. The advantage with this deployment is that you can create fixes for non-Apache back-end servers. Even if you do not use ModSecurity under normal circumstances, it is best to have it "on deck" ready to be enabled if need be.
- **Increase HTTP Audit Logging** – The standard Common Log Format (CLF) utilized by most web servers does not provide adequate data for conducting proper incident response. You need to have access to the following HTTP data:
    - Request URI (including QUERY_STRING)
    - Full Request Headers (including Cookies)
    - Full Request Body (POST payload)
    - Full Response Headers
    - Full Response Body

## Identification Phase

The Identification Phase occurs when an organization becomes aware of a vulnerability within their web application. There are generally two different methods of identifying vulnerabilities: `Proactive` and `Reactive`.

### Proactive Identification

This occurs when an organization takes it upon themselves to assess their web security posture and conducts the following tasks:

- **Dynamic Application Assessments** - Ethical attackers conduct penetration tests or automated web assessment tools are run against the live web application to identify flaws.
- **Source code reviews** - Ethical attackers use manual/automated means to analyze the source code of the web application to identify flaws.

Due to the fact that custom coded web applications are unique, these proactive identification tasks are extremely important as you are not able to rely upon third-party vulnerability notifications.

### Reactive Identification

There are three main reactive methods for identifying vulnerabilities:

- **Vendor contact (e.g. pre-warning)** - Occurs when a vendor discloses a vulnerability for commercial web application software that you are using. Example is Microsoft's [Active Protections Program (MAPP)](https://www.microsoft.com/en-us/msrc/mapp)
- **Public disclosure** - Public vulnerability disclosure for commercial/open source web application software that you are using. The threat level for public disclosure is increased as more people know about the vulnerability.
- **Security incident** – This is the most urgent situation as the attack is active. In these situations, remediation must be immediate.

## Analysis Phase

Here are the recommended steps to start the analysis phase:

1. **Determine Virtual Patching Applicability** - Virtual patching is ideally suited for injection-type flaws but may not provide an adequate level of attack surface reduction for other attack types or categories. Thorough analysis of the underlying flaw should be conducted to determine if the virtual patching tool has adequate detection logic capabilities.
2. **Utilize Bug Tracking/Ticketing System** - Enter the vulnerability information into a bug tracking system for tracking purposes and metrics. Recommend you use ticketing systems you already use such as Jira or you may use a specialized tool such as [ThreadFix](https://threadfix.it/).
3. **Verify the name of the vulnerability** - This means that you need to have the proper public vulnerability identifier (such as CVE name/number) specified by the vulnerability announcement, vulnerability scan, etc. If the vulnerability is identified proactively rather than through public announcements, then you should assign your own unique identifier to each vulnerability.
4. **Designate the impact level** - It is always important to understand the level of criticality involved with a web vulnerability. Information leakages may not be treated in the same manner as an SQL Injection issue.
5. **Specify which versions of software are impacted** - You need to identify what versions of software are listed so that you can determine if the version(s) you have installed are affected.
6. **List what configuration is required to trigger the problem** - Some vulnerabilities may only manifest themselves under certain configuration settings.
7. **List Proof of Concept (PoC) exploit code or payloads used during attacks/testing** - Many vulnerability announcements have accompanying exploit code that shows how to demonstrate the vulnerability. If this data is available, make sure to download it for analysis. This will be useful later on when both developing and testing the virtual patch.

## Virtual Patch Creation Phase

The process of creating an accurate virtual patch is bound by two main tenants:

1. **No false positives** - Do not ever block legitimate traffic under any circumstances.
2. **No false negatives** - Do not ever miss attacks, even when the attacker intentionally tries to evade detection.

Care should be taken to attempt to minimize either of these two rules. It may not be possible to adhere 100% to each of these goals but remember that virtual patching is about **Risk Reduction**. It should be understood by business owners that while you are gaining the advantage of shortening the Time-to-Fix metric, you may not be implementing a complete fix for the flaw.

### Manual Virtual Patch Creation

#### Positive Security (Allow List) Virtual Patches (**Recommended Solution**)

Positive security model (allowlist) is a comprehensive security mechanism that provides an independent input validation envelope to an application. The model specifies the characteristics of valid input (character set, length, etc…) and denies anything that does not conform. By defining rules for every parameter in every page in the application the application is protected by an additional security envelop independent from its code.

##### Example Allow List ModSecurity Virtual Patch

In order to create an allow-list virtual patch, you must be able to verify what the normal, expected input values are. If you have implemented proper audit logging as part of the Preparation Phase, then you should be able to review audit logs to identify the format of expected input types. In this case, the `reqID` parameter is supposed to only hold integer characters so we can use this virtual patch:

```text
##
## Verify we only receive 1 parameter called "reqID"
##
SecRule REQUEST_URI "@contains /wp-content/plugins/levelfourstorefront/scripts/administration/exportsubscribers.php" "chain,id:1,phase:2,t:none,t:Utf8toUnicode,t:urlDecodeUni,t:normalizePathWin,t:lowercase,block,msg:'Input Validation Error for \'reqID\' parameter - Duplicate Parameters Names Seen.',logdata:'%{matched_var}'"
  SecRule &ARGS:/reqID/ "!@eq 1"

##
## Verify reqID's payload only contains integers
##
SecRule REQUEST_URI "@contains /wp-content/plugins/levelfourstorefront/scripts/administration/exportsubscribers.php" "chain,id:2,phase:2,t:none,t:Utf8toUnicode,t:urlDecodeUni,t:normalizePathWin,t:lowercase,block,msg:'Input Validation Error for \'reqID\' parameter.',logdata:'%{args.reqid}'"
  SecRule ARGS:/reqID/ "!@rx ^[0-9]+$"
```

This virtual patch will inspect the `reqID` parameter value on the specified page and prevent any characters other than integers as input.

- **Note** - You should make sure to assign rule IDs properly and track them in the bug tracking system.
- **Caution**: There are numerous evasion vectors when creating virtual patches. Please consult the [OWASP Best Practices: Virtual Patching document](https://owasp.org/www-community/Virtual_Patching_Best_Practices) for a more thorough discussion on countering evasion methods.

#### Negative Security (Block List) Virtual Patches

A negative security model (denylist) is based on a set of rules that detect specific known attacks rather than allow only valid traffic.

##### Example Block List ModSecurity Virtual Patch

Here is the example [PoC code](https://packetstormsecurity.com/files/119217/WordPress-Shopping-Cart-8.1.14-Shell-Upload-SQL-Injection.html) that was supplied by the public advisory:

```text
http://localhost/wordpress/wp-content/plugins/levelfourstorefront/scripts/administration/exportsubscribers.php?reqID=1' or 1='1
```

Looking at the payload, we can see that the attacker is inserting a single quote character and then adding additional SQL query logic to the end. Based on this data, we could disallow the single quote character like this:

```text
SecRule REQUEST_URI "@contains /wp-content/plugins/levelfourstorefront/scripts/administration/exportsubscribers.php" "chain,id:1,phase:2,t:none,t:Utf8toUnicode,t:urlDecodeUni,t:normalizePathWin,t:lowercase,block,msg:'Input Validation Error for \'reqID\' parameter.',logdata:'%{args.reqid}'"
  SecRule ARGS:/reqID/ "@pm '"
```

#### Which Method is Better for Virtual Patching – Positive or Negative Security

A virtual patch may employ either a positive or negative security model. Which one you decide to use depends on the situation and a few different considerations. For example, negative security rules can usually be implemented more quickly, however the possible evasions are more likely.

Positive security rules, only the other hand, provides better protection however it is often a manual process and thus is not scalable and difficult to maintain for large/dynamic sites. While manual positive security rules for an entire site may not be feasible, a positive security model can be selectively employed when a vulnerability alert identifies a specific location with a problem.

#### Beware of Exploit-Specific Virtual Patches

You want to resist the urge to take the easy road and quickly create an **exploit-specific virtual patch**.

For instance, if an authorized penetration test identified an XSS vulnerability on a page and used the following attack payload in the report:

```html
<script>
  alert('XSS Test')
</script>
```

It would not be wise to implement a virtual patch that simply blocks that exact payload. While it may provide some immediate protection, its long term value is significantly decreased.

### Automated Virtual Patch Creation

Manual patch creation may become unfeasible as the number of vulnerabilities grow and automated means may become necessary. If the vulnerabilities were identified using automated tools and an XML report is available, it is possible to leverage automated processes to auto-convert this vulnerability data into virtual patches for protection systems.

Three examples include:

- **OWASP ModSecurity Core Rule Set (CRS) Scripts** - The OWASP CRS includes scripts to auto-convert XML output from tools such as [OWASP ZAP into ModSecurity Virtual Patches]. Reference [here](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/modsecurity-advanced-topic-of-the-week-automated-virtual-patching-using-owasp-zed-attack-proxy).
- **ThreadFix Virtual Patching** - ThreadFix also includes automated processes of converting imported vulnerability XML data into virtual patches for security tools such as ModSecurity. Reference [here](https://github.com/denimgroup/threadfix/wiki/Waf-Types#mod_security).
- **Direct Importing to WAF Device** - Many commercial WAF products have the capability to import DAST tool XML report data and automatically adjust their protection profiles.

## Implementation/Testing Phase

In order to accurately test out the newly created virtual patches, it may be necessary to use an application other than a web browser. Some useful tools are:

- Web browser.
- Command-line web clients such as Curl and Wget.
- Local Proxy Servers such as [OWASP ZAP](https://www.zaproxy.org/).
- [ModSecurity AuditViewer](https://web.archive.org/web/20181011065823/http://www.jwall.org/web/audit/viewer.jsp) – which allows you to load a ModSecurity audit log file, manipulate it and then re-inject the data back into any web server.

### Testing Steps

- Implement virtual patches initially in a "Log Only" configuration to ensure that you do not block any normal user traffic (false positives).
- If the vulnerability was identified by a specific tool or assessment team - request a retest.
- If retesting fails due to evasions, then you must go back to the Analysis phase to identify how to better fix the issue.

## Recovery/Follow-Up Phase

- **Update Data in Ticket System** - Although you may need to expedite the implementation of virtual patches, you should still track them in your normal Patch Management processes. This means that you should create proper change request tickets, etc… so that their existence and functionality is documented. Updating the ticket system also helps to identify "time-to-fix" metrics for different vulnerability types. Make sure to properly log the virtual patch rule ID values.
- **Periodic Re-assessments** - You should also have periodic re-assessments to verify if/when you can remove previous virtual patches if the web application code has been updated with the real source code fix. I have found that many people opt to keep virtual patches in place due to better identification/logging vs. application or db capabilities.
- **Running Virtual Patch Alert Reports** - Run reports to identify if/when any of your virtual patches have triggered. This will show value for virtual patching in relation to windows of exposure for source code time-to-fix.

## References

- [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices).
- [OWASP Securing WebGoat with ModSecurity](https://wiki.owasp.org/index.php/Category:OWASP_Securing_WebGoat_using_ModSecurity_Project).
