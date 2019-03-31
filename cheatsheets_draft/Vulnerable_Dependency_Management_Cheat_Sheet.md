# Introduction

The objective of the cheat sheet is to provide a proposal of approach to handle the fixation of vulnerable third-party dependencies when they are detected, and this, depending on different situation.

The cheat sheet is not tools oriented but it contains a *tools* section providing pointer to software (free and commercial) that can be used to detect vulerable dependencies, if possible, in a cross-technology way because it's now rare that project use a single technology. 

# Context

Most of the project use third-party dependencies to delegate handling of differents kind of operations like generation of document in a specific format, HTTP communications, data parsing of a specific format...

It's a good approach because it allow the development team to focus on the real application code supporting the expected business feature. The downside is that when one of the dependencies used is impacted by a security issue then it impact also the security posture of the application itself.

This aspect is referenced in the:
* [OWASP TOP 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project) under the point *[A9 - Using Components with Known Vulnerabilities](https://www.owasp.org/index.php/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities)*.
* [OWASP Application Security Verification Standard Project](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project) under the section *V14.2 Dependency*.

Due to this context, it's important for a project to ensure that all the third-party dependencies used do not suffer for any security issue OR if they contains security issues then the developmment team is aware of that and mitigation measures are in place.

It's highly recommanded to perform automated analysis of the dependencies from the day one of the project. Indeed, if this task is added at the middle or end of the project it can imply a amount of work to handle all the issues identified that will not be possible to handle by the developmement team since a long time.

**Note:** In the rest of the cheat sheet, when we refer to *development team* then we assume that the team contain an member with application security skills or can ask help to someone in the company having these kind of skills.

# Remark about the detection

It's important to keep in mind the different way in which a security issue is handled after is discovery. 

*Way 1: [Responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure)*

Someone find a issue on a component and collaborate with the provider leading, most of the time, to the creation of a [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures) (sometime a specific vulnerability identifier to the provider is created but generally a CVE identifier is preferred) associated to the issue allowing the public referencing of the issue and sometime the available fixation/mitigation (sometime provider [do not want to fix the issue](https://www.excellium-services.com/cert-xlm-advisory/cve-2019-7161/)). 

In this way, the exploitation code/method is only provided to the provider of the component and not publicly disclosed.

Here the vulnerability is always referenced in the [CVE global database](https://nvd.nist.gov/vuln/data-feeds) used, generally, by the detection tools as one of the several input source used.

*Way 2: [Full disclosure](https://en.wikipedia.org/wiki/Full_disclosure_(computer_security)#Full_disclosure)*

Someone find a issue on a component and release all the information including exploitation code/method on site like [Full Disclosure mailing list](https://seclists.org/fulldisclosure/), [Exploit-DB](https://www.exploit-db.com/)...

Here a CVE is not always created then the vulnerability is not in the CVE global database causing the detection tools to be blind about this issue unless they use other input sources.

Conclusion, it's important to ensure, during the selection process of a vulnerable dependency detection tool, that this one use several reliable input sources in order to handle the both vulnerability disclosure ways.

# Remark about the security issue handling decision

When a securit issue is detected, it's also possible to decide to accept the risk represented by the security issue. However, this decision must be taken by the [Chief Risk Officer](https://en.wikipedia.org/wiki/Chief_risk_officer) (fallback possible to [Chief Information Security Officer](https://en.wikipedia.org/wiki/Chief_information_security_officer)) of the company based on technical feedback from the development team that have analysed the issue (see the *[Cases](#-cases)* section) as well as the CVE's [CVSS](https://www.first.org/cvss/user-guide) score indicators.

# Cases

When a security issue is detected, the development team can meet one of the situation (named *case* in the rest of the cheat sheet) presented in the sub sections below.

If the vulnerably impact a [transitive dependency](https://en.wikipedia.org/wiki/Transitive_dependency) then the action will be taken on the direct dependency of the project. Acting on a transitive dependency often impact the stability of the application. 

Acting on a on a transitive dependency require the developmement team to fully understand the complete relation/communicatin/usage from the project first level dependency until the dependency impacted by the security vulnerability, this task is amazingly time consuming.

## Case 1

### Context

Patched version of the component has been released by the provider.

### Ideal condition of application of the approach

Set of automated unit or integration or functionnal or security tests exists for the features of the application using the impacted dependency allowing to validate that the feature is operational.

### Approach

**Step 1:**
Update the version of the dependency in the project.

**Step 2:**
Run the tests, 2 output path possibles:
* All test succeeds, the update can be considered as validated.
* One or several tests failed, several output path possible:
    * Failure is due to change in some functions called (signature, argument, package...), calling code must be adapted and we go back to the begin of this step.
    * Technical incompatibility of the released dependency (require a more recent runtime version...) so the following actions can be taken:
        1. Raise the issue to the provider.
        2. During the waiting time of a feedback from the provider, apply the [Case 2](#-case-2).

## Case 2

### Context

Provider inform the team that it will take a while to fix the issue and, so, a patched version will not been available before months.

### Ideal condition of application of the approach

Provider can give the exploitation code and/or the list of impacted functions by the vulnerability, or better, a workarounk to prevent the exploitation of the issue.

### Approach

**Step 1:**

If a workaround is provided then applied it.

If a workaround is not provided then if the provider has given the list of the impacted functions then add protection code before the call to these function to ensure that the input data used to call the function is safe. 

It's also possible to add the protection measure at security device level (ex: Web Application Firewall) but we have decided here to show how to do it at the application level because, as the application is the nearest exploitaton point, it can apply specific tunned countermeasure and exploit detection alerting. Moreover, sometime security device cannot be leveraged (ex: issue in the applicatin authorization matrix).

*Example using java code in which the impacted function suffer from a [Remote Code Execution](https://www.netsparker.com/blog/web-security/remote-code-evaluation-execution/) issue:*

```java
public void callFunctionWithRCEIssue(String externalInput){
    //Apply input validation on the external input using regex
    if(Pattern.matches("[a-zA-Z0-9]{1,50}", externalInput)){
        //Call the flawed function using safe input
        functionWithRCEIssue(externalInput);
    }else{
        //Log the detection of exploitation
        SecurityLogger.warn("Exploitation of the RCE issue XXXXX detected !");
        //Raise an exception leading to a generic error send to the client...
    }
}
```

If the provider has provided nothing about the vulnerability then apply the [Case 3](#-case-3) skipping the *step 2* of this case. We assume here that, at least, the [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures) has been provided.

**Step 2:**

If the provider has given the exploitation code then try to execute it against the features where protection code has been added in order to verify that the protection code is effective.

If you have a set of automated unit or integration or functionnal or security tests that exists for the application then run them to verify that the protection code added do not imapct the stability of the application.

Add a comment in the project *README* explaining that the issue (specify the related [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)) is handled during the waiting time of a patched version because the detection tool will continue to raise an alert on this dependency. 

**Note:** You can add the dependency to the ignore list but the ignore scope for this dependency must only cover the [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures) related to the vulnerability because a dependency can be impacted by several vulnerabilities having each one is proper [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures).

## Case 3

### Context

Provider inform the team that he cannot fix the issue so no patched version will be released at all (apply also if provider do not want to fix the issue or do not answer at all).

The only information given to the development team is the [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures).

**Note:** This case is really complex and time consuming and is generally used as last resort.

### Ideal condition of application of the approach

Nothing specific because here we are in *patch yourself* condition.

### Approach

**Step 1:**

If we are in this case due to one of the following condition, it's a good idea to start a parallel study to find another component better maintained or if it's a commercial component with support **then put pressure** on the provider with the help of your [Chief Risk Officer](https://en.wikipedia.org/wiki/Chief_risk_officer) (fallback possible to [Chief Information Security Officer](https://en.wikipedia.org/wiki/Chief_information_security_officer)):
* Provider do not want to fix the issue.
* Provider do not answer at all.

In all cases, here, we need to handle the vulnerability right now...

**Step 2:**

As we know the vulnerable dependency, we know where it is used in the application (if it's a transitive dependency then we can identify the first level dependency using it using the [IDE](https://en.wikipedia.org/wiki/Integrated_development_environment) built-in feature or the dependency management system used (Maven, Gradle, Nuget, NPM...). Note that IDE is also used to identify call to the dependency. 

So, we can identify any call to this dependency but we still miss information about which kind of patching we must perform...

To obtain these informations, we use the CVE description to know which kind of vulnerability affect the dependency:
* The `description` give the answer: SQL injection, Remote Code Execution, Cross-Site Scripting, Cross-Site Request Forgery...

Now, we know which kind of patching we must perform (it's become similar to [Case 2](#case-2) with the protection code) and where to add it.

*Example:*

We have application using the Jackson API in a version exposed to the [CVE-2016-3720](https://nvd.nist.gov/vuln/detail/CVE-2016-3720).

The description of the CVE is:

```text
XML external entity (XXE) vulnerability in XmlMapper in the Data format extension for Jackson 
(aka jackson-dataformat-xml) allows attackers to have unspecified impact via unknown vectors.  
```

Based on these information, we determine that the patching will be to add a [pre-validation of any XML data](XML_External_Entity_Prevention_Cheat_Sheet.md) passed to the Jakson API to prevent [XML external entity (XXE)](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/) vulnerability.

**Step 3:**

If you have a set of automated unit or integration or functionnal or security tests that exists for the application then run them to verify that the patch do not impact the stability of the application.

# Tools

TODO:

# Authors and Primary Editors

TODO: