# Legacy Application Management Cheat Sheet

## Introduction

Legacy applications are applications that are recognised as being outdated but remain in active use by an organisation. This may occur if a viable alternative to the application is not available, is currently infeasibly expensive, or if the application is highly bespoke and services a very niche role within an organisation's digital ecosystem. Legacy applications often introduce significant security risks to an organisation for the following reasons:

- Legacy applications might have reached End-of-Life (EoL) meaning that the application no longer receives patching or vendor support. This drastically increases the risk of an unmitigated zero day being left in an exploitable state on the application.
- Some applications have been built using technologies that are no longer conventionally used or taught to technical staff. This might mean that the knowledge required to troubleshoot fix vulnerabilities when they arise may be lacking.
- Legacy applications may produce data in custom formats, use old interfaces or networking protocols that may stifle efforts to use data produced by the applications with services used for vulnerability management or security logging, such as a SIEM (Security Information and Event Management) solution.

As there is no one-size fits all approach to securing legacy applications, this cheat sheet is intended to act as a resource offering some practical suggestions on securing legacy applications when alternatives to the use of legacy applications do not exist. The preferred approach will depend on factors such as the data stored and produced by the legacy application, whether the application and associated infrastructure has know vulnerabilities that cannot be patched, how much it is possible to restrict access to use of the legacy application. Engaging with security domain experts (in-house or external) who can provide specific and contextualised advice may be necessary.

## Inventory and Asset Management

At a baseline, organisations should have a clear understanding about what legacy software are in current use and what the expected risks of the use of these legacy solutions are.

**Inventory Management:** Start by compiling documentation identifying legacy applications used by your organisation, version numbers, date of production, and relevant configuration settings. Ideally, this will include details related to what network/s can be used to access the product and what services are running on infrastructure used for hosting the application or running the application database, for instance. This could also include information about the physical location and permitted access to associated infrastracture hosted on-premises. In circumstances, it might also be useful to maintain a formal SBOM (Software Bill of Materials), which serves a useful role when an application relies on third-party dependencies in order to function.

**Risk Assessment:** Next, ensure your organisation has a clear understanding of the level of risk posed to the organisation by the legacy application/specific components of the legacy application. This may be a formal process that is informed by undertaking threat-modeling of an application, as described in the [OWASP Threat Modeling Cheat Sheet](/cheatsheets/Threat_Modeling_Cheat_Sheet.md). Qualifying the risk posed by legacy software might also be aided by using an industry standard risk assessment framework, such as the NIST (National Institure of Standards and Technology) [Risk Management Framework](https://csrc.nist.gov/Projects/risk-management).

As a more informal indicator of how conservative security measures to protect the application ought to be, consider the following questions which might help to contextualize what the risk profile of a particular legacy application or it's components might be:

- What information is handled/stored by the application? Furthermore, if this information were to be compromised, how would this impact your business and potentially its regulatory requirements.
- Do the application/application dependencies/infrastucture used for deploying the application have known vulnerabilities and, if so, how easily exploitable are these?
- How criticial is the availability of the legacy application to your organisation's business continuity?
- If an attacker were able to gain access to this application, is there a risk that they could use this to exfiltrate other information from or establish acess to a particularly privileged network or environment?

## Authorization

Authorization measures enforce rules around who can access a given resource and how they can establish access to that resource. Authorization is covered in significant depth in the [OWASP Authorization Cheat Sheet](/cheatsheets/Authorization_Cheat_Sheet.md).

Specifically, when it comes to applying authorization controls to legacy systems, organisations should consider these to be inherently high risk. Therefore, the security principle of least privilege (allowing only as much access as is strictly required for staff/users to perform required roles and to facilitate business operations) particularly applies to the use of legacy software. Consider implementing the following as applicable:

- Apply network-level authorization controls to the application. This might entail hosting the application within a restricted subnet and/or applying IP allow-listing to prevent users interacting particularly with public-facing legacy applications from arbitrary hosts.
- Authorization controls could be considered at a more granular level by reducing the feature set available to end users. For example, it might be necessary to disable certain administrative functionalities entirely.
- Ensure that only authenticated users can access the application. This might be enforced by the application itself, by use of an IdP (Identity Provider) service. If the application is hosted in a restricted network environment, authentication should also be required to access this network environment. Implementing one or more of these controls will both slow down an attacker and will assist with investigations if an incident were to occur. See the [OWASP Authentication Cheet Sheet](/cheatsheets/Authentication_Cheat_Sheet.md) for further information pertaining to authentication management.
- Close any ports on hosts used to run the application that are not required for use in order for the application to perform strictly what is needed by the organisation. Access to certain ports may also be restricted using firewall/application firewall rules to lock down server infrastrure.
- For situations where an application is hosted/supported by on premises infrastructure, like physical web and database servers, disable ports that can be used for access to management interfaces, e.g. IPMI (Intelligent Platform Management Interface).

## Vulnerability Management

**Vulnerability Scanning:** Legacy applications should be subject to regular vulnerability scanning with an industry standard vulnerability assessment tool, such as Nessus and Qualys. This should occur on a regular basis, ideally with scans scheduled to occur automatically at some time interval. Where appropirate, some vulnerabilities might also be identified using code scanning tools, such as a SAST (Static Application Security Testing) tool or SCA (Software Composition Analysis) for checking the currency of dependencies used to support the application.

**Patch Management:** Where possible, apply patches raised by the tools described above. Patching efforts should be prioritized on the basis of the severity of the vulnerability and whether the vulnerability has a published CVE (Common Vulnerabilities and Exposures) and a publicly listed exploit. In circumstances where patching is not practically possible for the legacy application, consider applying additional restrictions to the application/affected component as noted in the section on Authorization.

## Data Storage

Confirm that, where ever possible, data handled by the application is both encrypted at rest (i.e. when stored in a database) and in transit. Cheat Sheets on [Cryptographic Storage](/cheatsheets/Cryptographic_Storage_Cheat_Sheet.md) and [HTTP Strict Transport Security](/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md) may provide some useful further context. In some circumstances legacy applications might be restricted to the use of older network protocols that only support tranmission of data in clear-text. In this case and particularly if it is expected that sensitive data will be transmitted to and from the application in its network environment, it is especially important to apply the most restrictive network conditions possible to the application, which in extreme cases might necessitate temporary or permanent air-gapping (functional isolation) of the application.

## Ensuring Maintainability

It may be necessary to maintain a high degree of institutional expertise regarding the application, so that it is possible for staff to both remediate security vulnerabilities and troubleshoot the application when needed to ensure business continuity. The following recommendations apply:

- Ideally more than one staff member should be adequately trained to the extent of being able to resolve basic bugs or troubleshoot/reconfigure the legacy application as needed. This will reduce the risk of catastrophic loss of capability regarding maintanence of the legacy application if one member of staff leaves the organisation.
- Encourage staff to regularly document processes including recording troubleshoot guides for common failure scenarios for the legacy application.

## Change Management

Where ever feasible the ultimate goal will be to shift from the use of unmantainable legacy applications to a solution which is both maintainable and architected to be resilient to threats. Staged change management planning will need to take into account the following factors:

- What budget can practically be allocated to upgrading to a modern solution and within what timeframe?
- Do people with the necessary expertise to do the technical work required to handle this exist within your organisation or could these people be acquired/developed?
- How urgently does a migration to an upgraded solution need to happen?

A change management plan, formal or informal, should include a clear description of granular steps towards migration to an upgraded solution, an explicit date of expected completion, a clear articulation of the business and security case for the change. To produce a realistic plan for migration staff involved in overseeing and using the existing solution should be consulted extensively to get a sense for how critical the legacy application is to your organisation and what constraints there might be to facilitating migration.

## Continuous Monitoring and Incident Response

Legacy applications should be subject to an especially high degree of security monitoring and rapid response to potential incidents. This might be challenged by intra-operability issues that mean that logs produced by the application are in a format that cannot be ingested by security monitoring tools by your organisation. Potential work arounds might include:

- Developing custom APIs for modifiying security applicable information from your legacy application/legacy application logs into a format ingestable by security monitoring solutions used by your organisations.
- Where the above is not possible consider using automation scripts to generate reports that can be reviewed by staff at regular intervals that assess for indicators of compromise.
- Be vigilant to any anomolous network traffic into and out of the legacy application environment and to any surges in network activity.
- If you have access to an incident response team, ensure that they are aware that incident response and investigation of unusual events should be prioritised for critical legacy systems.

## Disaster Recovery Planning

Backups, staff procedures, etc..

## References
