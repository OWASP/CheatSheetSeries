# Legacy Application Management Cheat Sheet

## Introduction

Legacy applications are applications that are recognised as being outdated but remain in active use by an organisation. This may occur if a viable alternative to the application is not available, is currently infeasibly expensive, or if the application is highly bespoke and services a very niche role within an organisation's digital ecosystem. Legacy applications often introduce significant security risks to an organisation for the following reasons:

- Legacy applications might have reached End-of-Life (EoL) meaning that the application no longer receives patching or vendor support. This drastically increases the risk of an unmitigated zero day being left in an exploitable state on the application.
- Some applications have been built using technologies that are no longer conventionally used or taught to technical staff. This might mean that the knowledge required to troubleshoot fix vulnerabilities when they arise may be lacking.
- Legacy applications may produce data in custom formats, use old interfaces or networking protocols that may stifle efforts to use data produced by the applications with services used for vulnerability management or security logging, such as a SIEM (Security Information and Event Management) solution.

There is no one-size fits all approach to securing legacy applications. The preferred approach will depend on factors such as the data stored and produced by the legacy application, whether the application and associated infrastructure has know vulnerabilities that cannot be patched, how much it is possible to restrict access to use of the legacy application.

## Inventory and Asset Management

At a baseline, organisations should have a clear understanding about what legacy software are in current use and what the expected risks of the use of these legacy solutions are.

**Inventory Management:** Start by compiling documentation identifying legacy applications used by your organisation, version numbers, date of production, and relevant configuration settings. Ideally, this will include details related to what network/s can be used to access the product and what services are running on infrastructure used for hosting the application or running the application database, for instance. This could also include information about the physical location and permitted access to associated infrastracture hosted on-premises. In circumstances, it might also be useful to maintain a formal SBOM (Software Bill of Materials), which serves a useful role when an application relies on third-party dependencies in order to function.

**Risk Assessment:** Next, ensure your organisation has a clear understanding of the level of risk posed to the organisation by the legacy application/specific components of the legacy application. This may be a formal process that is informed by undertaking threat-modeling of an application, as described in the [OWASP Threat Modeling Cheat Sheet](/cheatsheets/Threat_Modeling_Cheat_Sheet.md). Qualifying the risk posed by legacy software might also be aided by using an industry standard risk assessment framework, such as the NIST (National Institure of Standards and Technology) [Risk Management Framework](https://csrc.nist.gov/Projects/risk-management).

As a more informal indicator of how conservative security measures to protect the application ought to be, consider the following questions which might help to contextualize what the risk profile of a particular legacy application or it's components might be:

- What information is handled/stored by the application? Furthermore, if this information were to be compromised, how would this impact your business and potentially its regulatory requirements.
- Do the application/application dependencies/infrastucture used for deploying the application have known vulnerabilities and, if so, how easily exploitable are these?
- How criticial is the availability of the legacy application to your organisation's business continuity?
- If an attacker were able to gain access to this application, is there a risk that they could use this to exfiltrate other information from or establish acess to a particularly privileged network or environment?

## Access Controls

Will be the content that deals with who and how these assets can be managed.

## Vulnerability Management

Program expectations for vulnerability management. 

## Data Storage

How we handle data at rest and in transmission; can we encrypt data associated with the legacy system at all.

## Ensuring Maintainability

Staff training, having more than 1 person able to assist with troubleshooting the legacy application.

## Change Management

Including over the longer term considering ways that you are able to migrate from this legacy application to something that will be maintainable. 

## Continuous Monitoring and Incident Response

Keeping staff trained, having appropriate logging up and running so that it is possible to run investigations.

## Disaster Recovery Planning

Backups, staff procedures, etc..

## References

A