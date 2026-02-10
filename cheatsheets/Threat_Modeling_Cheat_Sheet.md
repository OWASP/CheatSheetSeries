# Threat Modeling Cheat Sheet

## Introduction

Threat modeling is a structured approach to identify and mitigate security threats in a system. This cheat sheet provides a concise, actionable guide for modern application developers, whether you're just getting started or looking for a refresher.
For a more detailed explanation, see the OWASP [Threat Modeling project](https://owasp.org/www-project-threat-modeling/)

## Overview

Threat modeling is a structured, repeatable process used to identify and respond to potential security threats in a system. It involves modeling a system from an attacker’s perspective to gain actionable insights and determine effective mitigations.

Threat modeling should be performed early in the SDLC and treated as a living activity, maintained and refined as the system evolves. It works best when integrated into normal development processes rather than treated as a one-time or optional task.

According to the [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/), the threat modeling process should answer the following four questions:

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good enough job?

These four questions will act as the foundation for the four major phases described below.

## Advantages

Why threat model? Threat modeling adds effort to the development process, so it’s reasonable to ask what value it provides. The following section briefly outlines the key benefits.

### Identify Risks Early On

Threat modeling identifies potential security issues during the design phase, allowing security to be "built in" rather than "bolted on." Fixing issues early is far more efficient than addressing them in production.

### Increased Security Awareness

Threat modeling encourages participants to think creatively and critically about the system from an attacker’s perspective, applying general security knowledge to a specific context. It is usually a team effort, promoting idea sharing and feedback, making it a highly educational activity.

### Improved Visibility of Target of Evaluation (TOE)

Effective threat modeling requires understanding the system itself, including data flows, trust boundaries, and interactions. As a result, teams gain improved visibility into how the system works and where security weaknesses may exist.

### Getting Started (Practical Tips)

While no single method is “the right way,” here’s a simple starting approach:

1. Map the system – Identify components, data flows, and boundaries.

2. List assets – What needs protection? Data, processes, services.

3. Identify threats – Use frameworks (STRIDE, CAPEC) or common attack patterns.

4. Rank & mitigate – Prioritize based on risk and implement protections.

5. Review & iterate – Revisit when architecture changes or new threats emerge.

This workflow gives a practical entry point while respecting the craft of threat modeling. Advanced techniques, patterns, and examples are available in the [Threat Modeling project](https://owasp.org/www-project-threat-modeling/)

## Addressing Each Question

There is no universally accepted industry standard for the threat modeling process, and no single “right” answer for every use case. That said, most approaches include system modeling, threat identification, and risk response in some form.

Guided by the four key questions discussed above, this cheat sheet organizes threat modeling into four practical steps: application decomposition, threat identification and ranking, mitigations, and review and validation.

Other methodologies exist, some of which are less closely aligned with this structure and have their own advocates.

### System Modeling

One practical way to start is to model your system using **Data Flow Diagrams (DFDs)**; other approaches may also work depending on your context.

System modeling answers the question: "What are we building?" Understanding the system is essential to identifying relevant threats and provides the foundation for subsequent threat modeling activities.

A common approach is to use **Data Flow Diagrams (DFDs)** to visually model processes, data flows, data stores, trust boundaries, and external entities—highlighting potential attack points. Tools such as [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon), [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool), [draw.io](https://draw.io), or [OWASP pytm](https://owasp.org/www-project-pytm/) can be used. Whiteboarding is possible for simple systems, but diagrams should be stored and maintained.

For complex systems, multiple DFDs may be needed, ranging from high-level overviews to detailed sub-system diagrams.

**Tip:** Brainstorming sessions can complement DFDs, particularly in early stages or when involving less technical participants, helping teams clarify terminology, identify key processes, and build a shared understanding of the system.

### Cloud Threat Modeling

Most modern systems are cloud-native or hybrid. Traditional threat modeling techniques (such as STRIDE or DFDs) often require adaptation for cloud architectures, which introduce shared responsibility models, managed services and APIs, multi-tenant and federated identity, and highly dynamic infrastructure (IaC, serverless, containers).

Cloud threat modeling should explicitly account for cloud-specific components and responsibilities, including identity and access management (IAM), virtual networks, managed services, data storage, and the division of security controls between the cloud provider and the customer. Dynamic and ephemeral environments, such as container orchestration platforms and serverless functions, also require special attention, as assets and trust boundaries may change rapidly.

Cloud threat modeling frameworks such as AWS’s [Well-Architected Framework – Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) can serve as useful references.

### Threat Identification

After the system has been modeled, the next step is to address the question: *what can go wrong?* This step focuses on identifying and ranking threats **within the context of the specific system**, using outputs from the system modeling phase.

There are many techniques and data sources available for threat identification. For illustration purposes, this cheat sheet uses **STRIDE**, though other approaches may be used alongside or instead of it in practice.

**STRIDE** is a well-established threat modeling technique originally developed by Microsoft. It provides a structured way to consider potential threats and encourages engineers to systematically examine how each category could materialize in the system. Each STRIDE threat represents a violation of a desirable security attribute:

| Threat Category             | Violates          | Examples                                                                                                    |
| --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------- |
| **S**poofing                | Authentication   | An attacker steals the authentication token of a legitimate user and impersonates them.                     |
| **T**ampering               | Integrity        | An attacker performs unintended updates to a database or modifies data in transit.                           |
| **R**epudiation             | Accounting       | An attacker manipulates logs to hide their actions.                                                         |
| **I**nformation Disclosure  | Confidentiality  | An attacker extracts sensitive user data from a database or system.                                         |
| **D**enial of Service       | Availability     | An attacker prevents legitimate users from accessing the system.                                            |
| **E**levation of Privileges | Authorization    | An attacker modifies a token or configuration to gain higher privileges.                                     |

STRIDE is flexible and easy to start with. Simple techniques such as **brainstorming**, **whiteboarding**, or even [games](https://github.com/adamshostack/eop/) can help teams generate potential threats. STRIDE is also supported in popular tools such as [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) and [Microsoft’s Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool). Additionally, STRIDE pairs well with **tactical approaches** such as kill chains or [MITRE ATT&CK](https://attack.mitre.org/), enabling a bridge from high-level threats to practical countermeasures. See [this overview](https://web.isc2ncrchapter.org/under-attck-how-mitres-methodology-to-find-threats-and-embed-counter-measures-might-work-in-your-organization/) for guidance on integrating STRIDE and ATT&CK.

Once threats have been identified, they are often **ranked**. Ranking is ideally based on a combination of:

1. **Likelihood** — how probable is the threat?
2. **Impact** — what is the potential damage if it occurs?

High-likelihood, high-impact threats are prioritized first. However, estimating these values can be challenging, and teams may also consider **effort to remediate** as part of prioritization. Some practitioners advocate combining all three factors into a single prioritization metric for clarity.

### Response and Mitigations

With an understanding of the system and its applicable threats, the next step is to answer the question: *what are we going to do about it?* Each identified threat must have a defined response. Threat responses are related to, but not the same as, traditional risk responses. Adam Shostack identifies the following response options:

- **Mitigate:** Reduce the likelihood or impact of the threat.
- **Eliminate:** Remove the feature or component that introduces the threat.
- **Transfer:** Shift responsibility to another entity, such as a customer or third party.
- **Accept:** Acknowledge the threat without further action due to business or technical constraints.

When a threat is mitigated, mitigation strategies should be documented as concrete, actionable requirements. Depending on the threat modeling approach and system complexity, mitigations may be applied at either the threat category level or the individual threat level.

Reference materials such as [OWASP’s ASVS](https://owasp.org/www-project-application-security-verification-standard/) and [MITRE’s CWE list](https://cwe.mitre.org/index.html) can help guide the selection of appropriate mitigations.

### Review and Validation

The final step answers the question: *did we do a good enough job?* The completed threat model must be reviewed by all relevant stakeholders, not just the development or security teams.

Key review questions include:

- Does the system model (e.g., DFD) accurately reflect the system?
- Have all relevant threats been identified?
- Has a response strategy been defined for each identified threat?
- For threats requiring mitigation, do the proposed controls reduce risk to an acceptable level?
- Has the threat model been formally documented and stored for future reference?
- Can the agreed-upon mitigations be tested, and can their effectiveness be measured?

## Threat Modeling and the Development Team

### Challenges

Threat modeling can present several challenges for development teams. Developers may lack sufficient security knowledge or experience, making it difficult to correctly apply threat modeling methodologies or identify relevant threats.

The process can also be time-consuming and hard to align with tight development timelines, especially if teams lack adequate tools or resources. Furthermore, ineffective communication and collaboration between development, security, and other stakeholders can lead to incomplete or misaligned threat models.

### Addressing the Challenges

Challenges can be mitigated by involving security specialists in threat modeling sessions, ensuring relevant expertise is present during threat identification, analysis, and mitigation.

Organizations should invest in regular security training for development teams and adopt tools and processes that simplify and support threat modeling activities.

Finally, fostering a security-focused culture—where threat modeling is treated as a standard part of the SDLC—improves cross-team collaboration and integrates security considerations into everyday development practices.

## References

### Methods and Techniques

An alphabetical list of techniques:

- [LINDDUN](https://linddun.org/)
- [PASTA](https://cdn2.hubspot.net/hubfs/4598121/Content%20PDFs/VerSprite-PASTA-Threat-Modeling-Process-for-Attack-Simulation-Threat-Analysis.pdf)
- [STRIDE](<https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823878(v=cs.20)?redirectedfrom=MSDN>)
- [OCTAVE](https://insights.sei.cmu.edu/library/introduction-to-the-octave-approach/)
- [VAST](https://go.threatmodeler.com/vast-methodology-data-sheet)

### Tools

- [Cairis](https://github.com/cairis-platform/cairis)
- [draw.io](https://draw.io) - see also [threat modeling libraries](https://github.com/michenriksen/drawio-threatmodeling) for the tool
- [IriusRisk](https://www.iriusrisk.com/) - offers a free Community Edition
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [OWASP's Threat Dragon](https://github.com/OWASP/threat-dragon)
- [OWASP's pytm](https://owasp.org/www-project-pytm/)
- [TaaC-AI](https://github.com/yevh/TaaC-AI) - AI-driven Threat modeling-as-a-Code (TaaC)
- Threat Composer - [Demo](https://awslabs.github.io/threat-composer), [Repository](https://github.com/awslabs/threat-composer/)

### General Reference

- [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling) - resource list
- [Tactical Threat Modeling](https://safecode.org/wp-content/uploads/2017/05/SAFECode_TM_Whitepaper.pdf)
- [Threat Modeling: A Summary of Available Methods](https://insights.sei.cmu.edu/library/threat-modeling-a-summary-of-available-methods/)
- Threat modeling for builders, free online training available on [AWS SkillBuilder](https://explore.skillbuilder.aws/learn/course/external/view/elearning/13274/threat-modeling-for-builders-workshop), and [AWS Workshop Studio](https://catalog.workshops.aws/threatmodel/en-US)
- [Threat Modeling Handbook](https://security.cms.gov/policy-guidance/threat-modeling-handbook)
- [Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process)
- [The Ultimate Beginner's Guide to Threat Modeling](https://shostack.org/resources/threat-modeling)
