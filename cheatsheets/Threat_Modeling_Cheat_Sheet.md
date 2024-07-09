# Threat Modeling Cheat Sheet

## Introduction

Threat modeling is an important concept for modern application developers to understand. This goal of this cheatsheet is provide a concise, but actionable, reference for both those new to threat modeling and those seeking a refresher. The official project page is [https://owasp.org/www-project-threat-model/](https://owasp.org/www-project-threat-model/).

## Overview

In the context of application security, threat modeling is a structured, repeatable process used to gain actionable insights into the security characteristics of a particular system. It involves modeling a system from a security perspective, identifying applicable threats based on this model, and determining responses to these threats. Threat modeling analyzes a system from an adversarial perspective, focusing on ways in which an attacker can exploit a system.

Threat modeling is ideally performed early in the SDLC, such as during the design phase. Moreover, it is not something that is performed once and never again. A threat model is something that should be maintained, updated and refined alongside the system. Ideally, threat modeling should be integrated seamlessly into a team's normal SDLC process; it should be treated as standard and necessary step in the process, not an add-on.

According to the [Threat Model Manifesto](https://www.threatmodelingmanifesto.org/), the threat modeling process should answer the following four questions:

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good enough job?

These four questions will act as the foundation for the four major phases described below.

## Advantages

Before turning to an overview of the process, it may be worth addressing the question: why threat model? Why bother adding more work to the development process? What are the benefits? The following section will briefly outline some answers to these questions.

### Identify Risks Early-On

Threat modeling seeks to identify potential security issues during the design phase. This allows security to be "built-into" a system rather than "bolted-on". This is far more efficient than having to identify and resolve security flaws after a system is in production.

### Increased Security Awareness

Proper threat modeling requires participants to think creatively and critically about the security and threat landscape of a specific application. It challenges individuals to "think like an attacker" and apply general security knowledge to a specific context. Threat modeling is also typically a team effort with members being encouraged to share ideas and provide feedback on others. Overall, threat modeling can prove to be a highly educational activity that benefits participants.

### Improved Visibility of Target of Evaluation (TOE)

Threat modeling requires a deep understanding of the system being evaluated. To properly threat model, one must understand data flows, trust boundaries, and other characteristics of the system. Thus, [Stiliyana Simeonova](https://securityintelligence.com/threat-modeling-in-the-enterprise-part-1-understanding-the-basics/) asserts that improved visibility into a system and its interactions is one advantage of threat modeling.

## Addressing Each Question

There is no universally accepted industry standard for the threat modeling process, no "right" answer for every use case. However, despite this diversity, most approaches do include the the processes of system modeling, threat identification, and risk response in some form. Inspired by these commonalities and guided by the four key questions of threat modeling discussed above, this cheatsheet will break the threat modeling down into four basic steps: application decomposition, threat identification and ranking, mitigations, and review and validation. There are processes that are less aligned to this, including PASTA and OCTAVE, each of which has passionate advocates.

### System Modeling

The step of system modeling seeks to answer the question "what are we building"? Without understanding a system, one cannot truly understand what threats are most applicable to it; thus, this step provides a critical foundation for subsequent activities. Although different techniques may be used in this first step of threat modeling, data flow diagrams (DFDs) are arguably the most common approach.

DFDs allow one to visually model a system and its interactions with data and other entities; they are created using a [small number of simple symbols](https://github.com/adamshostack/DFD3). DFDs may be created within dedicated threat modeling tools such as [OWASP's Threat Dragon](https://github.com/OWASP/threat-dragon) or [Microsoft's Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) or using general purpose diagraming solutions such as [draw.io](https://draw.io). If you prefer an -as-code approach, [OWASP's pytm](https://owasp.org/www-project-pytm/) can help there. Depending on the scale and complexity of the system being modeled, multiple DFDs may be required. For example, one could create a DFD representing a high-level overview of the entire system along with a number of more focused DFDs which detail sub-systems. Technical tools are not strictly necessary; whiteboarding may be sufficient in some instances, though it is preferable to have the DFDs in a form that can be easily stored, referenced, and updated as needed.

Regardless of how a DFD or comparable model is generated, it is important that the solution provides a clear view of trust boundaries, data flows, data stores, processes, and the external entities which may interact with the system. These often represent possible attack points and provide crucial input for the subsequent steps.

Another approach to Data Flow Diagrams (DFD) could be the brainstorming technique, which is an effective method for generating ideas and discovering the project's domain. Applying brainstorming in this context can bring numerous benefits, such as increased team engagement, unification of knowledge and terminology, a shared understanding of the domain, and quick identification of key processes and dependencies. One of the main arguments for using brainstorming is its flexibility and adaptability to almost any scenario, including business logic. Additionally, this technique is particularly useful when less technical individuals participate in the session, as it eliminates barriers related to understanding and applying the components of DFD models and their correctness.

Brainstorming engages all participants, fostering better communication and mutual understanding of issues. Every team member has the opportunity to contribute, which increases the sense of responsibility and involvement. During a brainstorming session, participants can collaboratively define and agree on key terms and concepts, leading to a unified language used in the project. This is especially important in complex projects where different teams might have different approaches to terminology. Due to the dynamic nature of brainstorming, the team can quickly identify key business processes and their interrelations.

Integrating the results of brainstorming with formal modeling techniques can lead to a better understanding of the domain and more effective system design.

### Threat Identification

After the system has been modeled, it is now time to address the question of "what can go wrong?". This question must be explored with the inputs from the first step in mind; that is, it should focus on identifying and ranking threats within the context of the specific system being evaluated. In attempting to answer this question, threat modelers have a wealth of data sources and techniques at their disposal. For illustration purposes, this cheatsheet will leverage STRIDE; however, in practice, other approaches may be used alongside or instead of STRIDE.

STRIDE is a mature and popular threat modeling technique and mnemonic originally developed by Microsoft employees. To facilitate threat identification, STRIDE groups threats into one of six general prompts and engineers are encouraged to systematically consider how these general threats may materialize within the context of the specific system being evaluated. Each STRIDE threat may be considered a violation of a desirable security attribute; the categories and associated desirable attributes are are as follows:

| Threat Category             | Violates          | Examples                                                                                                    |
| --------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------- |
| **S**poofing                | Authenticity      | An attacker steals the authentication token of a legitimate user and uses it to impersonate the user.       |
| **T**ampering               | Integrity         | An attacker abuses the application to perform unintended updates to a database.                             |
| **R**epudiation             | Non-repudiability | An attacker manipulates logs to cover their actions.                                                        |
| **I**nformation Disclosure  | Confidentiality   | An attacker extract data from a database containing user account info.                                      |
| **D**enial of Service       | Availability      | An attacker locks a legitimate user out of their account by performing many failed authentication attempts. |
| **E**levation of Privileges | Authorization     | An attacker tampers with a JWT to change their role.                                                        |

STRIDE provides valuable structure for responding to the question of "what can go wrong". It is also a highly flexible approach and getting started need not be complex. Simple techniques such as brainstorming and whiteboarding or even [games](https://github.com/adamshostack/eop/) may be used initially. STRIDE is also incorporated into popular threat modeling tools such as [OWASP's Threat Dragon](https://github.com/OWASP/threat-dragon) and [Microsoft's Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool). Additionally, as a relatively high-level process, STRIDE pairs well with more tactical approaches such as kill chains or [MITRE's ATT&CK](https://attack.mitre.org/) (please refer to [this article](https://blog.isc2.org/isc2_blog/2020/02/under-attack-how-mitres-methodology-to-find-threats-and-embed-counter-measures-might-work-in-your-or.html) for an overview of how STRIDE and ATT&CK can work together).

After possible threats have been identified, people will frequently rank them. In theory, ranking should be based on the mathematical product of an identified threat's likelihood and its impact. A threat that is likely to occur and result in serious damage would be prioritized much higher than one that is unlikely to occur and would only have a moderate impact. However, these both can be challenging to calculate, and they ignore the work to fix a problem. Some advocate for including that in a single prioritization.

### Response and Mitigations

Equipped with an understanding of both the system and applicable threats, it is now time to answer "what are we going to do about it"?. Each threat identified earlier must have a response. Threat responses are similar, but not identical, to risk responses. [Adam Shostack](https://shostack.org/resources/threat-modeling) lists the following responses:

- **Mitigate:** Take action to reduce the likelihood that the threat will materialize.
- **Eliminate:** Simply remove the feature or component that is causing the threat.
- **Transfer:** Shift responsibility to another entity such as the customer.
- **Accept:** Do not mitigate, eliminate, or transfer the risk because none of the above options are acceptable given business requirements or constraints.

If one decides to mitigates a threat, mitigation strategies must be formulated and documented as requirements. Depending on the complexity of the system, nature of threats identified, and the process used for identifying threats (STRIDE or another method), mitigation responses may be applied at either the category or individual threat level. In the former case, the mitigation would apply to all threats within that category. Mitigations strategies must be actionable not hypothetical; they must be something that can actually be built into to the system being developed. Although mitigations strategies must be tailored to the particular application, resources such as as [OWASP's ASVS](https://owasp.org/www-project-application-security-verification-standard/) and [MITRE's CWE list](https://cwe.mitre.org/index.html) can prove valuable when formulating these responses.

### Review and Validation

Finally, it is time to answer the question "did we do a good enough job"? The threat model must be reviewed by all stakeholders, not just the development or security teams. Areas to focus on include:

- Does the DFD (or comparable) accurately reflect the system?
- Have all threats been identified?
- For each identified threat, has a response strategy been agreed upon?
- For identified threats for which mitigation is the desired response, have mitigation strategies been developed which reduce risk to an acceptable level?
- Has the threat model been formally documented? Are artifacts from the threat model process stored in such a way that it can be accessed by those with "need to know"?
- Can the agreed upon mitigations be tested? Can success or failure of the requirements and recommendations from the the threat model be measured?

## Threat Modeling and the Development Team

### Challenges

Threat modeling can be challenging for development teams for several key reasons. Firstly, many developers lack sufficient knowledge and experience in the field of security, which hinders their ability to effectively use methodologies and frameworks, identify, and model threats. Without proper training and understanding of basic security principles, developers may overlook potential threats or incorrectly assess their risks.

Additionally, the threat modeling process can be complex and time-consuming. It requires a systematic approach and in-depth analysis, which is often difficult to reconcile with tight schedules and the pressure to deliver new functionalities. Development teams may feel a lack of tools and resources to support them in this task, leading to frustration and discouragement.

Another challenge is the communication and collaboration between different departments within the organization. Without effective communication between development teams, security teams, and other stakeholders, threat modeling can be incomplete or misdirected.

### Addressing the Challenges

In many cases, the solution lies in inviting members of the security teams to threat modeling sessions, which can significantly improve the process. Security specialists bring essential knowledge about potential threats that is crucial for effective identification, risk analysis, and mitigation. Their experience and understanding of the latest trends and techniques used by cybercriminals can provide key insights for learning and developing the competencies of development teams. Such joint sessions not only enhance developers' knowledge but also build a culture of collaboration and mutual support within the organization, leading to a more comprehensive approach to security.

To change the current situation, organizations should invest in regular IT security training for their development teams. These training sessions should be conducted by experts and tailored to the specific needs of the team. Additionally, it is beneficial to implement processes and tools that simplify and automate threat modeling. These tools can help in identifying and assessing threats, making the process more accessible and less time-consuming.

It is also important to promote a culture of security throughout the organization, where threat modeling is seen as an integral part of the Software Development Life Cycle (SDLC), rather than an additional burden. Regular review sessions and cross-team workshops can improve collaboration and communication, leading to a more effective and comprehensive approach to security. Through these actions, organizations can make threat modeling a less burdensome and more efficient process, bringing real benefits to the security of their systems.

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

### General Reference

- [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling) - resource list
- [Tactical Threat Modeling](https://safecode.org/wp-content/uploads/2017/05/SAFECode_TM_Whitepaper.pdf)
- [Threat Modeling: A Summary of Available Methods](https://insights.sei.cmu.edu/library/threat-modeling-a-summary-of-available-methods/)
- [Threat Modeling Handbook](https://security.cms.gov/policy-guidance/threat-modeling-handbook)
- [Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process)
- [The Ultimate Beginner's Guide to Threat Modeling](https://shostack.org/resources/threat-modeling)
