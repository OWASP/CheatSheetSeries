# Cloud Architecture Security Cheat Sheet

## Introduction

This cheat sheet will discuss common and necessary security patterns to follow when creating and reviewing **cloud architectures.** Each section will cover a specific security guideline or cloud design decision to consider. This sheet is written from a medium to large scale enterprise system, so additional overhead elements will be discussed, which may be unecessary for smaller organizations.


### Table of Contents
- Risk Analysis, Threat Modeling, and Attack Surface Modeling
- Public and Private Resources
- Trust Boundaries
- Security Tooling
- Tooling Limitations
- Managed vs Un-Managed Tooling

- TODO Additional Resources


## General Guidelines

### Risk Analysis, Threat Modeling, and Attack Surface Assessments

With any application or architecture, understanding the risk and threats is extremely important for properly security. No one can spend their entire budget or bandwidth focus on security, and a product must be delivered at some point, so properly allocating security resources is necessary.
With this in mind, enterprises must perform risk assessments, threat modeling activites, and attack surface assessments to identify the following:

- What threats an application might face
- The likelihood of those threats actualizing as attacks
- The attack surface with which those attacks could be targeted
- The business impact of losing data or functionality due to said attack

This is all necessary to properly scope the security of an architecture. However, these are all separate subjects that can/should be discussed in greater detail. Use the resources link below to investigate further as part of a health secure architecture convesation.

- [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
- [TODO RISK SHEET]()


### Public and Private Resources



### Trust Boundaries

*Note: This diverges in some key ways from Zero Trust. For a more in depth look at that topic, check out [CISA's Zero Trust Maturity Model](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)*.

#### Defining Trust Boundaries
Trust boundaries are one of the most important considerations within a secure architecture. Simply defined, these boundaries are connections between components within a system where some or all of the connection is trusted by the components. 



## Additional Resources
- [Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
