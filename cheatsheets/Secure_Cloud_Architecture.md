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


#### Defining Trust Boundaries
Trust boundaries are connections between components within a system where a trust decision has to be made by the components. Another way to phrase it, this boundary is a point where two components with potentially different trust levels meet. These boundaries can range in scale, from the degrees of trust given to users interacting with an application, to trusting or verifying specific claims between code functions or components within a cloud architecture. Generally speaking however, trusting each component to perform its function correctly and securely suffices. Therefore, trust boundaries mainly occur in the connections between cloud components, and between the application and third party elements, like end users and other vendors.  

As an example of a trust boundary, consider the architecture below. An API gateway connects to multiple compute instances in a chain. Separately, there exists an authentication server, which can verify the integrity of a Json Web Token at any stage of the process. As shown by the dotted lines, trust boundaries exist between each compute component, the API gateway and the authentication server, even though many or all of the elements could be apart of the same organization's applications. 

**PICTURE HERE**



#### Exploring Different Trust Boundary Configurations


*Note: This diverges in some key ways from Zero Trust. For a more in depth look at that topic, check out [CISA's Zero Trust Maturity Model](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)*.


## Additional Resources
- [Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
