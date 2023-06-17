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

Placeholder

Placeholder

Placeholder



### Trust Boundaries


#### Defining Trust Boundaries
Trust boundaries are connections between components within a system where a trust decision has to be made by the components. Another way to phrase it, this boundary is a point where two components with potentially different trust levels meet. These boundaries can range in scale, from the degrees of trust given to users interacting with an application, to trusting or verifying specific claims between code functions or components within a cloud architecture. Generally speaking however, trusting each component to perform its function correctly and securely suffices. Therefore, trust boundaries mainly occur in the connections between cloud components, and between the application and third party elements, like end users and other vendors.  

As an example of a trust boundary, consider the architecture below. An API gateway connects to multiple compute instances in a chain. Separately, there exists an authentication server, which can verify the integrity of a Json Web Token at any stage of the process. As shown by the dotted lines, trust boundaries exist between each compute component, the API gateway and the authentication server, even though many or all of the elements could be apart of the same organization's applications. 

**PICTURE HERE**



#### Exploring Different Levels of Trust
In the example from the last section, the trust boundaries existed between each element. This section will explore the differences between certain configurations of trust on said boundaries. For each example below, additional elements will be added to better explain the implications of trusting a certain resource. The "business criticality" as a number from 1 (lowest) to 5 (highest) will identify which resources are most important in the scenario. The threat level of a specific resource as a color from green (safe) to red (dangerous) will outline which resources should likely hold the least trust.


##### 1. No trust example:
As shown in the diagram below, this example outlines a model where no component trusts any other component, regardless of criticality or threat level. This type of trust configuration would likely be used for incredibly high risk applications, where either very personal data or important business data would be exposed, or where the application as a whole has an extremely high criticality for the company. Notice that each component calls out to the authentication server. This implies that no data passing between each component, even when "inside" the application, is considered trusted. 

**PICTURE HERE**

This could be a necessary approach for certain applications with incredibly high risk of compromise. However, security must be careful when advocating for this model, as it will have significant performance and maintenance drawbacks. 

|            Pros               |         Cons          |
|:-----------------------------:|:---------------------:|
| High assurance data integrity | Slow and inefficient  |
|       Defense in depth        |      Complicated      |
|                               | Likely more expensive |

##### 2. High trust example:
Next, consider the an opposite approach, where everything is trusted. In this instance, the "dangerous" user input is trusted and essentially handed directly to a high criticality business component. The authentication resource is not used at all. In this instance, there would be a high likelihood that an attack of some kind would occur against the system, because there are no controls in place to prevent it. Additionally, this setup could be considred wasteful, as both the API gateway and the authentication server are not necessarily performing their intended function.

**PICTURE HERE**

This is an unlikely architecture for all but the simplest and lowest risk applications. **Do not use this trust boundary configuration** unless there is no sensitive content to protect or efficiency is the only metric for success. Generally speaking, trusting user input is never recommended, even in low risk applications.

| Pros      | Cons                    |
|:---------:|:-----------------------:|
| Efficient |        Insecure         |
|  Simple   |        Wasteful         |
|           | High risk of compromise |


##### 3. Some trust example:
Most applications will need trust boundary configuration like this. Using knowledge from the risk and attack surface analysis in section 1, security can reasonably assign trust to low risk components or processes, and verify only when necessary to protect business critical resources. This will prevent wasting valuable security resources, but also limit the complexity and efficiency loss due to additional security overhead.

**PICTURE HERE**

By nature, this approach limits the pros and cons of both previous examples. This model should be used for most applications, unless the benefits of the above examples are absolutely necessary to meet business requirements.

|              Pros             |          Cons          |
|:-----------------------------:|:----------------------:|
|     Secured based on risk     | Known gaps in security |
| Cost derived from criticality |                        |


*Note: This trust methodology diverges from Zero Trust. For a more in depth look at that topic, check out [CISA's Zero Trust Maturity Model](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)*.


## Additional Resources
- [Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
