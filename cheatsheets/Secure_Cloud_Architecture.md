# Cloud Architecture Security Cheat Sheet

## Introduction

This cheat sheet will discuss common and necessary security patterns to follow when creating and reviewing **cloud architectures.** Each section will cover a specific security guideline or cloud design decision to consider. This sheet is written from a medium to large scale enterprise system, so additional overhead elements will be discussed, which may be unecessary for smaller organizations.




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
Cloud resources often have public and private configuration settings, which while flexible, can lead to common pitfalls for developing secure cloud architectures. Generally speaking, resources should be configured for private use with dedicated public connections points for internet access. 

#### Object Storage
Object storage usually has multiple options for access data:

- Accessing resources using built in Identity and Access Management policies
- Using cryptographically signed URLs and HTTP request
- Direct access with public storage


##### IAM Access
This method involves using other tooling, like a website hosted on the cloud service, to interact with the object storage on the user's behalf. This method is best used when the application has other user interfaces available, when it is important to hide as much of the storage system as possible, or when the information is not direct user assets (metadata). It can be used in combination with web authentication and logging to better track and control access to resources.

|                 Pros                 |                  Cons                  |
|:------------------------------------:|:--------------------------------------:|
|       No direct access to table      |    Potential use of broad IAM policy   |
| No user visibility to object storage | Possibility to inject into custom code |
|   Identifiable and loggable access   |                                        |

This approach is acceptable for sensitive user data, but must follow rigorous coding and cloud best practices, in order to properly secure data.


##### Signed URLs
URL Signing for object storage involves using some method or either statically or dynamically generating URLs, which cryptographically guarantee that an entity can access a resource in storage. This is best used when direct access to specific user files is necessary or preferred, as there is no file transfer overhead. It is advisable to only use this method for user data which is not very sensitive. This method can be secure, but falls into some interesting pitfalls. Code injection may still be possible if the method of URL generation is custom, dynamic and injectable, and anyone can access the resource anonymously, if given the URL. 


|                    Pros                   |                  Cons                  |
|:-----------------------------------------:|:--------------------------------------:|
|        Access to only one resource        |            Anonymous Access            |
| Minimal user visibility to object storage |       Anyone can access with URL       |
|           Efficient file transfer         | Possibility to inject into custom code |

##### Public Object Storage

**This is not an advisable method for resource storage and distribution**, and should only be used for public, non-sensitive, non-specific resources. This storage approach will provide threat actors additional reconnaissance into a cloud environment, and any data which is stored in this configuration for any period of time must be considered publicly available.

|                 Pros                |                     Cons                     |
|:-----------------------------------:|:--------------------------------------------:|
| Efficient access to many resources  |         Anyone can access/No privacy         |
|       Simple public file share      |            Direct Access to table            |
|                                     | Possibly leak info mistakenly put in storage |

#### VPC and Subnet


#### Public vs Private compute?


Placeholder

Placeholder

Placeholder



### Trust Boundaries


#### Defining Trust Boundaries
Trust boundaries are connections between components within a system where a trust decision has to be made by the components. Another way to phrase it, this boundary is a point where two components with potentially different trust levels meet. These boundaries can range in scale, from the degrees of trust given to users interacting with an application, to trusting or verifying specific claims between code functions or components within a cloud architecture. Generally speaking however, trusting each component to perform its function correctly and securely suffices. Therefore, trust boundaries mainly occur in the connections between cloud components, and between the application and third party elements, like end users and other vendors.  

As an example of a trust boundary, consider the architecture below. An API gateway connects to multiple compute instances in a chain. Separately, there exists an authentication server, which can verify the integrity of a Json Web Token at any stage of the process. As shown by the dotted lines, trust boundaries exist between each compute component, the API gateway and the authentication server, even though many or all of the elements could be apart of the same organization's applications. 


![Trust Boundaries](../assets/Secure_Cloud_Architecture_Trust_Boundaries_1.png)



#### Exploring Different Levels of Trust
In the example from the last section, the trust boundaries existed between each element. This section will explore the differences between certain configurations of trust on said boundaries. For each example below, additional elements will be added to better explain the implications of trusting a certain resource. The "business criticality" as a number from 1 (lowest) to 5 (highest) will identify which resources are most important in the scenario. The threat level of a specific resource as a color from green (safe) to red (dangerous) will outline which resources should likely hold the least trust.


##### 1. No trust example:
As shown in the diagram below, this example outlines a model where no component trusts any other component, regardless of criticality or threat level. This type of trust configuration would likely be used for incredibly high risk applications, where either very personal data or important business data would be exposed, or where the application as a whole has an extremely high criticality for the company. Notice that each component calls out to the authentication server. This implies that no data passing between each component, even when "inside" the application, is considered trusted. Additionally, notice that there isn't trust between the authentication server and each component. While not displayed in the diagram, this would have additional impacts, like more rigorous checks before authentication, and more overhead dedicated to cryptographic operations.

![No Trust Across Boundaries](../assets/Secure_Cloud_Architecture_Trust_Boundaries_2.png)

This could be a necessary approach for certain applications with incredibly high risk of compromise or highly valuable data, such as those found in financial, military or energy systems. However, security must be careful when advocating for this model, as it will have significant performance and maintenance drawbacks. 

|            Pros               |         Cons          |
|:-----------------------------:|:---------------------:|
| High assurance data integrity | Slow and inefficient  |
|       Defense in depth        |      Complicated      |
|                               | Likely more expensive |

##### 2. High trust example:
Next, consider the an opposite approach, where everything is trusted. In this instance, the "dangerous" user input is trusted and essentially handed directly to a high criticality business component. The authentication resource is not used at all. In this instance, there would be a high likelihood that an attack of some kind would occur against the system, because there are no controls in place to prevent it. Additionally, this setup could be considred wasteful, as both the API gateway and the authentication server are not necessarily performing their intended function.

![Complete Trust Across Boundaries](../assets/Secure_Cloud_Architecture_Trust_Boundaries_3.png)

This is an unlikely architecture for all but the simplest and lowest risk applications. **Do not use this trust boundary configuration** unless there is no sensitive content to protect or efficiency is the only metric for success. Generally speaking, trusting user input is never recommended, even in low risk applications.

| Pros      | Cons                    |
|:---------:|:-----------------------:|
| Efficient |        Insecure         |
|  Simple   |        Wasteful         |
|           | High risk of compromise |


##### 3. Some trust example:
Most applications will need trust boundary configuration like this. Using knowledge from the risk and attack surface analysis in section 1, security can reasonably assign trust to low risk components or processes, and verify only when necessary to protect business critical resources. This will prevent wasting valuable security resources, but also limit the complexity and efficiency loss due to additional security overhead.

![Some Trust Across Boundaries](../assets/Secure_Cloud_Architecture_Trust_Boundaries_4.png)

By nature, this approach limits the pros and cons of both previous examples. This model should be used for most applications, unless the benefits of the above examples are absolutely necessary to meet business requirements.

|              Pros             |          Cons          |
|:-----------------------------:|:----------------------:|
|     Secured based on risk     | Known gaps in security |
| Cost derived from criticality |                        |


*Note: This trust methodology diverges from Zero Trust. For a more in depth look at that topic, check out [CISA's Zero Trust Maturity Model](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)*.


### Security Tooling




### Cloud Offering Limitations




### Managed vs Un-Managed Tooling




## Additional Resources
- [Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
