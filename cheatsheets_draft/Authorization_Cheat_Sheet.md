# Authorization Cheat Sheet

## Introduction

Authorization may be defined as "[t]he process of verifying that a requested action or service is approved for a specific entity" [NIST](https://csrc.nist.gov/glossary/term/authorization). Authorization is distinct from authentication which is the process of verifying an entity's identity. When designing and developing a software solution, it is important to keep these distinctions in mind. A user who has been authenticated (perhaps by providing a username and password) is often not authorized to access every resource and perform every action that is technically possible through a system. For example, a web app may have both regular users and admins, with the admins being able to perform actions the average user is not privileged to do so, even though have been authenticated. Additionally, authentication is not always required for accessing resources; an unauthenticated user may be authorized to access certain public resources, such as an image or login page, or even an entire web app.

Flaws related to authorization logic are a notable concern for web apps. Broken Access Control was ranked as the fifth most concerning web security vulnerability in [OWASP's 2017 Top 10](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control) and asserted to have a "High" likelihood of exploit by [MITRE's CWE program](https://cwe.mitre.org/data/definitions/285.html). Furthermore, according to [Veracode's State of Software Vol. 10](https://www.veracode.com/sites/default/files/pdf/resources/sossreports/state-of-software-security-volume-10-veracode-report.pdf), Access Control was among the more common of OWASP's Top 10 to be involved in exploits and security incidents despite being among the least prevalent of those examined.

The potential impact resulting from exploitation of authorization flaws is highly variable, both in form and severity. Attackers may be able read, create, modify, or delete resources that were meant to be protected (thus jeopardizing their confidentiality, integrity, and/or availability); however, the actual impact of such actions is necessarily linked to the criticality and sensitivity of the compromised resources. Thus, the business cost of a successfully exploited authorization flaw can range from very low to extremely high.

The objective of this cheat sheet is to assist developers in implementing authorization logic that is robust, appropriate to the app's business context, maintainable, and scalable. The guidance provided in this cheat sheet should be applicable to all phases of the development lifecycle and flexible enough to meet the needs of diverse development environments.

## Threat Model

## Recommendations

### Enforce Least Privileges

As a security concept, Least Privileges refers to the principle of assigning users only the minimum privileges necessary to complete their job. Although perhaps most commonly applied in system administration, this principle has relevance to the software developer as well. Least Privileges must be applied both horizontally and vertically. For example, even though both an accountant and sales representative may occupy the same level in an organization's hierarchy, both require access to different resources to perform their jobs. The accountant should likely not be granted access to a customer database and the sales representative should not be able to access payroll data. Similarly, the head of the sales department is likely to need more privileged access than his or her subordinates.

Failure to enforce least privileges in an application can jeopardize the confidentially of sensitive resources. Mitigation strategies are applied primarily during the Architecture and Design phase (see [CWE-272](https://cwe.mitre.org/data/definitions/272.html)); however, the principle must be addressed throughout the SDLC.

Consider the following points and best practices:

- During the design phase, ensure trust boundaries are defined. Enumerate the types of users that will be accessing the system, the resources exposed and the operations (such as read, write, update, etc) that might be performed on those resources. For every combination of user type and resource, determine what operations, if any, the user (based on role and/or other attributes) must be able to perform on that resource. For an ABAC system ensure all categories of attributes are considered. For example, a Sales Representative may need to access a customer database from the internal network during working hours, but not from home at midnight.
- Create tests that validate that the permissions mapped out in the design phase are being correctly enforced.
- After the app has been deployed, periodically review permissions in the system for "privilege creep"; that is, ensure the privileges of users in the current environment do not exceed those defined during the design phase (plus or minus any formally approved changes).
- Remember, it is easier to grant users additional permissions rather than to take away some they previously enjoyed. Careful planning and implementation of Least Privileges early in the SDLC can help reduce the risk of needing to revoke permissions that are later deemed overly broad.

### Deny by Default

Even when no access control rules are explicitly matched, an the application cannot remain neutral when an entity is requesting access to a particular resource. The application must always make a decision, whether implicitly or explicitly, to either deny or permit the requested access. Logic errors and other mistakes relating to access control may happen, especially when access requirements are complex; consequently, one should not rely entirely on explicitly defined rules for matching all possible requests. For security purposes. an application should be configured to deny access by default.

Consider the following points and best practices:

- Adopt a "deny-by-default" mentality both during initial development and whenever new functionality or resources are exposed by the app. One should be able to explicitly justify why a specific permission was granted to a particular user or group rather than assuming access to be the default position.
- Although some frameworks or libraries may themselves adopt a deny-by-default strategy, explicit configuration should be preferred over relying on framework or library defaults. The logic and defaults of third-party code may evolve over time, without the developer's full knowledge or understanding of the change's implications for a particular project.
  
### Validate the Permissions on Every Request

### Thoroughly Review the Authorization Logic of Chosen Tools and Technologies, Implementing Custom Logic if Necessary

### Prefer Feature and Attribute Based Access Control over RBAC

### Ensure Lookup IDs are Not Accessible Even When Guessed or Cannot Be Tampered With

### Enforce Authorization Checks on Static Resources

### Verify that Authorization Checks are Performed in the Right Location

### Exit Safely when Authorization Checks Fail

### Implement Appropriate Logging

### Create Unit and Integration Test Cases for Authorization Logic

## References

### ABAC

- [NIST Special Publication 800-162 Guide to Attribute Based Access Control (ABAC) Definition and Considerations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf)
  
- [NIST SP 800-178 A Comparison of Attribute Based Access Control (ABAC) Standards for Data Service Applications](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-178.pdf)
  
- [NIST SP 800-205 Attribute Considerations for Access Control Systems](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-205.pdf)

### Least Privilege

- [Least Privilege](https://us-cert.cisa.gov/bsi/articles/knowledge/principles/least-privilege)

### RBAC

- [Role-Based Access Controls](https://csrc.nist.gov/CSRC/media/Publications/conference-paper/1992/10/13/role-based-access-controls/documents/ferraiolo-kuhn-92.pdf).
