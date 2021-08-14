# Access Control Cheat Sheet

## Introduction

This article is focused on providing clear, simple, actionable guidance for providing access control security in your applications. The objective is to guide developers, reviewers, designers, architects on designing, creating, and maintaining access controls in web applications.

### What is Authorization?

Authorization is the process where requests to access a particular resource should be granted or denied. It should be noted that authorization is not equivalent to authentication - as these terms and their definitions are frequently confused. Authentication is providing and validating identity. The authorization includes the execution rules that determine which functionality and data the user (or Principal) may access, ensuring the proper allocation of access rights after authentication is successful.

It can be summarized as:
> The requested **action** is **permitted** at this **time** for this **identity**

Where:

- **Identity** is _assured_ when the requester is challenged at the time they make the request, which means they have just fulfilled a challenge/response mechanism to verify they are who they claim, in terms of identity. If the challenge occurred before the request there is no assurance, acknowledging there may be a trusted session, but without assurance through via _challenge_ there can only be an unverified identity making this request
- **Action** The purpose for an authorization mechanism, a requester is attempting to perform an action that is sensitive, requires elevated privileges, or has some other implication like user privacy or _material_ impacts to the business.
- **Permitted** means the identity has been checked for permission to perform the action, using Access Controls.
- **Time** is extremely meaningful for the security characteristics of Authorization because it is the responsibility of the server to verify that the request is being processed _now_ and that is when the request was made. If it was made earlier being replayed now, or has been time skewed to a future time, the server should reject the request as it is not relevant to the current Authorization context.

## What is Access Control?

Web applications need access controls to allow users (with varying privileges) to use the application. They also need administrators to manage the application’s access control rules and the granting of permissions or entitlements to users and other entities. Various access control design methodologies are available. To choose the most appropriate one, a risk assessment needs to be performed to identify threats and vulnerabilities specific to your application, so that the proper access control methodology is appropriate for your application.

### Access Control Policy

Why do we need an access control policy for web development?

The intention of having an access control policy is to ensure that security requirements are described clearly to architects, designers, developers and support teams, such that access control functionality is designed and implemented in a consistent manner.

### Role-Based Access Control (RBAC)

In Role-Based Access Control (RBAC), access decisions are based on an individual's roles and responsibilities within the organization or user base.

The process of defining roles is usually based on analyzing the fundamental goals and structure of an organization and is usually linked to the security policy. For instance, in a medical organization, the different roles of users may include those such as a doctor, nurse, attendant, patients, etc. These members require different levels of access in order to perform their functions, but also the types of web transactions and their allowed context vary greatly depending on the security policy and any relevant regulations (HIPAA, Gramm-Leach-Bliley, etc.).

An RBAC access control framework should provide web application security administrators with the ability to determine who can perform what actions, when, from where, in what order, and in some cases under what relational circumstances.

The advantages of using this methodology are:

- Roles are assigned based on organizational structure with emphasis on the organizational security policy
- Easy to use
- Easy to administer
- Built into most frameworks
- Aligns with security principles like segregation of duties and least privileges

Problems that can be encountered while using this methodology:

- Documentation of the roles and accesses has to be maintained stringently.
- Multi-tenancy can not be implemented effectively unless there is a way to associate the roles with multi-tenancy capability requirements, e.g. OU in Active Directory
- There is a tendency for scope creep to happen, e.g. more accesses and privileges can be given than intended for. Or a user might be included in two roles if proper access reviews and subsequent revocation is not performed.
- Does not support data-based access control

The areas of caution while using RBAC are:

- Roles must be only be transferred or delegated using strict sign-offs and procedures.
- When a user changes their role to another one, the administrator must make sure that the earlier access is revoked such that at any given point of time, a user is assigned to only those roles on a need to know basis.
- Assurance for RBAC must be carried out using strict access control reviews.

### Attribute-Based Access Control (ABAC)

In Attribute-Based Access Control (ABAC), access decisions are based on attributes of the subject of the request compared to the permissions held by the identity of the requester.

Attributes come in various forms and are easiest summarized to be the metadata of data, rather than data itself. If you stored a user email the _attribute_ may be a reference to the database table in a relation database, or a primary key associated to the data that maps to the primary key of the identity in a key-value store or in disparate data stores, or another example is the index of a document store that holds the data.

There are more modern datastores that provide the ability to 'label', 'tag', and define actual metadata or headers returned with data served by a RESTful API, these are all great examples of attributes.

The advantages of using this methodology are:

- Data Lineage can be applied to track data accessed to the original source or a primary source of truth (or both).
- Audit purposes, simple system to answer one of the hardest data access questions. Who can or has accessed this data?
- Non-repudiation is possible when attributes are logged for data access by identity.
- Capable of being very granular or very high level, attributes are very flexible

Problems that can be encountered while using this methodology:

- Overhead of setting up deliberate access control policy in a least privileged fashion, typically ABAC suffers the same overly permissive policies due to it simply being possible and the path of least resistance
- Overhead of setting attributes to data, ABAC implementations usually end up having a set of very arbitrary default attributes that are applied to high level policy and widely granted to users. A proper ABAC would have new data attributed appropriately at the time the data is created with the only default access given to the data creator, which may also not be appropriate in some obscure cases. The problem is defaults are typically set at higher levels than would be a secure least privileged scenario

The areas of caution while using ABAC are:

- Consider that good ABAC only works in scenarios where data is relatively static, or not frequently being created or changing in any way.
- ABAC works best when there are clear data owners who can permit others access to the data intentionally.
- Avoid starting ABAC when there is any chance new data can not be given a data owner to grant access, or when you find that data access defaults are overly permissive to excess of users or when the default attribute covers an excess of data.

### Organization-Based Access Control (OrBAC)

For Organization-Based Access Control (OrBAC) to be relevant it is implied the access control policy spans many Organizations typical for a multi-tenant environment, where access decisions are based on an individual's express authorization to the target organization data because they are a member of a specific organization.

OrBAC is frequently confused with RBAC _because_ it's mechanism is semantically named 'Role' in many environments that inherit from Active Directory or newer cloud service providers that adopted the terminology of 'role'. For example if you work for a managed service provider and this gives you authority to the data of a client organization for the purposes of 'managing' it for the customer, or many customers, but you are not permitted the same authority for another specific customer. Then you may be using RoleA for CustomerA, RoleB for CustomerB, and a colleague uses RoleC for CustomerC but you cannot use RoleC.
This is OrBAC _not_ RBAC despite there being semantically named roles.

The advantages of using this methodology are:

- Purpose built solution for multi-tenant situations typical for professional services companies and managed service provider.
- Used in combination with other access control policy as an additional layer to provide customers with a level of trust and assurance.

Problems that can be encountered while using this methodology:

- When OrBAC is the only Access Control policy in place, it is far too overly permissive to be considered an appropriate security characteristic for Authorization purposes at the data access action, but completely appropriate for Authorization purposes to act on behalf of an organization without any specificity on what action can be permitted on the data at the stage or OrBAC decision.
- Certain limits may exist that means it is not feasible for all of the permitted customers to have their own 'Role' given to an individual that may actually be Authorized, so it is common in cases where customer number exceed the limitation for a new type of 'group of roles' to be used that span many organizations. When this occurs there is no longer any assurances that an individual organization can trust defeating the purpose of the OrBAC approach entirely

The areas of caution while using ABAC are:

- If you discover limitations that leads to groups of organizations to share a logical Authorization permission that can be granted, or decide to do so for usability reasons; you might not have any need for OrBAC because the benefit of OrBAC and the reason it exists is to provide individual assurance to the organizations being Authorized. Which cannot be assured when 2 or more organizations are bundled and shared together. Consider keeping your OrBAC strategy based on individual organizations and look to the second order access control strategy to solve the limitation or usability issues.

### Discretionary Access Control (DAC)

Discretionary Access Control (DAC) is a means of restricting access to information based on the identity of users and/or membership in certain groups. Access decisions are typically based on the authorizations granted to a user based on the credentials they presented at the time of authentication (user name, password, hardware/software token, etc.). In most typical DAC models, the owner of the information or any resource can change its permissions at their discretion (thus the name).

A DAC framework can provide web application security administrators with the ability to implement fine-grained access control. This model can be a basis for data-based access control implementation

The advantages of using this model are:

- Easy to use
- Easy to administer
- Aligns to the principle of least privileges.
- Object owner has total control over access granted

Problems that can be encountered while using this methodology:

- Documentation of the roles and accesses has to be maintained stringently.
- Multi-tenancy can not be implemented effectively unless there is a way to associate the roles with multi-tenancy capability requirements, e.g. OU in Active Directory
- There is a tendency for scope creep to happen, e.g. more accesses and privileges can be given than intended for.

The areas of caution while using DAC are:

- While granting trusts
- Assurance for DAC must be carried out using strict access control reviews.

### Mandatory Access Control (MAC)

Mandatory Access Control (MAC) ensures that the enforcement of organizational security policy does not rely on voluntary web application user compliance. MAC secures information by assigning sensitivity labels on information and comparing this to the level of sensitivity a user is operating at. MAC is usually appropriate for extremely secure systems, including multilevel secure military applications or mission-critical data applications.

The advantages of using this methodology are:

- Access to an object is based on the sensitivity of the object
- Access based on the need to know is strictly adhered to, and scope creep has minimal possibility
- Only an administrator can grant access

Problems that can be encountered while using this methodology:

- Difficult and expensive to implement
- Not agile

The areas of caution while using MAC are:

- Classification and sensitivity assignment at an appropriate and pragmatic level
- Assurance for MAC must be carried out to ensure that the classification of the objects is at the appropriate level.

### Permission Based Access Control

The key concept in Permission Based Access Control is the abstraction of application actions into a set of *permissions*. A *permission* may be represented simply as a string-based name, for example, "READ". Access decisions are made by checking if the current user *has* the permission associated with the requested application action.

The *has* relationship between the user and permission may be satisfied by creating a direct relationship between the user and permission (called a *grant*), or an indirect one. In the indirect model, the permission *grant* is to an intermediate entity such as *user group*. A user is considered a member of a *user group* if and only if the user *inherits* permissions from the *user group*. The indirect model makes it easier to manage the permissions for a large number of users since changing the permissions assigned to the user group affects all members of the user group.

In some Permission Based Access Control systems that provide fine-grained domain object-level access control, permissions may be grouped into *classes*. In this model, it is assumed that each domain object in the system can be associated with a *class* which determines the permissions applicable to the respective domain object. In such a system a "DOCUMENT" class may be defined with the permissions "READ", "WRITE" and DELETE"; a "SERVER" class may be defined with the permissions "START", "STOP", and "REBOOT".
