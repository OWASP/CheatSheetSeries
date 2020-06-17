# Access Control Cheat Sheet

## Introduction

This article is focused on providing clear, simple, actionable guidance for providing access control security in your applications. The objective is to guide developers, reviewers, designers, architects on designing, creating, and maintaining access controls in web applications.

### What is Access Control / Authorization

Authorization is the process where requests to access a particular resource should be granted or denied. It should be noted that authorization is not equivalent to authentication - as these terms and their definitions are frequently confused. Authentication is providing and validating identity. The authorization includes the execution rules that determine which functionality and data the user (or Principal) may access, ensuring the proper allocation of access rights after authentication is successful.

Web applications need access controls to allow users (with varying privileges) to use the application. They also need administrators to manage the application’s access control rules and the granting of permissions or entitlements to users and other entities. Various access control design methodologies are available. To choose the most appropriate one, a risk assessment needs to be performed to identify threats and vulnerabilities specific to your application, so that the proper access control methodology is appropriate for your application.

### Access Control Policy

Why do we need an access control policy for web development?

The intention of having an access control policy is to ensure that security requirements are described clearly to architects, designers, developers and support teams, such that access control functionality is designed and implemented in a consistent manner.

## Role-Based Access Control (RBAC)

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

## Discretionary Access Control (DAC)

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

## Mandatory Access Control (MAC)

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

## Permission Based Access Control

The key concept in Permission Based Access Control is the abstraction of application actions into a set of *permissions*. A *permission* may be represented simply as a string-based name, for example, "READ". Access decisions are made by checking if the current user *has* the permission associated with the requested application action.

The *has* relationship between the user and permission may be satisfied by creating a direct relationship between the user and permission (called a *grant*), or an indirect one. In the indirect model, the permission *grant* is to an intermediate entity such as *user group*. A user is considered a member of a *user group* if and only if the user *inherits* permissions from the *user group*. The indirect model makes it easier to manage the permissions for a large number of users since changing the permissions assigned to the user group affects all members of the user group.

In some Permission Based Access Control systems that provide fine-grained domain object-level access control, permissions may be grouped into *classes*. In this model, it is assumed that each domain object in the system can be associated with a *class* which determines the permissions applicable to the respective domain object. In such a system a "DOCUMENT" class may be defined with the permissions "READ", "WRITE" and DELETE"; a "SERVER" class may be defined with the permissions "START", "STOP", and "REBOOT".
