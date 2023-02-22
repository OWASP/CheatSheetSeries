# Secure Product Design Cheat Sheet

## Introduction

The purpose of Secure Product Design is to ensure that all products meet or exceed the security requirements laid down by the organization as part of the development lifecycle and to ensure that all security decisions made about the product being developed are explicit choices and result in the correct level of security for the product being developed.

## Methodology

As a basic start, establish secure defaults, minimise the attack surface area, and fail securely to those well-defined and understood defaults.

Secure Product Design comes about through two processes:

1. **_Product Inception_**; and
2. **_Product Design_**

The first process happens when a product is conceived, or when an existing product is being re-invented. The latter is continuous, evolutionary, and done in an agile way, close to where the code is being written.

## Security Principles

### 1. The principle of Least Privilege and Separation of Duties

Least Privilege is a security principle that states that users should only be given the minimum amount of access necessary to perform their job. This means that users should only be given access to the resources they need to do their job, and no more. This helps to reduce the risk of unauthorized access to sensitive data or systems, as users are only able to access the resources they need. Least Privilege is an important security principle that should be followed in order to ensure the security of an organization's data and systems.

Separation of duties is a fundamental principle of internal control in business and organizations. It is a system of checks and balances that ensures that no single individual has control over all aspects of a transaction. This is done by assigning different tasks to different people, so that no one person has control over the entire process. This helps to reduce the risk of fraud and errors, as well as ensuring that all tasks are completed in a timely manner. Separation of duties is an important part of any organization's internal control system, and is essential for maintaining the integrity of the organization's financial records.

### 2. The principle of Defense-in-Depth

The principle of Defense-in-Depth is a security strategy that involves multiple layers of security controls to protect an organization’s assets. It is based on the idea that if one layer of security fails, the other layers will still be able to protect the asset. The layers of security can include physical security, network security, application security, and data security. The goal of Defense-in-Depth is to create a secure environment that is resilient to attack and can quickly detect and respond to any security incidents. By implementing multiple layers of security, organizations can reduce the risk of a successful attack and minimize the damage caused by any successful attack.

### 3. The principle of Zero Trust

Zero Trust is a security model that assumes that all users, devices, and networks are untrusted and must be verified before access is granted. It is based on the idea that organizations should not trust any user, device, or network, even if they are inside the organization’s network. Instead, all requests for access must be authenticated and authorized before access is granted. Zero Trust also requires organizations to continuously monitor and audit user activity to ensure that access is only granted to those who need it. This model is designed to reduce the risk of data breaches and other security incidents by ensuring that only authorized users have access to sensitive data.

### 4. The principle of Security-in-the-Open

Security-in-the-Open is a concept that emphasizes the importance of security in open source software development. It focuses on the need for developers to be aware of the security implications of their code and to take steps to ensure that their code is secure. This includes using secure coding practices, testing for vulnerabilities, and using secure development tools. Security-in-the-Open also encourages developers to collaborate with security experts to ensure that their code is secure.

## Security Focus Areas

### 1. Context

Where does this application under consideration fit into the ecosystem of the organization, which departments use it and for what reason? What kinds of data might it contain, and what is the risk profile as a result?

The processes employed to build the security context for an application include [Threat Modeling](Threat_Modeling_Cheat_Sheet.md) - which results in security related stories being added during **_Product Design_** at every iteration of *product delivery* - and when performing a Business Impact Assessment - which results in setting the correct Product Security Levels for a given product during **_Product Inception_**.

Context is all important because over-engineering for security can have even greater cost implications than over-engineering for scale or performance, but under-engineering can have devastating consequences too.

### 2. Components

From libraries in use by the application (selected during any **_Product Design_** stage) through to external services it might make use of (changing of which happen during **_Product Inception_**), what makes up this application and how are those parts kept secure? In order to do this we leverage a library of secure design patterns and ready to use components defined in your Golden Path / Paved Road documentation and by analyzing those choices through [Threat Modeling](Threat_Modeling_Cheat_Sheet.md).

A part of this component review must also include the more commercial aspects of selecting the right components (licensing and maintenance) as well as the limits on usage that might be required.

### 3. Connections

How do you interact with this application and how does it connect to those components and services mentioned before? Where is the data stored and how is it accessed? Connections can also describe any intentional lack of connections. Think about the segregation of tiers that might be required depending on the Product Security Levels required and the potential segregation of data or whole environments if required for different tenants.

Adding (or removing) connections is probably a sign that **_Product Inception_** is happening.

### 4. Code

Code is the ultimate expression of the intention for a product and as such it must be functional first and foremost. But there is a quality to how that functionality is provided that must meet or exceed the expectations of it.

Some basics of secure coding include:

   1. Input validation: Verify that all input data is valid and of the expected type, format, and length before processing it. This can help prevent attacks such as SQL injection and buffer overflows.
   2. Error handling: Handle errors and exceptions in a secure manner, such as by logging them in a secure way and not disclosing sensitive information to an attacker.
   3. Authentication and Authorization: Implement strong authentication and authorization mechanisms to ensure that only authorized users can access sensitive data and resources.
   4. Cryptography: Use cryptographic functions and protocols to protect data in transit and at rest, such as HTTPS and encryption - the expected levels for a given Product Security Level can often be found by reviewing your Golden Path / Paved Road documentation.
   5. Least privilege: Use the principle of the least privilege when writing code, such that the code and the system it runs on are given the minimum access rights necessary to perform their functions.
   6. Secure memory management: Use high-level languages recommended in your Golden Path / Paved Road documentation or properly manage memory to prevent memory-related vulnerabilities such as buffer overflows and use-after-free.
   7. Avoiding hardcoded secrets: Hardcoded secrets such as passwords and encryption keys should be avoided in the code and should be stored in a secure storage.
   8. Security testing: Test the software for security vulnerabilities during development and just prior to deployment.
   9. Auditing and reviewing the code: Regularly audit and review the code for security vulnerabilities, such as by using automated tools or having a third party review the code.
   10. Keeping up-to-date: Keep the code up-to-date with the latest security best practices and vulnerability fixes to ensure that the software is as secure as possible.

Ensure that you integrate plausibility checks at each tier of your application (e.g., from frontend to backend) and ensure that you write unit and integration tests to validate that all threats discovered during [Threat Modeling](Threat_Modeling_Cheat_Sheet.md) have been mitigated to a level of risk acceptable to the organization. Use that to compile use-cases and [abuse-cases](Abuse_Case_Cheat_Sheet.md) for each tier of your application.

### 5. Configuration

Building an application securely can all too easily be undone if it's not securely configured. At a minimum we should ensure the following:

1. Bearing in mind the principle of Least Privilege: Limit the access and permissions of system components and users to the minimum required to perform their tasks.
2. Remembering Defense-in-Depth: Implement multiple layers of security controls to protect against a wide range of threats.
3. Ensuring Secure by Default: Configure systems and software to be secure by default, with minimal manual setup or configuration required.
4. Secure Data: Protect sensitive data, such as personal information and financial data, by encrypting it in transit and at rest. Protecting that data also means ensuring it's correctly backed up and that the data retention is set correctly for the desired Product Security Level.
5. Plan to have the configuration Fail Securely: Design systems to fail in a secure state, rather than exposing vulnerabilities when they malfunction.
6. Always use Secure Communications: Use secure protocols for communication, such as HTTPS, to protect against eavesdropping and tampering.
7. Perform regular updates - or leverage [maintained images](https://www.cisecurity.org/cis-hardened-images): Keeping software, docker images and base operating systems up-to-date with the [latest security patches](https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final) is an essential part of maintaining a secure system.
8. Have a practiced Security Incident response plan: Having a plan in place for how to respond to a security incident is essential for minimizing the damage caused by any successful attack and a crucial part of the Product Support Model.

Details of how to precisely ensure secure configuration can be found in [Infrastructure as Code Security Cheat Sheet](Infrastructure_as_Code_Security_Cheat_Sheet.md)
