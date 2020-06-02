# Authorization Cheat Sheet

## Introduction

Briefly introduce reader to the topic and cheatsheet.

## Threat Model

Would include vulnerable code examples here.

## Recommendations

### Enforce Least Privileges

### Deny by Default

### Validate the Permissions on Every Request

Anything stored client-side can be readily tampered with, do not cache permissions, etc.

### Use Established Frameworks, APIs, and Libraries

In addition to saving time, these tools have been (when chose carefully of course) have withstood scrutiny. Akin (though certainly not identical) to the argument of why one should not try and create their own cryptographic algorithms/implementations.

### Prefer Feature and Attribute Based Access Control over RBAC

For the reasons promoted [here](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls), under point five.

### Ensure Lookup IDs are Not Accessible Even When Guessed or Cannot Be Tampered With

This would essentially relate to IDOR. Emphasize the importance of context and app's threat model in deciding whether such a control is necessary.

### Enforce Authorization Checks on Static Resources

### Verify that Authorization Checks are Performed in the Right Location

### Exit Safely when Authorization Checks Fail

### Implement Appropriate Logging

### Create Unit and Integration Test Cases for Authorization Logic

## References

Would definitely like to include references to other OWASP resources, CWE, perhaps some NIST SPs, links relevant to particular languages or frameworks (Spring Security has an excellent section on the topic), etc.
