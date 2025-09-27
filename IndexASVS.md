# ASVS Index (v5.0)

## Table of Contents

- [Objective](#objective)  
- [V1: Architecture, Design and Threat Modeling Requirements](#v1-architecture-design-and-threat-modeling-requirements)  
- [V2: Authentication Verification Requirements](#v2-authentication-verification-requirements)  
- [V3: Session Management Verification Requirements](#v3-session-management-verification-requirements)  
- [V4: Access Control Verification Requirements](#v4-access-control-verification-requirements)  
- [V5: Validation, Sanitization and Encoding Verification Requirements](#v5-validation-sanitization-and-encoding-verification-requirements)  
- [V6: Stored Cryptography Verification Requirements](#v6-stored-cryptography-verification-requirements)  
- [V7: Error Handling and Logging Verification Requirements](#v7-error-handling-and-logging-verification-requirements)  
- [V8: Data Protection and Privacy Verification Requirements](#v8-data-protection-and-privacy-verification-requirements)  
- [V9: Communications Verification Requirements](#v9-communications-verification-requirements)  
- [V10: Malicious Code Verification Requirements](#v10-malicious-code-verification-requirements)  
- [V11: Business Logic Verification Requirements](#v11-business-logic-verification-requirements)  
- [V12: File and Resources Verification Requirements](#v12-file-and-resources-verification-requirements)  
- [V13: API and Web Service Verification Requirements](#v13-api-and-web-service-verification-requirements)  
- [V14: Configuration and Deployment Verification Requirements](#v14-configuration-and-deployment-verification-requirements)  
- [Archived Versions](#archived-versions)  

---

## Objective

The objective of this index is to help an OWASP Application Security Verification Standard (`ASVS`) user clearly identify which cheat sheets are useful for each section during their use of **ASVS 5.0**.

This index is based on version **5.0** of the ASVS.  
For backward reference, see the archived ASVS 4.0 index (link in *Archived Versions*).

---

## V1: Architecture, Design and Threat Modeling Requirements

### V1.1 Secure Software Development Lifecycle
**Requirement:** Verify the use of a secure software development lifecycle that addresses security in all stages of development.

**Related Cheat Sheets:**
- [Threat Modeling Cheat Sheet](cheatsheets/Threat_Modeling_Cheat_Sheet.md)
- [Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)
- [Attack Surface Analysis Cheat Sheet](cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)

### V1.2 Authentication Architecture
**Requirement:** Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength.

**Related Cheat Sheets:**
- [Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

### V1.3 Session Management Architecture
**Requirement:** Verify the application uses a single and well-known session management mechanism for protecting against session management vulnerabilities.

**Related Cheat Sheets:**
- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V1.4 Access Control Architecture
**Requirement:** Verify the application uses a single and well-known access control mechanism for enforcing access control.

**Related Cheat Sheets:**
- [Access Control Cheat Sheet](cheatsheets/Access_Control_Cheat_Sheet.md)

### V1.5 Input and Output Architecture
**Requirement:** Verify that the application uses a single and well-known encoding/validation mechanism for protecting against input and output-based vulnerabilities.

**Related Cheat Sheets:**
- [Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)
- [Cross_Site_Scripting_Prevention_Cheat_Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

> Note: ensure the XSS prevention filename exactly matches the repo filename (here kept as `Cross_Site_Scripting_Prevention_Cheat_Sheet.md` to match earlier entries).

### V1.6 Cryptographic Architecture
**Requirement:** Verify that the application uses well-known cryptographic primitives and proper key handling.

**Related Cheat Sheets:**
- [Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)
- [Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V1.7 Error Handling and Logging Architecture
**Requirement:** Verify that the application uses consistent error handling and logging mechanisms.

**Related Cheat Sheets:**
- [Error Handling Cheat Sheet](cheatsheets/Error_Handling_Cheat_Sheet.md)
- [Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

### V1.8 Data Protection and Privacy Architecture
**Requirement:** Verify that the application addresses data protection and privacy at architecture level.

**Related Cheat Sheets:**
- [User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V1.9 Communications Security Architecture
**Requirement:** Verify secure communications design is in place.

**Related Cheat Sheets:**
- [Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V1.10 Malicious Code Architecture
**Requirement:** Verify defenses against malicious scripts, third-party code, and supply-chain risks.

**Related Cheat Sheets:**
- [Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V1.11 Business Logic Architecture
**Requirement:** Verify business logic threats are considered in design.

**Related Cheat Sheets:**
- [Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

### V1.12 Secure File and Resource Architecture
**Requirement:** Verify secure handling and storage of uploaded files and resources.

**Related Cheat Sheets:**
- [File Upload Cheat Sheet](cheatsheets/File_Upload_Cheat_Sheet.md)

### V1.13 Web Service Architecture
**Requirement:** Verify web service/API architecture follows secure patterns.

**Related Cheat Sheets:**
- [Web Service Security Cheat Sheet](cheatsheets/Web_Service_Security_Cheat_Sheet.md)
- [REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

### V1.14 Configuration and Deployment Architecture
**Requirement:** Verify secure configuration and deployment patterns are used.

**Related Cheat Sheets:**
- [Docker Security Cheat Sheet](cheatsheets/Docker_Security_Cheat_Sheet.md)

---

## V2: Authentication Verification Requirements

### V2.1 Password Security Requirements
**Requirement:** Verify that passwords are stored and processed securely.

**Related Cheat Sheets:**
- [Choosing and Using Security Questions Cheat Sheet](cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md)
- [Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)
- [Credential Stuffing Prevention Cheat Sheet](cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md)

### V2.2 General Authenticator Requirements
**Requirement:** Verify authenticators and their usage are secure.

**Related Cheat Sheets:**
- [Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)
- [Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)
- [Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V2.3 Authenticator Lifecycle Requirements
**Requirement:** Verify authenticators lifecycle (provisioning, rotation, revocation) is secure.

**Related Cheat Sheets:**
- [Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

### V2.4 Credential Storage Requirements
**Requirement:** Verify credential storage is secure (hashing, salting, KDFs).

**Related Cheat Sheets:**
- [Password Storage Cheat Sheet](cheatsheets/Password_Storage_Cheat_Sheet.md)

### V2.5 Credential Recovery Requirements
**Requirement:** Verify secure credential recovery mechanisms.

**Related Cheat Sheets:**
- [Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

### V2.6 Look-up Secret Verifier Requirements
**Requirement:** Verify look-up secrets are implemented securely.

**Related Cheat Sheets:**
- [Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

### V2.7 Out of Band Verifier Requirements
**Requirement:** Verify out-of-band verifiers (email, SMS, push) are used securely.

**Related Cheat Sheets:**
- [Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

### V2.8 Single Factor OTP Verifier Requirements
**Requirement:** Verify single-factor OTP mechanisms are implemented securely.

**Related Cheat Sheets:**
- [Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

### V2.9 Multi-Factor Authenticator Requirements
**Requirement:** Verify multi-factor authentication is implemented correctly.

**Related Cheat Sheets:**
- [Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

### V2.10 Cryptographic Verifier Requirements
**Requirement:** Verify cryptographic verifiers and hardware/software tokens are used securely.

**Related Cheat Sheets:**
- [Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)
- [Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

---

## V3: Session Management Verification Requirements

### V3.1 Fundamental Session Management Requirements
**Requirement:** Verify session creation, handling and invalidation are secure.

**Related Cheat Sheets:**
- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V3.2 Session Binding Requirements
**Requirement:** Verify sessions are bound to user context to mitigate fixation and hijack.

**Related Cheat Sheets:**
- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)
- [Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V3.3 Session Logout and Timeout Requirements
**Requirement:** Verify logout, timeout and session termination behave correctly.

**Related Cheat Sheets:**
- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V3.4 Cookie-based Session Management
**Requirement:** Verify secure cookie attributes and handling.

**Related Cheat Sheets:**
- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)
- [Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

### V3.5 Token-based Session Management
**Requirement:** Verify token issuance, validation, and revocation are secure.

**Related Cheat Sheets:**
- [JSON_Web_Token_for_Java_Cheat_Sheet.md](cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md)
- [REST_Security_Cheat_Sheet.md](cheatsheets/REST_Security_Cheat_Sheet.md)

### V3.6 Defenses Against Session Management Exploits
**Requirement:** Verify mitigations for session attacks are present.

**Related Cheat Sheets:**
- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)
- [Transaction_Authorization_Cheat_Sheet.md](cheatsheets/Transaction_Authorization_Cheat_Sheet.md)

---

## V4: Access Control Verification Requirements

### V4.1 General Access Control Design
**Requirement:** Verify access control design follows principle of least privilege and separation of duties.

**Related Cheat Sheets:**
- [Access_Control_Cheat_Sheet.md](cheatsheets/Access_Control_Cheat_Sheet.md)
- [Authorization_Testing_Automation_Cheat_Sheet.md](cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)

### V4.2 Operation Level Access Control
**Requirement:** Verify operation-level authorization checks are enforced server-side.

**Related Cheat Sheets:**
- [Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md](cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)
- [Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Authorization_Testing_Automation_Cheat_Sheet.md](cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)

### V4.3 Other Access Control Considerations
**Requirement:** Verify additional access control threats are considered.

**Related Cheat Sheets:**
- [REST_Assessment_Cheat_Sheet.md](cheatsheets/REST_Assessment_Cheat_Sheet.md)
- [Multifactor_Authentication_Cheat_Sheet.md](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

---

## V5: Validation, Sanitization and Encoding Verification Requirements

### V5.1 Input Validation Requirements
**Requirement:** Verify robust input validation is in place.

**Related Cheat Sheets:**
- [Mass_Assignment_Cheat_Sheet.md](cheatsheets/Mass_Assignment_Cheat_Sheet.md)
- [Input_Validation_Cheat_Sheet.md](cheatsheets/Input_Validation_Cheat_Sheet.md)

### V5.2 Sanitization and Sandboxing Requirements
**Requirement:** Verify sanitization, escaping and sandboxing are applied appropriately.

**Related Cheat Sheets:**
- [Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Cross_Site_Scripting_Prevention_Cheat_Sheet.md](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [DOM_based_XSS_Prevention_Cheat_Sheet.md](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)
- [Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

### V5.3 Output Encoding and Injection Prevention Requirements
**Requirement:** Verify output encoding and injection prevention measures are applied.

**Related Cheat Sheets:**
- [Cross_Site_Scripting_Prevention_Cheat_Sheet.md](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [DOM_based_XSS_Prevention_Cheat_Sheet.md](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)
- [HTML5_Security_Cheat_Sheet.md](cheatsheets/HTML5_Security_Cheat_Sheet.md)
- [Injection_Prevention_Cheat_Sheet.md](cheatsheets/Injection_Prevention_Cheat_Sheet.md)
- [Injection_Prevention_in_Java_Cheat_Sheet.md](cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.md)
- [Input_Validation_Cheat_Sheet.md](cheatsheets/Input_Validation_Cheat_Sheet.md)
- [LDAP_Injection_Prevention_Cheat_Sheet.md](cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md)
- [OS_Command_Injection_Defense_Cheat_Sheet.md](cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md)
- [File_Upload_Cheat_Sheet.md](cheatsheets/File_Upload_Cheat_Sheet.md)
- [Query_Parameterization_Cheat_Sheet.md](cheatsheets/Query_Parameterization_Cheat_Sheet.md)
- [SQL_Injection_Prevention_Cheat_Sheet.md](cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md)
- [Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)
- [Bean_Validation_Cheat_Sheet.md](cheatsheets/Bean_Validation_Cheat_Sheet.md)
- [XML_External_Entity_Prevention_Cheat_Sheet.md](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)
- [XML_Security_Cheat_Sheet.md](cheatsheets/XML_Security_Cheat_Sheet.md)

### V5.4 Memory, String, and Unmanaged Code Requirements
**Requirement:** Verify memory and low-level code safety controls.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

### V5.5 Deserialization Prevention Requirements
**Requirement:** Verify deserialization and related object handling is safe.

**Related Cheat Sheets:**
- [Deserialization_Cheat_Sheet.md](cheatsheets/Deserialization_Cheat_Sheet.md)
- [XML_External_Entity_Prevention_Cheat_Sheet.md](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)
- [XML_Security_Cheat_Sheet.md](cheatsheets/XML_Security_Cheat_Sheet.md)

---

## V6: Stored Cryptography Verification Requirements

### V6.1 Data Classification
**Requirement:** Verify sensitive data classification and handling.

**Related Cheat Sheets:**
- [Abuse_Case_Cheat_Sheet.md](cheatsheets/Abuse_Case_Cheat_Sheet.md)
- [User_Privacy_Protection_Cheat_Sheet.md](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V6.2 Algorithms
**Requirement:** Verify cryptographic algorithm selection and usage.

**Related Cheat Sheets:**
- [Cryptographic_Storage_Cheat_Sheet.md](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)
- [Key_Management_Cheat_Sheet.md](cheatsheets/Key_Management_Cheat_Sheet.md)

### V6.3 Random Values
**Requirement:** Verify quality of random values used in crypto.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

### V6.4 Secret Management
**Requirement:** Verify secret storage, rotation and vaulting.

**Related Cheat Sheets:**
- [Key_Management_Cheat_Sheet.md](cheatsheets/Key_Management_Cheat_Sheet.md)

---

## V7: Error Handling and Logging Verification Requirements

### V7.1 Log Content Requirements
**Requirement:** Verify logs contain appropriate content and avoid leakage.

**Related Cheat Sheets:**
- [Logging_Cheat_Sheet.md](cheatsheets/Logging_Cheat_Sheet.md)

### V7.2 Log Processing Requirements
**Requirement:** Verify secure processing, aggregation and retention of logs.

**Related Cheat Sheets:**
- [Logging_Cheat_Sheet.md](cheatsheets/Logging_Cheat_Sheet.md)

### V7.3 Log Protection Requirements
**Requirement:** Verify log protection from tampering and unauthorized access.

**Related Cheat Sheets:**
- [Logging_Cheat_Sheet.md](cheatsheets/Logging_Cheat_Sheet.md)

### V7.4 Error Handling
**Requirement:** Verify errors are handled safely and not leaking sensitive info.

**Related Cheat Sheets:**
- [Error_Handling_Cheat_Sheet.md](cheatsheets/Error_Handling_Cheat_Sheet.md)

---

## V8: Data Protection and Privacy Verification Requirements

### V8.1 General Data Protection
**Requirement:** Verify policies and controls for data protection are implemented.

**Related Cheat Sheets:**
- [User_Privacy_Protection_Cheat_Sheet.md](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V8.2 Client-side Data Protection
**Requirement:** Verify client-side storage and handling are safe.

**Related Cheat Sheets:**
- [HTML5_Security_Cheat_Sheet.md](cheatsheets/HTML5_Security_Cheat_Sheet.md)

### V8.3 Sensitive Private Data
**Requirement:** Verify sensitive personal data handling is compliant.

**Related Cheat Sheets:**
- [User_Privacy_Protection_Cheat_Sheet.md](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

---

## V9: Communications Verification Requirements

### V9.1 Communications Security Requirements
**Requirement:** Verify transport-level protections (TLS, HSTS, etc.) are enforced.

**Related Cheat Sheets:**
- [HTTP_Strict_Transport_Security_Cheat_Sheet.md](cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md)
- [Transport_Layer_Security_Cheat_Sheet.md](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V9.2 Server Communications Security Requirements
**Requirement:** Verify server-to-server communications are protected.

**Related Cheat Sheets:**
- [Transport_Layer_Security_Cheat_Sheet.md](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

---

## V10: Malicious Code Verification Requirements

### V10.1 Code Integrity Controls
**Requirement:** Verify supply-chain and third-party code controls are in place.

**Related Cheat Sheets:**
- [Third_Party_Javascript_Management_Cheat_Sheet.md](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V10.2 Malicious Code Search
**Requirement:** Verify scanning and detection for malicious code.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

### V10.3 Deployed Application Integrity Controls
**Requirement:** Verify integrity of deployed artifacts and runtime protections.

**Related Cheat Sheets:**
- [Docker_Security_Cheat_Sheet.md](cheatsheets/Docker_Security_Cheat_Sheet.md)

---

## V11: Business Logic Verification Requirements

### V11.1 Business Logic Security Requirements
**Requirement:** Verify business logic controls and abuse-case mitigations are present.

**Related Cheat Sheets:**
- [Abuse_Case_Cheat_Sheet.md](cheatsheets/Abuse_Case_Cheat_Sheet.md)
- [Transaction_Authorization_Cheat_Sheet.md](cheatsheets/Transaction_Authorization_Cheat_Sheet.md)

---

## V12: File and Resources Verification Requirements

### V12.1 File Upload Requirements
**Requirement:** Verify file upload handling and scanning.

**Related Cheat Sheets:**
- [File_Upload_Cheat_Sheet.md](cheatsheets/File_Upload_Cheat_Sheet.md)

### V12.2 File Integrity Requirements
**Requirement:** Verify stored file integrity and validation.

**Related Cheat Sheets:**
- [File_Upload_Cheat_Sheet.md](cheatsheets/File_Upload_Cheat_Sheet.md)
- [Third_Party_Javascript_Management_Cheat_Sheet.md](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V12.3 File Execution Requirements
**Requirement:** Verify execution prevention and safe handling of files.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

### V12.4 File Storage Requirements
**Requirement:** Verify secure storage of files.

**Related Cheat Sheets:**
- [File_Upload_Cheat_Sheet.md](cheatsheets/File_Upload_Cheat_Sheet.md)

### V12.5 File Download Requirements
**Requirement:** Verify secure handling of file downloads.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

### V12.6 SSRF Protection Requirements
**Requirement:** Verify protections against server-side request forgery.

**Related Cheat Sheets:**
- [Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

---

## V13: API and Web Service Verification Requirements

### V13.1 Generic Web Service Security Verification Requirements
**Requirement:** Verify web service design and controls.

**Related Cheat Sheets:**
- [Web_Service_Security_Cheat_Sheet.md](cheatsheets/Web_Service_Security_Cheat_Sheet.md)
- [Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

### V13.2 RESTful Web Service Verification Requirements
**Requirement:** Verify REST API controls, authentication and common threats.

**Related Cheat Sheets:**
- [REST_Assessment_Cheat_Sheet.md](cheatsheets/REST_Assessment_Cheat_Sheet.md)
- [REST_Security_Cheat_Sheet.md](cheatsheets/REST_Security_Cheat_Sheet.md)
- [Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Transport_Layer_Security_Cheat_Sheet.md](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V13.3 SOAP Web Service Verification Requirements
**Requirement:** Verify SOAP and XML-based services are protected.

**Related Cheat Sheets:**
- [XML_Security_Cheat_Sheet.md](cheatsheets/XML_Security_Cheat_Sheet.md)

### V13.4 GraphQL & Data-layer Security Requirements
**Requirement:** Verify GraphQL and backend data-layer protections.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

---

## V14: Configuration and Deployment Verification Requirements

### V14.1 Build
**Requirement:** Verify build systems and CI pipelines are secure.

**Related Cheat Sheets:**
- [Docker_Security_Cheat_Sheet.md](cheatsheets/Docker_Security_Cheat_Sheet.md)

### V14.2 Dependency
**Requirement:** Verify dependency management and vulnerability handling.

**Related Cheat Sheets:**
- [Docker_Security_Cheat_Sheet.md](cheatsheets/Docker_Security_Cheat_Sheet.md)
- [Vulnerable_Dependency_Management_Cheat_Sheet.md](cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.md)

### V14.3 Unintended Security Disclosure Requirements
**Requirement:** Verify sensitive info is not disclosed via configs or errors.

**Related Cheat Sheets:**
- [Error_Handling_Cheat_Sheet.md](cheatsheets/Error_Handling_Cheat_Sheet.md)

### V14.4 HTTP Security Headers Requirements
**Requirement:** Verify HTTP security headers are configured correctly.

**Related Cheat Sheets:**
- [Content_Security_Policy_Cheat_Sheet.md](cheatsheets/Content_Security_Policy_Cheat_Sheet.md)

### V14.5 Validate HTTP Request Header Requirements
**Requirement:** Verify HTTP request headers are validated and not abused.

**Related Cheat Sheets:**
- *(No specific cheat sheet currently mapped — contributions welcome.)*

---

## Archived Versions

- [ASVS 4.0 Index](IndexASVS_4.0.html)

---
