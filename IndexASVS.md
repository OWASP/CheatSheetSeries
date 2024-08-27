# ASVS Index

## Table of Contents

- [Objective](#objective)
- [V1: Architecture, Design and Threat Modeling Requirements](#v1-architecture-design-and-threat-modeling-requirements)
    - [V1.1 Secure Software Development Lifecycle Requirements](#v11-secure-software-development-lifecycle-requirements)
    - [V1.2 Authentication Architectural Requirements](#v12-authentication-architectural-requirements)
    - [V1.3 Session Management Architectural Requirements](#v13-session-management-architectural-requirements)
    - [V1.4 Access Control Architectural Requirements](#v14-access-control-architectural-requirements)
    - [V1.5 Input and Output Architectural Requirements](#v15-input-and-output-architectural-requirements)
    - [V1.6 Cryptographic Architectural Requirements](#v16-cryptographic-architectural-requirements)
    - [V1.7 Errors, Logging and Auditing Architectural Requirements](#v17-errors-logging-and-auditing-architectural-requirements)
    - [V1.8 Data Protection and Privacy Architectural Requirements](#v18-data-protection-and-privacy-architectural-requirements)
    - [V1.9 Communications Architectural Requirements](#v19-communications-architectural-requirements)
    - [V1.10 Malicious Software Architectural Requirements](#v110-malicious-software-architectural-requirements)
    - [V1.11 Business Logic Architectural Requirements](#v111-business-logic-architectural-requirements)
    - [V1.12 Secure File Upload Architectural Requirements](#v112-secure-file-upload-architectural-requirements)
    - [V1.13 API Architectural Requirements](#v113-api-architectural-requirements)
    - [V1.14 Configuration Architectural Requirements](#v114-configuration-architectural-requirements)
- [V2: Authentication Verification Requirements](#v2-authentication-verification-requirements)
    - [V2.1 Password Security Requirements](#v21-password-security-requirements)
    - [V2.2 General Authenticator Requirements](#v22-general-authenticator-requirements)
    - [V2.3 Authenticator Lifecycle Requirements](#v23-authenticator-lifecycle-requirements)
    - [V2.4 Credential Storage Requirements](#v24-credential-storage-requirements)
    - [V2.5 Credential Recovery Requirements](#v25-credential-recovery-requirements)
    - [V2.6 Look-up Secret Verifier Requirements](#v26-look-up-secret-verifier-requirements)
    - [V2.7 Out of Band Verifier Requirements](#v27-out-of-band-verifier-requirements)
    - [V2.8 Single or Multi Factor One Time Verifier Requirements](#v28-single-or-multi-factor-one-time-verifier-requirements)
    - [V2.9 Cryptographic Software and Devices Verifier Requirements](#v29-cryptographic-software-and-devices-verifier-requirements)
    - [V2.10 Service Authentication Requirements](#v210-service-authentication-requirements)
- [V3: Session Management Verification Requirements](#v3-session-management-verification-requirements)
    - [V3.1 Fundamental Session Management Requirements](#v31-fundamental-session-management-requirements)
    - [V3.2 Session Binding Requirements](#v32-session-binding-requirements)
    - [V3.3 Session Logout and Timeout Requirements](#v33-session-logout-and-timeout-requirements)
    - [V3.4 Cookie-based Session Management](#v34-cookie-based-session-management)
    - [V3.5 Token-based Session Management](#v35-token-based-session-management)
    - [V3.6 Re-authentication from a Federation or Assertion](#v36-re-authentication-from-a-federation-or-assertion)
    - [V3.7 Defenses Against Session Management Exploits](#v37-defenses-against-session-management-exploits)
- [V4: Access Control Verification Requirements](#v4-access-control-verification-requirements)
    - [V4.1 General Access Control Design](#v41-general-access-control-design)
    - [V4.2 Operation Level Access Control](#v42-operation-level-access-control)
    - [V4.3 Other Access Control Considerations](#v43-other-access-control-considerations)
- [V5: Validation, Sanitization and Encoding Verification Requirements](#v5-validation-sanitization-and-encoding-verification-requirements)
    - [V5.1 Input Validation Requirements](#v51-input-validation-requirements)
    - [V5.2 Sanitization and Sandboxing Requirements](#v52-sanitization-and-sandboxing-requirements)
    - [V5.3 Output encoding and Injection Prevention Requirements](#v53-output-encoding-and-injection-prevention-requirements)
    - [V5.4 Memory, String, and Unmanaged Code Requirements](#v54-memory-string-and-unmanaged-code-requirements)
    - [V5.5 Deserialization Prevention Requirements](#v55-deserialization-prevention-requirements)
- [V6: Stored Cryptography Verification Requirements](#v6-stored-cryptography-verification-requirements)
    - [V6.1 Data Classification](#v61-data-classification)
    - [V6.2 Algorithms](#v62-algorithms)
    - [V6.3 Random Values](#v63-random-values)
    - [V6.4 Secret Management](#v64-secret-management)
- [V7: Error Handling and Logging Verification Requirements](#v7-error-handling-and-logging-verification-requirements)
    - [V7.1 Log Content Requirements](#v71-log-content-requirements)
    - [V7.2 Log Processing Requirements](#v72-log-processing-requirements)
    - [V7.3 Log Protection Requirements](#v73-log-protection-requirements)
    - [V7.4 Error Handling](#v74-error-handling)
- [V8: Data Protection Verification Requirements](#v8-data-protection-verification-requirements)
    - [V8.1 General Data Protection](#v81-general-data-protection)
    - [V8.2 Client-side Data Protection](#v82-client-side-data-protection)
    - [V8.3 Sensitive Private Data](#v83-sensitive-private-data)
- [V9: Communications Verification Requirements](#v9-communications-verification-requirements)
    - [V9.1 Communications Security Requirements](#v91-communications-security-requirements)
    - [V9.2 Server Communications Security Requirements](#v92-server-communications-security-requirements)
- [V10: Malicious Code Verification Requirements](#v10-malicious-code-verification-requirements)
    - [V10.1 Code Integrity Controls](#v101-code-integrity-controls)
    - [V10.2 Malicious Code Search](#v102-malicious-code-search)
    - [V10.3 Deployed Application Integrity Controls](#v103-deployed-application-integrity-controls)
- [V11: Business Logic Verification Requirements](#v11-business-logic-verification-requirements)
    - [V11.1 Business Logic Security Requirements](#v111-business-logic-security-requirements)
- [V12: File and Resources Verification Requirements](#v12-authentication-architectural-requirements)
    - [V12.1 File Upload Requirements](#v121-file-upload-requirements)
    - [V12.2 File Integrity Requirements](#v122-file-integrity-requirements)
    - [V12.3 File execution Requirements](#v123-file-execution-requirements)
    - [V12.4 File Storage Requirements](#v124-file-storage-requirements)
    - [V12.5 File Download Requirements](#v125-file-download-requirements)
    - [V12.6 SSRF Protection Requirements](#v126-ssrf-protection-requirements)
- [V13: API and Web Service Verification Requirements](#v13-api-and-web-service-verification-requirements)
    - [V13.1 Generic Web Service Security Verification Requirements](#v131-generic-web-service-security-verification-requirements)
    - [V13.2 RESTful Web Service Verification Requirements](#v132-restful-web-service-verification-requirements)
    - [V13.3 SOAP Web Service Verification Requirements](#v133-soap-web-service-verification-requirements)
    - [V13.4 GraphQL and other Web Service Data Layer Security Requirements](#v134-graphql-and-other-web-service-data-layer-security-requirements)
- [V14: Configuration Verification Requirements](#v14-access-control-architectural-requirements)
    - [V14.1 Build](#v141-build)
    - [V14.2 Dependency](#v142-dependency)
    - [V14.3 Unintended Security Disclosure Requirements](#v143-unintended-security-disclosure-requirements)
    - [V14.4 HTTP Security Headers Requirements](#v144-http-security-headers-requirements)
    - [V14.5 Validate HTTP Request Header Requirements](#v145-validate-http-request-header-requirements)

## Objective

The objective of this index is to help an OWASP [Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) user clearly identify which cheat sheets are useful for each section during his or her usage of the ASVS.

This index is based on the version 4.0.x of the ASVS.

## V1: Architecture, Design and Threat Modeling Requirements

### V1.1 Secure Software Development Lifecycle Requirements

[Threat Modeling Cheat Sheet](cheatsheets/Threat_Modeling_Cheat_Sheet.md)

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

[Attack Surface Analysis Cheat Sheet](cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)

### V1.2 Authentication Architectural Requirements

None.

### V1.3 Session Management Architectural Requirements

None.

### V1.4 Access Control Architectural Requirements

[Docker Security Cheat Sheet](cheatsheets/Docker_Security_Cheat_Sheet.md)

### V1.5 Input and Output Architectural Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

[Deserialization Cheat Sheet](cheatsheets/Deserialization_Cheat_Sheet.md)

### V1.6 Cryptographic Architectural Requirements

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V1.7 Errors, Logging and Auditing Architectural Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

### V1.8 Data Protection and Privacy Architectural Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

[User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V1.9 Communications Architectural Requirements

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V1.10 Malicious Software Architectural Requirements

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

[Virtual Patching Cheat Sheet](cheatsheets/Virtual_Patching_Cheat_Sheet.md)

### V1.11 Business Logic Architectural Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

### V1.12 Secure File Upload Architectural Requirements

None.

### V1.13 API Architectural Requirements

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

### V1.14 Configuration Architectural Requirements

None.

## V2: Authentication Verification Requirements

### V2.1 Password Security Requirements

[Choosing and Using Security Questions Cheat Sheet](cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md)

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

[Credential Stuffing Prevention Cheat Sheet](cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md)

### V2.2 General Authenticator Requirements

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V2.3 Authenticator Lifecycle Requirements

None.

### V2.4 Credential Storage Requirements

[Password Storage Cheat Sheet](cheatsheets/Password_Storage_Cheat_Sheet.md)

### V2.5 Credential Recovery Requirements

[Choosing and Using Security Questions Cheat Sheet](cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md)

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

### V2.6 Look-up Secret Verifier Requirements

None.

### V2.7 Out of Band Verifier Requirements

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

### V2.8 Single or Multi Factor One Time Verifier Requirements

None.

### V2.9 Cryptographic Software and Devices Verifier Requirements

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V2.10 Service Authentication Requirements

None.

## V3: Session Management Verification Requirements

### V3.1 Fundamental Session Management Requirements

None.

### V3.2 Session Binding Requirements

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V3.3 Session Logout and Timeout Requirements

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V3.4 Cookie-based Session Management

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

### V3.5 Token-based Session Management

[JSON Web Token Cheat Sheet for Java](cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md)

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

### V3.6 Re-authentication from a Federation or Assertion

None.

### V3.7 Defenses Against Session Management Exploits

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

[Transaction Authorization Cheat Sheet](cheatsheets/Transaction_Authorization_Cheat_Sheet.md)

## V4: Access Control Verification Requirements

### V4.1 General Access Control Design

[Access Control Cheat Sheet](cheatsheets/Access_Control_Cheat_Sheet.md)

[Authorization Testing Automation](cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)

### V4.2 Operation Level Access Control

[Insecure Direct Object Reference Prevention Cheat Sheet](cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[Authorization Testing Automation](cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)

### V4.3 Other Access Control Considerations

[REST Assessment Cheat Sheet](cheatsheets/REST_Assessment_Cheat_Sheet.md)
[Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

## V5: Validation, Sanitization and Encoding Verification Requirements

### V5.1 Input Validation Requirements

[Mass Assignment Cheat Sheet](cheatsheets/Mass_Assignment_Cheat_Sheet.md)

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

### V5.2 Sanitization and Sandboxing Requirements

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

[XSS Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

[DOM based XSS Prevention Cheat Sheet](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

### V5.3 Output encoding and Injection Prevention Requirements

[XSS Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

[DOM based XSS Prevention Cheat Sheet](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet](cheatsheets/Injection_Prevention_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet in Java](cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.md)

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[LDAP Injection Prevention Cheat Sheet](cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md)

[OS Command Injection Defense Cheat Sheet](cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md)

[Protect File Upload Against Malicious File](cheatsheets/File_Upload_Cheat_Sheet.md)

[Query Parameterization Cheat Sheet](cheatsheets/Query_Parameterization_Cheat_Sheet.md)

[SQL Injection Prevention Cheat Sheet](cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md)

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

[Bean Validation Cheat Sheet](cheatsheets/Bean_Validation_Cheat_Sheet.md)

[XXE Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md)

### V5.4 Memory, String, and Unmanaged Code Requirements

None.

### V5.5 Deserialization Prevention Requirements

[Deserialization Cheat Sheet](cheatsheets/Deserialization_Cheat_Sheet.md)

[XXE Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md)

## V6: Stored Cryptography Verification Requirements

### V6.1 Data Classification

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

[User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V6.2 Algorithms

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V6.3 Random Values

None.

### V6.4 Secret Management

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

## V7: Error Handling and Logging Verification Requirements

### V7.1 Log Content Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

### V7.2 Log Processing Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

### V7.3 Log Protection Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

### V7.4 Error Handling

[Error Handling Cheat Sheet](cheatsheets/Error_Handling_Cheat_Sheet.md)

## V8: Data Protection Verification Requirements

### V8.1 General Data Protection

None.

### V8.2 Client-side Data Protection

None.

### V8.3 Sensitive Private Data

None.

## V9: Communications Verification Requirements

### V9.1 Communications Security Requirements

[HTTP Strict Transport Security Cheat Sheet](cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V9.2 Server Communications Security Requirements

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

## V10: Malicious Code Verification Requirements

### V10.1 Code Integrity Controls

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V10.2 Malicious Code Search

None.

### V10.3 Deployed Application Integrity Controls

[Docker Security Cheat Sheet](cheatsheets/Docker_Security_Cheat_Sheet.md)

## V11: Business Logic Verification Requirements

### V11.1 Business Logic Security Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

## V12: File and Resources Verification Requirements

### V12.1 File Upload Requirements

[Protect File Upload Against Malicious File](cheatsheets/File_Upload_Cheat_Sheet.md)

### V12.2 File Integrity Requirements

[Protect File Upload Against Malicious File](cheatsheets/File_Upload_Cheat_Sheet.md)

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V12.3 File execution Requirements

None.

### V12.4 File Storage Requirements

None.

### V12.5 File Download Requirements

None.

### V12.6 SSRF Protection Requirements

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

## V13: API and Web Service Verification Requirements

### V13.1 Generic Web Service Security Verification Requirements

[Web Service Security Cheat Sheet](cheatsheets/Web_Service_Security_Cheat_Sheet.md)

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

### V13.2 RESTful Web Service Verification Requirements

[REST Assessment Cheat Sheet](cheatsheets/REST_Assessment_Cheat_Sheet.md)

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V13.3 SOAP Web Service Verification Requirements

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md)

### V13.4 GraphQL and other Web Service Data Layer Security Requirements

None.

## V14: Configuration Verification Requirements

### V14.1 Build

[Docker Security Cheat Sheet](cheatsheets/Docker_Security_Cheat_Sheet.md)

### V14.2 Dependency

[Docker Security Cheat Sheet](cheatsheets/Docker_Security_Cheat_Sheet.md)

[Vulnerable Dependency Management Cheat Sheet](cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.md)

### V14.3 Unintended Security Disclosure Requirements

[Error Handling Cheat Sheet](cheatsheets/Error_Handling_Cheat_Sheet.md)

### V14.4 HTTP Security Headers Requirements

[Content Security Policy Cheat Sheet](cheatsheets/Content_Security_Policy_Cheat_Sheet.md)

### V14.5 Validate HTTP Request Header Requirements

None.
