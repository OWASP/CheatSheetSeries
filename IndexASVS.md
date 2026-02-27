# ASVS Index

## Table of Contents

- [Objective](#objective)
- [V1: Encoding and Sanitization](#v1-encoding-and-sanitization)
    - [V1.1 Encoding and Sanitization Architecture](#v11-encoding-and-sanitization-architecture)
    - [V1.2 Injection Prevention](#v12-injection-prevention)
    - [V1.3 Sanitization](#v13-sanitization)
    - [V1.4 Memory, String, and Unmanaged Code](#v14-memory-string-and-unmanaged-code)
    - [V1.5 Safe Deserialization](#v15-safe-deserialization)
- [V2: Validation and Business Logic](#v2-validation-and-business-logic)
    - [V2.1 Validation and Business Logic Documentation](#v21-validation-and-business-logic-documentation)
    - [V2.2 Input Validation](#v22-input-validation)
    - [V2.3 Business Logic Security](#v23-business-logic-security)
    - [V2.4 Anti-automation](#v24-anti-automation)
- [V3: Web Frontend Security](#v3-web-frontend-security)
    - [V3.1 Web Frontend Security Documentation](#v31-web-frontend-security-documentation)
    - [V3.2 Unintended Content Interpretation](#v32-unintended-content-interpretation)
    - [V3.3 Cookie Setup](#v33-cookie-setup)
    - [V3.4 Browser Security Mechanism Headers](#v34-browser-security-mechanism-headers)
    - [V3.5 Browser Origin Separation](#v35-browser-origin-separation)
    - [V3.6 External Resource Integrity](#v36-external-resource-integrity)
    - [V3.7 Other Browser Security Considerations](#v37-other-browser-security-considerations)
- [V4: API and Web Service](#v4-api-and-web-service)
    - [V4.1 Generic Web Service Security](#v41-generic-web-service-security)
    - [V4.2 HTTP Message Structure Validation](#v42-http-message-structure-validation)
    - [V4.3 GraphQL](#v43-graphql)
    - [V4.4 WebSocket](#v44-websocket)
- [V5: File Handling](#v5-file-handling)
    - [V5.1 File Handling Documentation](#v51-file-handling-documentation)
    - [V5.2 File Upload and Content](#v52-file-upload-and-content)
    - [V5.3 File Storage](#v53-file-storage)
    - [V5.4 File Download](#v54-file-download)
- [V6: Authentication](#v6-authentication)
    - [V6.1 Authentication Documentation](#v61-authentication-documentation)
    - [V6.2 Password Security](#v62-password-security)
    - [V6.3 General Authentication Security](#v63-general-authentication-security)
    - [V6.4 Authentication Factor Lifecycle and Recovery](#v64-authentication-factor-lifecycle-and-recovery)
    - [V6.5 General Multi-factor authentication requirements](#v65-general-multi-factor-authentication-requirements)
    - [V6.6 Out-of-Band authentication mechanisms](#v66-out-of-band-authentication-mechanisms)
    - [V6.7 Cryptographic authentication mechanism](#v67-cryptographic-authentication-mechanism)
    - [V6.8 Authentication with an Identity Provider](#v68-authentication-with-an-identity-provider)
- [V7: Session Management](#v7-session-management)
    - [V7.1 Session Management Documentation](#v71-session-management-documentation)
    - [V7.2 Fundamental Session Management Security](#v72-fundamental-session-management-security)
    - [V7.3 Session Timeout](#v73-session-timeout)
    - [V7.4 Session Termination](#v74-session-termination)
    - [V7.5 Defenses Against Session Abuse](#v75-defenses-against-session-abuse)
    - [V7.6 Federated Re-authentication](#v76-federated-re-authentication)
- [V8: Authorization](#v8-authorization)
    - [V8.1 Authorization Documentation](#v81-authorization-documentation)
    - [V8.2 General Authorization Design](#v82-general-authorization-design)
    - [V8.3 Operation Level Authorization](#v83-operation-level-authorization)
    - [V8.4 Other Authorization Considerations](#v84-other-authorization-considerations)
- [V9: Self-contained Tokens](#v9-self-contained-tokens)
    - [V9.1 Token source and integrity](#v91-token-source-and-integrity)
    - [V9.2 Token content](#v92-token-content)
- [V10: OAuth and OIDC](#v10-oauth-and-oidc)
    - [V10.1 Generic OAuth and OIDC Security](#v101-generic-oauth-and-oidc-security)
    - [V10.2 OAuth Client](#v102-oauth-client)
    - [V10.3 OAuth Resource Server](#v103-oauth-resource-server)
    - [V10.4 OAuth Authorization Server](#v104-oauth-authorization-server)
    - [V10.5 OIDC Client](#v105-oidc-client)
    - [V10.6 OpenID Provider](#v106-openid-provider)
    - [V10.7 Consent Management](#v107-consent-management)
- [V11: Cryptography](#v11-cryptography)
    - [V11.1 Cryptographic Inventory and Documentation](#v111-cryptographic-inventory-and-documentation)
    - [V11.2 Secure Cryptography Implementation](#v112-secure-cryptography-implementation)
    - [V11.3 Encryption Algorithms](#v113-encryption-algorithms)
    - [V11.4 Hashing and Hash-based Functions](#v114-hashing-and-hash-based-functions)
    - [V11.5 Random Values](#v115-random-values)
    - [V11.6 Public Key Cryptography](#v116-public-key-cryptography)
    - [V11.7 In-Use Data Cryptography](#v117-in-use-data-cryptography)
- [V12: Secure Communication](#v12-secure-communication)
    - [V12.1 General TLS Security Guidance](#v121-general-tls-security-guidance)
    - [V12.2 HTTPS Communication with External Facing Services](#v122-https-communication-with-external-facing-services)
    - [V12.3 General Service to Service Communication Security](#v123-general-service-to-service-communication-security)
- [V13: Configuration](#v13-configuration)
    - [V13.1 Configuration Documentation](#v131-configuration-documentation)
    - [V13.2 Backend Communication Configuration](#v132-backend-communication-configuration)
    - [V13.3 Secret Management](#v133-secret-management)
    - [V13.4 Unintended Information Leakage](#v134-unintended-information-leakage)
- [V14: Data Protection](#v14-data-protection)
    - [V14.1 Data Protection Documentation](#v141-data-protection-documentation)
    - [V14.2 General Data Protection](#v142-general-data-protection)
    - [V14.3 Client-side Data Protection](#v143-client-side-data-protection)
- [V15: Secure Coding and Architecture](#v15-secure-coding-and-architecture)
    - [V15.1: Secure Coding and Architecture Documentation](#v151-secure-coding-and-architecture-documentation)
    - [V15.2: Security Architecture and Dependencies](#v152-security-architecture-and-dependencies)
    - [V15.3: Defensive Coding](#v153-defensive-coding)
    - [V15.4: Safe Concurrency](#v154-safe-concurrency)
- [V16: Security Logging and Error Handling](#v16-security-logging-and-error-handling)
    - [V16.1: Security Logging Documentation](#v161-security-logging-documentation)
    - [V16.2: General Logging](#v162-general-logging)
    - [V16.3: Security Events](#v163-security-events)
    - [V16.4: Log Protection](#v164-log-protection)
    - [V16.5: Error Handling](#v165-error-handling)
- [V17: WebRTC](#v17-webrtc)
    - [V17.1: TURN Server](#v171-turn-server)
    - [V17.2: Media](#v172-media)
    - [V17.3: Signaling](#v173-signaling)

## Objective

The objective of this index is to help an OWASP [Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) user clearly identify which cheat sheets are useful for each section during his or her usage of the ASVS.

This index is based on the version 5.0.x of the ASVS. For ASVS 4.0.x, please go to the [DEPRECATED: ASVS 4.0 Index](IndexASVS4.m).

## V1: Encoding and Sanitization

### V1.1 Encoding and Sanitization Architecture

[Cross Site Scripting Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

### V1.2 Injection Prevention

[Bean Validation Cheat Sheet](cheatsheets/Bean_Validation_Cheat_Sheet.md)

[Cross Site Scripting Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

[DOM based XSS Prevention Cheat Sheet](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)

[File Upload Cheat Sheet](cheatsheets/File_Upload_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet](cheatsheets/Injection_Prevention_Cheat_Sheet.md)

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[Java Security Cheat Sheet](cheatsheets/Java_Security_Cheat_Sheet.md)

[LDAP Injection Prevention](cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md)

[OS Command Injection Defense](cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md)

[Query Parameterization Cheat Sheet](cheatsheets/Query_Parameterization_Cheat_Sheet.md)

[SQL Injection Prevention](cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md)

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md)

[XSS Filter Evasion Cheat Sheet](cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.md)

[XML External Entity Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

### V1.3 Sanitization

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[Cross Site Scripting Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

[DOM based XSS Prevention Cheat Sheet](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet](cheatsheets/Injection_Prevention_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet in Java](cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.md)

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[LDAP Injection Prevention](cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md)

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

[XML External Entity Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

### V1.4 Memory, String, and Unmanaged Code

None.

### V1.5 Safe Deserialization

[Deserialization Cheat Sheet](cheatsheets/Deserialization_Cheat_Sheet.md)

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md)

[XML External Entity Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

## V2: Validation and Business Logic

### V2.1 Validation and Business Logic Documentation

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

### V2.2 Input Validation

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[Microservices Security Cheat Sheet](cheatsheets/Microservices_Security_Cheat_Sheet.md)

[Web Service Security Cheat Sheet](cheatsheets/Web_Service_Security_Cheat_Sheet.md)

### V2.3 Business Logic Security

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

### V2.4 Anti-automation

[Denial of Service Cheat Sheet](cheatsheets/Denial_of_Service_Cheat_Sheet.md)

## V3: Web Frontend Security

### V3.1 Web Frontend Security Documentation

[Content Security Policy Cheat Sheet](cheatsheets/Content_Security_Policy_Cheat_Sheet.md)

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[HTTP Strict Transport Security Cheat Sheet](cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md)

### V3.2 Unintended Content Interpretation

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[DOM Clobbering Prevention Cheat Sheet](cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.md)

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md)

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V3.3 Cookie Setup

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V3.4 Browser Security Mechanism Headers

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md)

[HTTP Strict Transport Security Cheat Sheet](cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md)

### V3.5 Browser Origin Separation

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md)

### V3.6 External Resource Integrity

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

### V3.7 Other Browser Security Considerations

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[HTTP Strict Transport Security Cheat Sheet](cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md)

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

## V4: API and Web Service

### V4.1 Generic Web Service Security

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

[REST Assessment Cheat Sheet](cheatsheets/REST_Assessment_Cheat_Sheet.md)

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

[Web Service Security Cheat Sheet](cheatsheets/Web_Service_Security_Cheat_Sheet.md)

### V4.2 HTTP Message Structure Validation

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

[Web Service Security Cheat Sheet](cheatsheets/Web_Service_Security_Cheat_Sheet.md)

### V4.3 GraphQL

[REST Security Cheat Sheet](cheatsheets/GraphQL_Cheat_Sheet.md)

### V4.4 WebSocket

[REST Security Cheat Sheet](cheatsheets/WebSocket_Security_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

## V5: File Handling

### V5.1 File Handling Documentation

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[File Upload Cheat Sheet](cheatsheets/File_Upload_Cheat_Sheet.md)

### V5.2 File Upload and Content

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[File Upload Cheat Sheet](cheatsheets/File_Upload_Cheat_Sheet.md)

### V5.3 File Storage

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md)

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

### V5.4 File Download

[File Upload Cheat Sheet](cheatsheets/File_Upload_Cheat_Sheet.md)

## V6: Authentication

### V6.1 Authentication Documentation

[Credential Stuffing Prevention Cheat Sheet](cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md)

### V6.2 Password Security

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

### V6.3 General Authentication Security

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

[Credential Stuffing Prevention Cheat Sheet](cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md)

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

### V6.4 Authentication Factor Lifecycle and Recovery

[Choosing and Using Security Questions Cheat Sheet](cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md)

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

[Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

### V6.5 General Multi-factor authentication requirements

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

[Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

[Password Storage Cheat Sheet](cheatsheets/Password_Storage_Cheat_Sheet.md)

[Transaction Authorization Cheat Sheet](cheatsheets/Transaction_Authorization_Cheat_Sheet.md)

### V6.6 Out-of-Band authentication mechanisms

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md)

[Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

### V6.7 Cryptographic authentication mechanism

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

[Multifactor Authentication Cheat Sheet](cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)

### V6.8 Authentication with an Identity Provider

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md)

## V7: Session Management

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V7.1 Session Management Documentation

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V7.2 Fundamental Session Management Security

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V7.3 Session Timeout

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V7.4 Session Termination

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V7.5 Defenses Against Session Abuse

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V7.6 Federated Re-authentication

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

## V8: Authorization

### V8.1 Authorization Documentation

[Authorization Cheat Sheet](cheatsheets/Authorization_Cheat_Sheet.md)

[Authorization Testing Automation](cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)

### V8.2 General Authorization Design

[Authorization Cheat Sheet](cheatsheets/Authorization_Cheat_Sheet.md)

[Insecure Direct Object Reference Prevention Cheat Sheet](cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V8.3 Operation Level Authorization

[Transaction Authorization Cheat Sheet](cheatsheets/Transaction_Authorization_Cheat_Sheet.md)

### V8.4 Other Authorization Considerations

[Authorization Cheat Sheet](cheatsheets/Authorization_Cheat_Sheet.md)

[Multi-Tenant Application Security Cheat Sheet](cheatsheets/Multi_Tenant_Security_Cheat_Sheet.md)

## V9: Self-contained Tokens

### V9.1 Token source and integrity

[JSON Web Token Cheat Sheet for Java](cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md)

[SAML Security Cheat Sheet](cheatsheets/SAML_Security_Cheat_Sheet.md)

### V9.2 Token content

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md)

## V10: OAuth and OIDC

### V10.1 Generic OAuth and OIDC Security

[OAuth 2.0 Protocol Cheatsheet](cheatsheets/OAuth2_Cheat_Sheet.md)

### V10.2 OAuth Client

[OAuth 2.0 Protocol Cheatsheet](cheatsheets/OAuth2_Cheat_Sheet.md)

### V10.3 OAuth Resource Server

[OAuth 2.0 Protocol Cheatsheet](cheatsheets/OAuth2_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V10.4 OAuth Authorization Server

[OAuth 2.0 Protocol Cheatsheet](cheatsheets/OAuth2_Cheat_Sheet.md)

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

### V10.5 OIDC Client

[OAuth 2.0 Protocol Cheatsheet](cheatsheets/OAuth2_Cheat_Sheet.md)

### V10.6 OpenID Provider

[OAuth 2.0 Protocol Cheatsheet](cheatsheets/OAuth2_Cheat_Sheet.md)

### V10.7 Consent Management

[Browser Extension Security Vulnerabilities](cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.md)

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

## V11: Cryptography

### V11.1 Cryptographic Inventory and Documentation

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V11.2 Secure Cryptography Implementation

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

### V11.3 Encryption Algorithms

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V11.4 Hashing and Hash-based Functions

[Password Storage Cheat Sheet](cheatsheets/Password_Storage_Cheat_Sheet.md)

### V11.5 Random Values

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

### V11.6 Public Key Cryptography

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V11.7 In-Use Data Cryptography

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

[Microservices Security Cheat Sheet](cheatsheets/Microservices_Security_Cheat_Sheet.md)

[Secrets Management Cheat Sheet](cheatsheets/Secrets_Management_Cheat_Sheet.md)

## V12: Secure Communication

### V12.1 General TLS Security Guidance

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V12.2 HTTPS Communication with External Facing Services

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

### V12.3 General Service to Service Communication Security

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

## V13: Configuration

### V13.1 Configuration Documentation

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

### V13.2 Backend Communication Configuration

[Docker Security Cheat Sheet](cheatsheets/Docker_Security_Cheat_Sheet.md)

[Server Side Request Forgery Prevention Cheat Sheet](cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)

### V13.3 Secret Management

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md)

### V13.4 Unintended Information Leakage

[Django Cheat Sheet](cheatsheets/Laravel_Cheat_Sheet.md)

[GraphQL Cheat Sheet](cheatsheets/Laravel_Cheat_Sheet.md)

[Laravel Cheat Sheet](cheatsheets/Laravel_Cheat_Sheet.md)

[NPM Security best practices](cheatsheets/NPM_Security_Cheat_Sheet.md)

[Symfony Cheat Sheet](cheatsheets/Symfony_Cheat_Sheet.md)

## V14: Data Protection

### V14.1 Data Protection Documentation

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)

[User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V14.2 General Data Protection

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md)

[User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md)

### V14.3 Client-side Data Protection

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md)

## V15: Secure Coding and Architecture

### V15.1: Secure Coding and Architecture Documentation

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md)

[Attack Surface Analysis Cheat Sheet](cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)

[Dependency Graph & SBOM Best Practices Cheat Sheet](cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.md)

[Software Supply Chain Security](cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.md)

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

[Threat Modeling Cheat Sheet](cheatsheets/Threat_Modeling_Cheat_Sheet.md)

### V15.2: Security Architecture and Dependencies

[Software Supply Chain Security](cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.md)

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)

[Virtual Patching Cheat Sheet](cheatsheets/Virtual_Patching_Cheat_Sheet.md)

[Vulnerable Dependency Management Cheat Sheet](cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.md)

### V15.3: Defensive Coding

[Mass Assignment Cheat Sheet](cheatsheets/Mass_Assignment_Cheat_Sheet.md)

[Prototype Pollution Prevention Cheat Sheet](cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.md)

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)

### V15.4: Safe Concurrency

[Secure Code Review Cheat Sheet](cheatsheets/Secure_Code_Review_Cheat_Sheet.md)

[Transaction Authorization Cheat Sheet](cheatsheets/Transaction_Authorization_Cheat_Sheet.md)

## V16: Security Logging and Error Handling

### V16.1: Security Logging Documentation

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

[Logging Vocabulary Cheat Sheet](cheatsheets/Logging_Vocabulary_Cheat_Sheet.md)

### V16.2: General Logging

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

### V16.3: Security Events

[Authorization Cheat Sheet](cheatsheets/Authorization_Cheat_Sheet.md)

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

[Logging Vocabulary Cheat Sheet](cheatsheets/Logging_Vocabulary_Cheat_Sheet.md)

### V16.4: Log Protection

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md)

### V16.5: Error Handling

[Error Handling Cheat Sheet](cheatsheets/Error_Handling_Cheat_Sheet.md)

## V17: WebRTC

### V17.1 TURN Server

None.

## V17.2 Media

[Transport Layer Security Cheat Sheet](cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)

## V17.3 Signaling

None.
