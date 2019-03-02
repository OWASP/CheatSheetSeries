# Objective

This index have for objective to indicate to help an OWASP [Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)  (ASVS) user to clearly identify which cheat sheets are useful for each section during his usage of the ASVS.

This index is based on the version 4.x of the ASVS.

# Not addressed topic

Section with `None` content can spot a topic that should be addressed by the Cheat Sheet Series project.

Do not hesitate to open an [issue](https://github.com/OWASP/CheatSheetSeries/issues/new?assignees=&labels=ACK_WAITING%2C+NEW_CS&template=new_cheatsheet_proposal.md&title=New+cheat+sheet+proposal) if you need that a dedicated cheat sheet be created to provide information about the target ASVS section.

# V1: Architecture, Design and Threat Modeling Requirements

## V1.1 Secure Software Development Lifecycle Requirements

[Threat Modeling Cheat Sheet](cheatsheets/Threat_Modeling_Cheat_Sheet.md).

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md).

[Attack Surface Analysis Cheat Sheet](cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md).

## V1.2 Authentication Architectural Requirements

None.

## V1.3 Session Management Architectural Requirements

None.

## V1.4 Access Control Architectural Requirements

None.

## V1.5 Input and Output Architectural Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md).

[Deserialization Cheat Sheet](cheatsheets/Deserialization_Cheat_Sheet.md).

## V1.6 Cryptographic Architectural Requirements

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md).

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md).

## V1.7 Errors, Logging and Auditing Architectural Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md).

## V1.8 Data Protection and Privacy Architectural Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md).

[User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md).

## V1.9 Communications Architectural Requirements

[Transport Layer Protection Cheat Sheet](cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md).

[TLS Cipher String Cheat Sheet](cheatsheets/TLS_Cipher_String_Cheat_Sheet.md).

## V1.10 Malicious Software Architectural Requirements

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md).

[Virtual Patching Cheat Sheet](cheatsheets/Virtual_Patching_Cheat_Sheet.md).

## V1.11 Business Logic Architectural Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md).

## V1.12 Secure File Upload Architectural Requirements

None.

## V1.13 API Architectural Requirements

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md).

## V1.14 Configuration Architectural Requirements

None.

# V2: Authentication Verification Requirements

## V2.1 Password Security Requirements

[Choosing and Using Security Questions Cheat Sheet](cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md).

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md).

[Credential Stuffing Prevention Cheat Sheet](cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md)

## V2.2 General Authenticator Requirements

[Authentication Cheat Sheet](cheatsheets/Authentication_Cheat_Sheet.md).

[Transport Layer Protection Cheat Sheet](cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md).

[TLS Cipher String Cheat Sheet](cheatsheets/TLS_Cipher_String_Cheat_Sheet.md).

## V2.3 Authenticator Lifecycle Requirements

None.

## V2.4 Credential Storage Requirements

[Password Storage Cheat Sheet](cheatsheets/Password_Storage_Cheat_Sheet.md).

## V2.5 Credential Recovery Requirements

[Choosing and Using Security Questions Cheat Sheet](cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md).

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md).

## V2.6 Look-up Secret Verifier Requirements

None.

## V2.7 Out of Band Verifier Requirements

[Forgot Password Cheat Sheet](cheatsheets/Forgot_Password_Cheat_Sheet.md).

## V2.8 Single or Multi Factor One Time Verifier Requirements

None.

## V2.9 Cryptographic Software and Devices Verifier Requirements

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md).

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md).

## V2.10 Service Authentication Requirements

None.

# V3: Session Management Verification Requirements

## V3.1 Fundamental Session Management Requirements

None.

## V3.2 Session Binding Requirements

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md).

## V3.3 Session Logout and Timeout Requirements

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md).

## V3.4 Cookie-based Session Management

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md).

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

## V3.5 Token-based Session Management

[JSON Web Token Cheat Sheet for Java](cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md).

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md).

## V3.6 Re-authentication from a Federation or Assertion

None.

## V3.7 Defenses Against Session Management Exploits

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md).

[Transaction Authorization Cheat Sheet](cheatsheets/Transaction_Authorization_Cheat_Sheet.md).

# V4: Access Control Verification Requirements

## V4.1 General Access Control Design

[Access Control Cheat Sheet](cheatsheets/Access_Control_Cheat_Sheet.md).

[Authorization Testing Automation](cheatsheets/Authorization_Testing_Automation.md).

## V4.2 Operation Level Access Control

[Insecure Direct Object Reference Prevention Cheat Sheet](cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md).

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

[Authorization Testing Automation](cheatsheets/Authorization_Testing_Automation.md).

## V4.3 Other Access Control Considerations

[REST Assessment Cheat Sheet](cheatsheets/REST_Assessment_Cheat_Sheet.md).

# V5: Validation, Sanitization and Encoding Verification Requirements

## V5.1 Input Validation Requirements

[Mass Assignment Cheat Sheet](cheatsheets/Mass_Assignment_Cheat_Sheet.md).

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md).

## V5.2 Sanitization and Sandboxing Requirements

[XSS Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

[DOM based XSS Prevention Cheat Sheet](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md).

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md).

## V5.3 Output encoding and Injection Prevention Requirements

[XSS Prevention Cheat Sheet](cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

[DOM based XSS Prevention Cheat Sheet](cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md).

[HTML5 Security Cheat Sheet](cheatsheets/HTML5_Security_Cheat_Sheet.md).

[Injection Prevention Cheat Sheet](cheatsheets/Injection_Prevention_Cheat_Sheet.md).

[Injection Prevention Cheat Sheet in Java](cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.md).

[Input Validation Cheat Sheet](cheatsheets/Input_Validation_Cheat_Sheet.md).

[LDAP Injection Prevention Cheat Sheet](cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md).

[OS Command Injection Defense Cheat Sheet](cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md).

[Protect File Upload Against Malicious File](cheatsheets/Protect_FileUpload_Against_Malicious_File.md).

[Query Parameterization Cheat Sheet](cheatsheets/Query_Parameterization_Cheat_Sheet.md).

[SQL Injection Prevention Cheat Sheet](cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md).

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md).

[Bean Validation Cheat Sheet](cheatsheets/Bean_Validation_Cheat_Sheet.md).

[XXE Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md).

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md).

## V5.4 Memory, String, and Unmanaged Code Requirements

None.

## V5.5 Deserialization Prevention Requirements

[Deserialization Cheat Sheet](cheatsheets/Deserialization_Cheat_Sheet.md).

[XXE Prevention Cheat Sheet](cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md).

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md).

# V6: Stored Cryptography Verification Requirements

## V6.1 Data Classification

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md).

[User Privacy Protection Cheat Sheet](cheatsheets/User_Privacy_Protection_Cheat_Sheet.md).

## V6.2 Algorithms

[Cryptographic Storage Cheat Sheet](cheatsheets/Cryptographic_Storage_Cheat_Sheet.md).

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md).

## V6.3 Random Values

None.

## V6.4 Secret Management

[Key Management Cheat Sheet](cheatsheets/Key_Management_Cheat_Sheet.md).

# V7: Error Handling and Logging Verification Requirements

## V7.1 Log Content Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md).

## V7.2 Log Processing Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md).

## V7.3 Log Protection Requirements

[Logging Cheat Sheet](cheatsheets/Logging_Cheat_Sheet.md).

## V7.4 Error Handling

[Error Handling Cheat Sheet](cheatsheets/Error_Handling_Cheat_Sheet.md).

# V8: Data Protection Verification Requirements

## V8.1 General Data Protection

None.

## V8.2 Client-side Data Protection

None.

## V8.3 Sensitive Private Data

None.

# V9: Communications Verification Requirements

## V9.1 Communications Security Requirements

[HTTP Strict Transport Security Cheat Sheet](cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md).

[Transport Layer Protection Cheat Sheet](cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md).

[TLS Cipher String Cheat Sheet](cheatsheets/TLS_Cipher_String_Cheat_Sheet.md).

## V9.2 Server Communications Security Requirements

None.

# V10: Malicious Code Verification Requirements

## V10.1 Code Integrity Controls

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md).

## V10.2 Malicious Code Search

None.

## V10.3 Deployed Application Integrity Controls

None.

# V11: Business Logic Verification Requirements

## V11.1 Business Logic Security Requirements

[Abuse Case Cheat Sheet](cheatsheets/Abuse_Case_Cheat_Sheet.md).

# V12: File and Resources Verification Requirements

## V12.1 File Upload Requirements

[Protect File Upload Against Malicious File](cheatsheets/Protect_FileUpload_Against_Malicious_File.md).

## V12.2 File Integrity Requirements

[Protect File Upload Against Malicious File](cheatsheets/Protect_FileUpload_Against_Malicious_File.md).

[Third Party Javascript Management Cheat Sheet](cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md).

## V12.3 File execution Requirements

None.

## V12.4 File Storage Requirements

None.

## V12.5 File Download Requirements

None.

## V12.6 SSRF Protection Requirements

[Unvalidated Redirects and Forwards Cheat Sheet](cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md).

# V13: API and Web Service Verification Requirements

## V13.1 Generic Web Service Security Verification Requirements

[Web Service Security Cheat Sheet](cheatsheets/Web_Service_Security_Cheat_Sheet.md).

## V13.2 RESTful Web Service Verification Requirements

[REST Assessment Cheat Sheet](cheatsheets/REST_Assessment_Cheat_Sheet.md).

[REST Security Cheat Sheet](cheatsheets/REST_Security_Cheat_Sheet.md).

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

## V13.3 SOAP Web Service Verification Requirements

[XML Security Cheat Sheet](cheatsheets/XML_Security_Cheat_Sheet.md).

## V13.4 GraphQL and other Web Service Data Layer Security Requirements

None.

# V14: Configuration Verification Requirements

## V14.1 Build

None.

## V14.2 Dependency

None.

## V14.3 Unintended Security Disclosure Requirements

[Error Handling Cheat Sheet](cheatsheets/Error_Handling_Cheat_Sheet.md).

## V14.4 HTTP Security Headers Requirements

None.

## V14.5 Validate HTTP Request Header Requirements

None.