# Security Definitions Cheatsheet

A concise reference of key security concepts for developers. This document provides clear, linked definitions to improve understanding of the OWASP Cheat Sheet Series.

---

## Encoding
**Definition:** Transforming data into a specific format for safe transmission or storage.  
**Purpose:** Prevent misinterpretation or injection attacks.  
**Example:** Base64 encoding.  
**See also:** [Escaping](#escaping), [Input Validation](#input-validation)

---

## Escaping
**Definition:** Adding special characters to data to prevent it from being interpreted as code.  
**Purpose:** Prevent injection attacks in contexts like HTML, SQL, or JavaScript.  
**Example:** Replacing `<` with `&lt;` in HTML.  
**See also:** [Encoding](#encoding), [Sanitization & Filtering](#sanitization--filtering)

---

## Serialization
**Definition:** Converting an object or data structure into a format that can be stored, transmitted, and reconstructed later.  
**Security Note:** Unsanitized serialized data can lead to deserialization attacks.

---

## Cryptography Concepts
- **Encryption:** Transforming data so only authorized parties can read it.  
- **Decryption:** Reversing encryption to restore original data.  
- **Hashing:** Creating a fixed-length digest of data; cannot be reversed.  
- **Digital Signature:** Validates authenticity and integrity of data.  
**See also:** [Authentication](#authentication), [Authorization](#authorization)

---

## Authentication
**Definition:** Verifying the identity of a user, system, or entity.  
**Example:** Logging in with a password or via OAuth.  
**See also:** [Authorization](#authorization), [Session Management](#session-management)

---

## Authorization
**Definition:** Determining what an authenticated user is allowed to do.  
**Example:** Admins can delete content; regular users cannot.  
**See also:** [Authentication](#authentication), [Access Control](#access-control)

---

## Input Validation
**Definition:** Ensuring user input conforms to expected type, format, and range.  
**Purpose:** Prevent attacks like SQL injection, XSS, and command injection.  
**See also:** [Sanitization & Filtering](#sanitization--filtering), [Encoding](#encoding)

---

## Sanitization & Filtering
- **Sanitization:** Cleaning input to remove harmful content.  
- **Filtering:** Restricting input to allowed characters or patterns.  
**Example:** Removing `<script>` tags to prevent XSS.  
**See also:** [Escaping](#escaping), [Input Validation](#input-validation)

---

## Session Management
**Definition:** Secure handling of user sessions (e.g., tokens, cookies).  
**Purpose:** Prevent session hijacking and replay attacks.  
**See also:** [Authentication](#authentication)

---

## Access Control
**Definition:** Enforcing permissions on resources to restrict unauthorized access.  
**See also:** [Authorization](#authorization)

---

## Logging & Monitoring
**Definition:** Tracking activity to detect and respond to security events.

---

## Secure Defaults
**Definition:** Configurations that prioritize security by default.
