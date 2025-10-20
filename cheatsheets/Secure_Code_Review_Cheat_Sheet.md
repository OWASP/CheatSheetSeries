# Secure Code Review Cheat Sheet

## Introduction

**Secure Code Review** is the process of manually examining source code to identify security vulnerabilities that automated tools often miss. It involves analyzing application logic, data flow, and implementation details to detect security flaws that require human expertise and contextual understanding.

**Manual Code Review** complements automated security testing tools (SAST/DAST) by focusing on areas where human analysis provides the most value, including business logic validation, complex security implementations, and context-specific vulnerabilities.

**Security-Focused Review** differs from functional code review by specifically targeting security concerns such as input validation, authentication mechanisms, authorization controls, cryptographic implementations, and potential attack vectors.

This cheat sheet provides practical guidance for conducting effective security code reviews, including methodologies, checklists, tools, and integration strategies for incorporating security reviews into the software development lifecycle.

## Review Methodology

### Preparation

Before starting the review:

- **Understand the Application**: Review architecture diagrams, data flow, and business requirements
- **Define Review Scope**: Specify boundaries (new code, changed files, or full application)
- **Gather Context**: Collect threat models, previous security findings, and compliance requirements
- **Identify Critical Assets**: Focus on sensitive data, high-risk functions, and external interfaces
- **Review Documentation**: Examine security requirements, design documents, and API specifications
- **Understand Attack Surface**: Map all entry points, APIs, and external integrations
- **Check Dependencies**: Review third-party libraries and their known vulnerabilities

### Review Process

Conduct the review in phases:

1. **Architecture Review**: Examine high-level design for security anti-patterns
2. **Entry Point Analysis**: Review all input vectors and validation mechanisms
3. **Authentication & Authorization**: Verify access controls and session management
4. **Data Flow Analysis**: Trace sensitive data through the application
5. **Business Logic Review**: Analyze workflows for logic flaws and race conditions
6. **Cryptographic Review**: Check encryption, hashing, and key management
7. **Error Handling**: Verify proper error handling and information disclosure prevention
8. **Configuration Review**: Check security configurations and deployment settings

## Common Vulnerability Patterns

### Input Validation Vulnerabilities

Check for missing server-side validation, improper sanitization, and weak input filtering. For more information, see [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md).

### Injection Vulnerabilities

**SQL Injection:**

Look for string concatenation in database queries and unsafe query construction. For more information, see [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md).

**Cross-Site Scripting (XSS):**

Review output encoding, DOM manipulation, and user input rendering. For more information, see [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

**Path Traversal:**

Check for unsafe file path construction and directory traversal vulnerabilities. For more information, see [File Upload Cheat Sheet](File_Upload_Cheat_Sheet.md).

**Command Injection:**

Identify direct command execution with user input and unsafe system calls. For more information, see [OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md).

**NoSQL Injection:**

Examine NoSQL query construction and parameter binding. For more information, see [NoSQL Security Cheat Sheet](NoSQL_Security_Cheat_Sheet.md).

### Authentication & Session Management Vulnerabilities

Review authentication mechanisms, session token generation, and user credential handling. For more information, refer to [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) and [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md).

### Access Control Vulnerabilities

Examine authorization checks, role-based access controls, and privilege escalation prevention. For more information, see [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md).

### Deserialization Vulnerabilities

**Insecure Deserialization:**

Check for unsafe deserialization of untrusted data and object injection vulnerabilities. For more information, see [Deserialization Cheat Sheet](Deserialization_Cheat_Sheet.md).

**XML External Entity (XXE):**

Review XML parsing configurations and external entity processing. For more information, see [XML External Entity Prevention Cheat Sheet](XML_External_Entity_Prevention_Cheat_Sheet.md).

### Cryptographic Implementation Flaws

Examine encryption algorithms, key management, and cryptographic implementations. For more information, refer to [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md).

## Review Techniques

### Code Pattern Analysis

Focus on high-risk code patterns:

- Input processing and validation functions
- Database query construction and ORM usage
- File operations and path handling
- Authentication and session management logic
- Authorization and access control checks
- Cryptographic operations and key management
- Error handling and logging mechanisms
- Configuration loading and environment variables

### Data Flow Analysis

Trace data through the application:

1. **Identify Sources**: User inputs, file uploads, API calls, database reads, environment variables
2. **Follow Processing**: Validation, transformation, business logic, caching
3. **Check Sinks**: Database queries, file writes, output rendering, logging, external APIs
4. **Validate Boundaries**: Input validation and output encoding at trust boundaries
5. **Trust Zones**: Verify security controls at each trust boundary crossing
6. **Data Classification**: Ensure sensitive data receives appropriate protection

### Threat-Based Review

Align review with common attack patterns:

- **OWASP Top 10**: Focus on prevalent web application risks
- **STRIDE Model**: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation
- **Attack Trees**: Map potential attack paths through the application
- **Abuse Cases**: Consider how features could be misused by attackers
- **Security Controls**: Verify defense-in-depth implementation

### Business Logic Review

Analyze application workflows for:

- State management and transition validation
- Race conditions and concurrency issues
- Transaction integrity and rollback mechanisms
- Resource limits and quota enforcement
- Authorization at each workflow step
- Workflow bypass opportunities

## Review Checklists

### Input Validation

- [ ] **Server-side validation**: All inputs validated on server regardless of client-side checks
- [ ] **Allowlist validation**: Uses allowlists rather than blocklists for input validation
- [ ] **Output encoding**: Context-appropriate encoding (HTML, JavaScript, CSS, URL, SQL)
- [ ] **File upload security**: Content-based validation, size limits, safe storage
- [ ] **SQL injection prevention**: Parameterized queries or stored procedures used
- [ ] **Length limits**: Input length restrictions enforced
- [ ] **Character handling**: Special characters and Unicode properly processed
- [ ] **Error messages**: No sensitive information disclosed in error responses

### Authentication & Session Management

- [ ] **Password security**: Strong hashing algorithms and salt usage (for more information, see [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md))
- [ ] **Account protection**: Lockout mechanisms with appropriate thresholds
- [ ] **Session management**: Secure token generation (≥128 bits entropy)
- [ ] **Session lifecycle**: Proper invalidation on logout/timeout
- [ ] **Re-authentication**: Required for sensitive operations
- [ ] **Multi-factor authentication**: Implementation for high-risk accounts (for more information, see [Multifactor Authentication Cheat Sheet](Multifactor_Authentication_Cheat_Sheet.md))
- [ ] **Password reset**: Secure, time-limited reset mechanisms (for more information, see [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md))
- [ ] **Session security**: HttpOnly, Secure, SameSite cookie attributes
- [ ] **Concurrent sessions**: Appropriate limits and monitoring

### Authorization

- [ ] **Server-side enforcement**: All access controls enforced server-side
- [ ] **Fail-safe defaults**: Default deny access policy
- [ ] **IDOR prevention**: Proper authorization for resource access
- [ ] **Function-level controls**: Administrative functions properly protected
- [ ] **Role validation**: Role assignments cannot be manipulated
- [ ] **Privilege escalation**: Horizontal and vertical escalation prevented
- [ ] **Centralized decisions**: Access control logic centralized
- [ ] **Post-authentication checks**: Authorization verified after authentication

### Cryptography

- [ ] **Strong algorithms**: Modern algorithms (AES-256, RSA-2048+, ECDSA P-256+)
- [ ] **Key management**: Proper key generation, storage, and rotation (for more information, see [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md))
- [ ] **Certificate validation**: Proper validation including hostname verification
- [ ] **Random generation**: Cryptographically secure random number generation
- [ ] **Data protection**: Encryption at rest and in transit
- [ ] **IV/Nonce handling**: Unique and unpredictable initialization vectors
- [ ] **Library maintenance**: Up-to-date cryptographic libraries
- [ ] **Side-channel protection**: Consideration of timing and other side-channel attacks

### Business Logic

- [ ] **Workflow integrity**: Proper state validation in multi-step processes
- [ ] **Race condition prevention**: Synchronization in concurrent operations
- [ ] **Transaction atomicity**: Proper rollback and consistency mechanisms
- [ ] **Resource limits**: Rate limiting and resource quotas implemented
- [ ] **Business rule enforcement**: Cannot bypass rules through direct API access

### Configuration & Deployment

- [ ] **Secure defaults**: Security-focused default configurations
- [ ] **Environment separation**: Proper isolation between environments
- [ ] **Secrets management**: No hardcoded secrets, proper secret storage and rotation (for more information, see [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md))
- [ ] **Error handling**: Graceful error handling without information disclosure (for more information, see [Error Handling Cheat Sheet](Error_Handling_Cheat_Sheet.md))
- [ ] **Logging security**: Sensitive data not logged, proper log protection (for more information, see [Logging Cheat Sheet](Logging_Cheat_Sheet.md))
- [ ] **Security headers**: Appropriate HTTP security headers configured (for more information, see [HTTP Headers Cheat Sheet](HTTP_Headers_Cheat_Sheet.md))
- [ ] **TLS configuration**: Strong cipher suites and protocol versions (for more information, see [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md))
- [ ] **Dependency management**: Up-to-date libraries without known vulnerabilities (for more information, see [Vulnerable Dependency Management Cheat Sheet](Vulnerable_Dependency_Management_Cheat_Sheet.md))

### Security Monitoring

- [ ] **Security events**: Authentication failures, authorization violations logged
- [ ] **Anomaly detection**: Unusual patterns and behaviors monitored
- [ ] **Audit trails**: Complete audit logs for sensitive operations
- [ ] **Real-time alerts**: Critical security events trigger immediate notifications
- [ ] **Log integrity**: Logs protected from tampering and unauthorized access
- [ ] **Incident response**: Clear procedures for security incident handling

## Tools and Techniques

### Code Editors

Use editors with security extensions:

- Visual Studio Code with ESLint, SonarLint
- IntelliJ IDEA with SpotBugs, SonarLint
- Eclipse with security plugins
- Vim/Neovim with security linters

### Command-Line Pattern Detection

```bash
# Find hardcoded secrets
grep -ri "password\s*=\|api_key\s*=\|secret\s*=" source/

# Find unsafe functions
grep -r "eval(\|exec(\|innerHTML\|document\.write" source/

# Find potential injections
grep -r "SELECT.*+\|executeQuery.*+" source/
```

### Automated Security Testing Integration

**SAST Tools Integration:**

- **SonarQube**: Integrate security rules into CI/CD pipeline
- **Checkmarx**: Static analysis for comprehensive vulnerability detection
- **Veracode**: Cloud-based static analysis platform
- **Semgrep**: Lightweight static analysis with custom rules

**Security Metrics:**

- **Vulnerability Density**: Number of vulnerabilities per lines of code
- **Fix Rate**: Time to remediate identified security issues
- **Coverage**: Percentage of code reviewed for security
- **Trend Analysis**: Security posture improvement over time

### Documentation Templates

**Finding Report Template:**

```text
Title: [Vulnerability Type] in [Component]
Severity: [Critical/High/Medium/Low]
CWE: [CWE Number and Name]
Location: [File:Line or Function]
Description: [Detailed explanation of the vulnerability]
Impact: [Security implications and potential attack scenarios]
Reproduction: [Steps to reproduce or proof of concept]
Recommendation: [Specific fix guidance with code examples]
References: [CWE links, OWASP references, vendor documentation]
Status: [Open/In Progress/Fixed/Accepted Risk]
Assignee: [Developer responsible for fix]
Due Date: [Target fix date]
```

**Review Summary Template:**

```text
Review Summary
==============
Application: [Application Name]
Version: [Version/Commit Hash]
Reviewer(s): [Names]
Review Date: [Date]
Scope: [Files/Components Reviewed]

Findings Summary:
- Critical: [Count]
- High: [Count] 
- Medium: [Count]
- Low: [Count]
- Informational: [Count]

Key Recommendations:
1. [Priority recommendation]
2. [Priority recommendation]
3. [Priority recommendation]

Overall Risk Assessment: [Low/Medium/High/Critical]
```

## Integration with SDLC

### Review Timing

Integrate reviews at key points:

- **Pre-commit**: Focus on changed code and new features
- **Pull requests**: Security-focused code review as part of PR process
- **Sprint completion**: Comprehensive review of completed features
- **Prerelease**: Security assessment before deployment
- **Post-incident**: Targeted review after security incidents

For CI/CD integration and automated security testing, for more information see [CI CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md).

### Team Collaboration

**Roles:**

- **Security reviewers**: Conduct analysis and provide guidance
- **Developers**: Implement fixes and follow secure coding practices
- **Security champions**: Bridge security and development teams

**Best Practices:**

- Use standardized checklists and templates
- Maintain a knowledge base of common issues
- Track metrics on review effectiveness
- Provide regular security training
- Integrate with existing development workflows

## Advanced Techniques

### Race Condition Analysis

Focus on Time-of-Check vs Time-of-Use (TOCTOU) vulnerabilities and ensure atomic operations.

### Business Logic Analysis

Analyze workflows for:

- State transitions and validation
- Opportunities to bypass steps or validation
- Proper validation at each workflow step
- Rollback mechanisms and cleanup on failures
- Behavior under concurrent access
- Boundary conditions and error scenarios

### Security Architecture Review

Review architecture patterns for consistent security enforcement and proper API security controls.

### Memory Safety

Review buffer management, integer overflow protection, and resource limits.

## References

**OWASP Resources:**

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

**Related OWASP Cheat Sheets:**

- [Threat Modeling Cheat Sheet](Threat_Modeling_Cheat_Sheet.md)
- [Abuse Case Cheat Sheet](Abuse_Case_Cheat_Sheet.md)
- [Attack Surface Analysis Cheat Sheet](Attack_Surface_Analysis_Cheat_Sheet.md)
- [Secure Product Design Cheat Sheet](Secure_Product_Design_Cheat_Sheet.md)
- [Mass Assignment Cheat Sheet](Mass_Assignment_Cheat_Sheet.md)
- [Insecure Direct Object Reference Prevention Cheat Sheet](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)
- [Cross-Site Request Forgery Prevention Cheat Sheet](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Server Side Request Forgery Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Unvalidated Redirects and Forwards Cheat Sheet](Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)
- [Denial of Service Cheat Sheet](Denial_of_Service_Cheat_Sheet.md)

**Industry Standards:**

- [CWE/SANS Top 25 Most Dangerous Software Errors](https://cwe.mitre.org/top25/)
- [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/Projects/ssdf)
- [ISO/IEC 27034 - Application Security](https://www.iso.org/standard/44378.html)

**Additional Resources:**

- [SANS Secure Coding Practices](https://www.sans.org/white-papers/2172/)
- [Microsoft Security Development Lifecycle (SDL)](https://www.microsoft.com/en-us/securityengineering/sdl/)
- [Google Security Code Review Guidelines](https://google.github.io/eng-practices/review/reviewer/security.html)
- [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode)
