# Secure Product Design Cheat Sheet

## Introduction
**Version:** 2025-09  
**Purpose:** Provide concise, actionable guidance for designing secure products in line with [CISA Secure by Design principles](https://www.cisa.gov/resources-tools/resources/shifting-balance-cybersecurity-risk-principles-and-approaches-secure).  
**Scope:** Focused strictly on secure design; does **not** cover full SDLC or development processes.

---

## CISA Secure by Design Principles

### 1. Secure by Default
- Enable secure settings and configurations out-of-the-box.  
- Disable unnecessary features, services, and ports.  
- Enforce secure permissions automatically.

### 2. Minimize Attack Surface
- Limit exposed endpoints, APIs, and functionality.  
- Apply **least privilege** to all users and system components.  
- Reduce unnecessary network access and integrations.

### 3. Fail Securely
- Default to the safest state during errors or failures.  
- Avoid leaking sensitive information in logs, error messages, or exceptions.  
- Implement robust error handling.

### 4. Transparency and Observability
- Enable secure logging of key events.  
- Ensure actions and decisions are auditable and traceable.  
- Provide visibility for security monitoring and incident response.

### 5. Resilience and Recovery
- Design systems to continue functioning under attack or failure.  
- Include backups, redundancy, and safe state restoration.  
- Test recovery and failover procedures regularly.

### 6. Security Leadership and Culture
- Promote security awareness and training.  
- Ensure leadership actively supports secure design practices.  
- Encourage proactive risk identification and reporting.

### 7. Continuous Improvement
- Regularly review and update security controls and policies.  
- Learn from incidents, audits, and threat intelligence.  
- Integrate lessons into design and operational practices.

---

## Practical Guidance

### Context
- Identify the product’s role in the organization and types of data handled.  
- Assess risk based on usage, exposure, and sensitivity.  
- Avoid over- or under-engineering security.

### Components
- Review libraries, dependencies, and external services for security risks.  
- Prefer components with strong security track records and maintenance.  
- Ensure proper licensing and usage restrictions.

### Connections
- Map data flows and system interactions.  
- Limit connections to what is strictly necessary.  
- Segregate environments and data based on security needs.

### Code
- Validate input: type, format, length, and range.  
- Handle errors securely; avoid leaking information.  
- Implement strong authentication and authorization.  
- Encrypt sensitive data at rest and in transit.  
- Apply **least privilege** to code and system access.  
- Avoid hardcoded secrets; store credentials securely.  
- Conduct regular code reviews and automated security testing.  
- Keep dependencies up-to-date with security patches.

### Configuration
- Apply secure default settings for systems and software.  
- Limit access and permissions based on least privilege.  
- Use secure communication protocols (e.g., HTTPS/TLS).  
- Update software, OS, and dependencies regularly.  

---

## References
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)  
- [CISA Secure by Design Principles](https://www.cisa.gov/resources-tools/resources/shifting-balance-cybersecurity-risk-principles-and-approaches-secure)  
- [Threat Modeling Cheat Sheet](Threat_Modeling_Cheat_Sheet.md)  
- [Abuse Case Cheat Sheet](Abuse_Case_Cheat_Sheet.md)  
