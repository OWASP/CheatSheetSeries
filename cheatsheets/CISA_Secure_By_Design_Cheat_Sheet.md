---
layout: col-sidebar
title: CISA Secure by Design Cheat Sheet
tags: CISA, Secure-by-Design, Development, Principles
level: 2
type: cheatsheet
pitch: Practical guidance for implementing CISA's Secure by Design principles in software development.
---

## Introduction

This cheat sheet provides practical guidance for implementing the [CISA Secure by Design](https://www.cisa.gov/securebydesign) principles in software development. These principles encourage software manufacturers to prioritize security throughout the product lifecycle rather than treating it as an add-on or customer responsibility.

## Core Principles

### 1. Take Ownership of Customer Security Outcomes

**Principle**: Software manufacturers should take ownership of security outcomes for their customers, rather than treating security as an optional feature or the customer's responsibility.

**Implementation Guidance**:

- **Security as Default**: Enable security features by default, don't make customers configure them
- **Transparent Security**: Clearly document security features and their status
- **Accountability**: Take responsibility when security issues occur in your products
- **Customer Education**: Provide clear guidance on secure deployment and configuration

### 2. Embrace Radical Transparency and Accountability

**Principle**: Be transparent about security practices, vulnerabilities, and incidents. Hold the organization accountable for security outcomes.

**Implementation Guidance**:

- **Vulnerability Disclosure**: Establish clear processes for vulnerability reporting and disclosure
- **Incident Transparency**: Communicate security incidents openly with customers
- **Metrics Publishing**: Share security metrics and improvement progress
- **Third-party Audits**: Welcome and publish results of independent security assessments

### 3. Build Organizational Structure and Leadership

**Principle**: Establish organizational structures and leadership that prioritize security throughout the product lifecycle.

**Implementation Guidance**:

- **Security Champions**: Appoint security champions in development teams
- **Executive Ownership**: Ensure C-level executives own security outcomes
- **Cross-functional Teams**: Create teams with both development and security expertise
- **Security Training**: Provide ongoing security education for all developers

### 4. Secure the Software Development Lifecycle (SDLC)

**Principle**: Integrate security practices throughout the entire software development process.

**Implementation Guidance**:

- **Threat Modeling**: Conduct threat modeling during design phase
- **Secure Coding Standards**: Establish and enforce secure coding guidelines
- **Automated Security Testing**: Integrate SAST, DAST, and SCA tools into CI/CD
- **Security Reviews**: Mandate security reviews for all major changes

### 5. Only Ship Products that are Secure by Default

**Principle**: Ensure products are secure in their default configuration without requiring customer intervention.

**Implementation Guidance**:

- **Default-Deny**: Implement principle of least privilege by default
- **Automatic Updates**: Enable automatic security updates by default
- **No Default Credentials**: Eliminate default passwords and credentials
- **Secure Configurations**: Pre-configure products with security-maximizing settings

### 6. Invest in Security Maintenance

**Principle**: Dedicate appropriate resources to maintaining product security throughout its lifecycle.

**Implementation Guidance**:

- **Patch Management**: Establish robust patch development and distribution processes
- **Vulnerability Management**: Maintain systems for tracking and addressing vulnerabilities
- **Long-term Support**: Provide security support for products throughout their lifecycle
- **Deprecation Planning**: Create clear plans for secure product end-of-life

### 7. Use Memory Safe Languages Where Possible

**Principle**: Prioritize memory-safe programming languages to eliminate entire classes of vulnerabilities.

**Implementation Guidance**:

- **Language Selection**: Choose memory-safe languages (Rust, Go, Java, C#, Python) for new projects
- **Legacy Code Mitigation**: Use security tools and practices for memory-unsafe languages
- **Training Investment**: Provide training on memory-safe language alternatives
- **Gradual Migration**: Plan migration paths for critical components to memory-safe languages

## Implementation Checklist

- [ ] Security features enabled by default
- [ ] Automatic security updates enabled
- [ ] No default credentials in shipped products
- [ ] Threat modeling integrated into design process
- [ ] Automated security testing in CI/CD pipeline
- [ ] Clear vulnerability disclosure process
- [ ] Executive ownership of security outcomes
- [ ] Memory-safe languages prioritized for new development
- [ ] Long-term security support commitment
- [ ] Transparent security communication practices

## Tools and Resources

- **CISA Secure by Design Alert**: [AA23-074A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-074a)
- **CISA Secure by Design Principles**: [Full PDF Guide](https://www.cisa.gov/sites/default/files/2023-04/secure_by_design_alert_4.19.23.pdf)
- **OWASP Secure Product Design Cheat Sheet**: [Link to related cheat sheet]
- **Memory Safety**: [CISA Memory Safety Roadmap](https://www.cisa.gov/resources-tools/resources/memory-safety-roadmap)

## References

1. [CISA Secure by Design](https://www.cisa.gov/securebydesign)
2. [CISA Secure by Design Alert AA23-074A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-074a)
3. [CISA Memory Safety Recommendations](https://www.cisa.gov/resources-tools/resources/memory-safety-roadmap)

## Contributors

- Prasad-JB
- OWASP Cheat Sheets Team
- CISA Cybersecurity Division
