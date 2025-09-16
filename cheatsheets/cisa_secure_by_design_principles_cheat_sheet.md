# CISA Secure by Design Principles Cheat Sheet

## Introduction

This cheat sheet summarizes the [Secure by Design](https://www.cisa.gov/securebydesign)
principles developed by the Cybersecurity and Infrastructure Security Agency (CISA) and its
partners. These principles encourage software manufacturers to shift the burden of security
from customers to the manufacturers themselves, by building security into the product lifecycle
from the ground up.

Adopting these principles leads to more resilient software, reduces the number of vulnerabilities
reaching customers, and makes products secure "out of the box."

## The 7 Principles

### 1. Take Ownership of Customer Security Outcomes

**What it means:** Software manufacturers should formally accept responsibility for the security
outcomes of their customers. This involves investing in robust security practices, transparently
publishing security data, and leading the response when things go wrong.

**Key Actions:**

-   Acknowledge that customer security is a core product feature, not an add-on.
-   Lead the response and remediation efforts when vulnerabilities are discovered in your products.
-   Publicly report on security metrics (e.g., CISA's [SBOM VEX](https://www.cisa.gov/sbom) adoption,
    prevalence of CVEs).

### 2. Embrace Radical Transparency and Accountability

**What it means:** Proactively and publicly sharing security information, roadmaps, and risks.
This builds trust and holds the organization accountable to its security goals.

**Key Actions:**

-   Publish Security Advisories and CVEs for all known vulnerabilities.
-   Create and maintain clear, accessible security documentation for customers.
-   Disclose software bill of materials (SBOM) and third-party dependency risks.

### 3. Build Organizational Structure and Leadership to Achieve Security Goals

**What it means:** Security must be a top-down priority, funded and supported by executive
leadership. The organizational structure must enable security goals, not hinder them.

**Key Actions:**

-   Elevate the Chief Information Security Officer (CISO) to a senior leadership position.
-   Allocate dedicated budget and resources for long-term security initiatives.
-   Integrate security teams early in the product development lifecycle (e.g., via "shift-left"
    practices).

### 4. Design Products with Secure Defaults

**What it means:** The most secure configuration should be the default configuration. Customers
should not be required to add security features or change settings to be secure.

**Key Actions:**

-   Eliminate default passwords and require them to be changed on first use.
-   Enable important security features (like MFA, encryption) by default.
-   Adopt a "zero-trust" architecture mindset for product design.

### 5. Implement Security Measures That Don't Rely on Customer Configuration

**What it means:** The most critical security protections should operate effectively without any
customer intervention. Security should be inherent to the product's operation.

**Key Actions:**

-   Provide automatic, non-disruptive security updates.
-   Build in protections against common threats (e.g., SQL injection, XSS) that work regardless of
    user settings.
-   Harden underlying infrastructure and services against attack.

### 6. Make Security a Core Business Requirement

**What it means:** Security is treated with the same importance as revenue, cost, and functionality.
It is a fundamental factor in all business decisions.

**Key Actions:**

-   Measure and report on the ROI of security investments.
-   Position strong security practices as a key market differentiator.
-   Tie executive and developer compensation to achieving security metrics.

### 7. Invest in Security Throughout the Product Lifecycle

**What it means:** Security is not a one-time event. It requires continuous investment from initial
design through end-of-life, including ongoing maintenance for legacy products.

**Key Actions:**

-   Integrate security testing (SAST, DAST, SCA) into CI/CD pipelines.
-   Plan for and invest in long-term maintenance and security support for released products.
-   Develop and practice incident response plans.

## Implementation Examples

### Secure by Default

-   **Before:** Product ships with admin/admin credentials
-   **After:** Product requires unique password setup during initial installation

### Transparency

-   **Before:** Security issues handled through private support channels
-   **After:** All vulnerabilities receive public CVEs and detailed advisories

### Ownership

-   **Before:** Customers must apply patches manually
-   **After:** Automatic security updates enabled by default with rollback options

## References

-   [CISA Secure by Design Homepage](https://www.cisa.gov/securebydesign)
-   [CISA Secure by Design Principles (PDF)](https://www.cisa.gov/sites/default/files/2023-04/secure_by_design_042023.pdf)
-   [Shifting the Balance of Cybersecurity Risk: Principles and Approaches for Security-by-Design and -Default](https://www.cisa.gov/news-events/alerts/2023/04/13/cisa-and-partners-release-secure-design-alert-urging-manufacturers-eliminate-default)

## Contributors

-   Prasad-JB
