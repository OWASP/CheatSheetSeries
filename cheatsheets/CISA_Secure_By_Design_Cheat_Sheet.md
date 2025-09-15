# CISA Secure by Design Cheat Sheet

## Introduction

CISA’s *Secure by Design* initiative defines seven principles that guide organizations toward building software with security as a core business requirement.  
This cheat sheet provides developers, architects, and security teams with practical, actionable steps to align with these principles.

---

## 1. Take Ownership of Customer Security Outcomes

- Ship products with **secure defaults** (e.g., MFA, encryption at rest & in transit).
- Provide clear documentation of security features and configurations.
- Deliver timely patches and updates; do not leave customers to defend themselves.

---

## 2. Embrace Radical Transparency and Accountability

- Publish **vulnerability advisories** openly with remediation timelines.
- Share **SBOMs (Software Bill of Materials)** with customers.
- Document secure configuration baselines.

---

## 3. Lead with Security as a Business Priority

- Make **security a core KPI**, not just a compliance checkbox.
- Integrate **threat modeling and security reviews** early in the design process.
- Ensure executive buy-in and accountability for security outcomes.

---

## 4. Understand and Address Harm Across the Product Lifecycle

- Identify and mitigate **misuse/abuse cases** during design.
- Provide secure **end-of-life and deprecation policies**.
- Consider the **human and societal impacts** of insecure defaults.

---

## 5. Ensure Default Secure Configurations

- Disable insecure or legacy options by default.
- Enforce **least privilege** and **role-based access control**.
- Ship products with **logging and monitoring enabled** by default.

---

## 6. Implement Security Controls at Scale

- Automate patching, vulnerability scanning, and CI/CD security checks.
- Use vetted, secure coding frameworks and libraries.
- Standardize secure configurations across environments.

---

## 7. Prioritize Security Investments for Maximum Impact

- Focus first on **exploitable, high-risk vulnerabilities**.
- Invest in developer education and secure coding training.
- Track and measure the ROI of security improvements.

---

## References

- [CISA Secure by Design Alert](https://www.cisa.gov/news-events/alerts/2023/04/13/shifting-balance-cybersecurity-risk-principles-secure-design)
- [CISA Secure by Design PDF](https://www.cisa.gov/sites/default/files/2023-04/principles_secure_by_design_secure_by_default_508c.pdf)
- [OWASP Secure Product Design Cheat Sheet](Secure_Product_Design_Cheat_Sheet.md)

---

