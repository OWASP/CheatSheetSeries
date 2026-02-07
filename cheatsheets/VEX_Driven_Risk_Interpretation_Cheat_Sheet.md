\# VEX-Driven Risk Interpretation for Safety-Critical SBOMs



\## Intent



This cheat sheet provides guidance on how existing VEX data can be interpreted to support risk-informed decision-making in safety-critical and regulated environments.



\## Scope



This guidance does not introduce new SBOM or VEX requirements. It focuses on using existing vulnerability and exploitability data to help organizations make consistent governance decisions.



\## Key Recommendations



\### Mapping CVSS / VEX Indicators to Safety-Relevant Risk Tiers



Use VEX status to determine whether vulnerabilities are exploitable in a given system context before prioritizing remediation.



\### Alignment with ISO/SAE 21434 and UNECE R155/156



Ensure SBOM vulnerability interpretation aligns with safety and regulatory risk management frameworks.



\### Lifecycle Handling (Review and Time-Bound Ownership)



All risk exceptions should be documented, reviewed periodically, and assigned clear ownership with expiration dates.



\## Example Use Case



An organization receives SBOM vulnerability data for a safety-critical system. VEX indicates that certain vulnerabilities are not exploitable in the deployed configuration. These are recorded as accepted risks, while exploitable issues affecting safety functions are prioritized.



\## References



\- SPDX

\- CSAF / VEX

\- ISO/SAE 21434

\- UNECE R155/156



