# Security Dashboards and Prioritization Cheat Sheet

## Introduction

Organizations collect security findings effectively through various scanning tools (SAST, DAST, SCA, penetration testing), but often struggle to convert them into clear, prioritized, and accountable remediation workflows. This cheat sheet provides actionable guidance on how to report, prioritize, and communicate security findings using repeatable patterns.

The goal is to help teams move from **finding generation → triage → prioritization → remediation** with transparency and accountability.

## Audience-Specific Dashboard Design

Different stakeholders need different views of security data. Designing dashboards for specific audiences prevents information overload and ensures actionable insights.

### Executive Dashboard

Executives need high-level visibility into organizational risk posture without technical details.

| Element | Purpose |
|---------|---------|
| Top 5-10 Critical Risks | Business-impact focused view of highest priority issues |
| Ownership Summary | Who is accountable for remediation |
| SLA Breach Count | How many findings exceed remediation deadlines |
| Risk Trend (30/60/90 days) | Is risk increasing or decreasing over time |
| Business Unit Comparison | Risk distribution across teams/products |

### Program/Engineering Dashboard

Engineering teams need detailed, actionable information to drive remediation.

| Element | Purpose |
|---------|---------|
| Finding Queue by Severity | Prioritized list of work |
| Age Distribution | How long findings have been open |
| Triage State Summary | New, In Progress, Blocked, Closed |
| Asset Context | Affected systems, services, repositories |
| Fix Guidance | Remediation instructions and references |
| Burndown Chart | Progress toward risk reduction goals |

## Data Unification Guidelines

When aggregating findings from multiple sources, apply consistent normalization.

### Severity Mapping

Map tool-specific severities to a common taxonomy:

| Common Severity | CVSS Score | Typical SLA |
|-----------------|------------|-------------|
| Critical | 9.0 - 10.0 | 7 days |
| High | 7.0 - 8.9 | 30 days |
| Medium | 4.0 - 6.9 | 90 days |
| Low | 0.1 - 3.9 | 180 days |

### Deduplication Strategies

- **Same vulnerability, same location**: Merge into single finding
- **Same vulnerability, different locations**: Group under parent issue
- **Different scanners, same finding**: Cross-reference and deduplicate
- **Refresh cadence**: Define how often each data source updates (daily, weekly)

## Prioritization Framework

Not all findings are equal. Prioritize based on multiple factors:

### Risk Scoring Formula

```
Priority Score = Severity × Exploitability × Asset Criticality × Exposure
```

| Factor | Weight | Description |
|--------|--------|-------------|
| Severity | Base score | CVSS or equivalent |
| Exploitability | 1.0 - 2.0 | Known exploit in the wild? |
| Asset Criticality | 0.5 - 2.0 | Customer-facing? Contains sensitive data? |
| Exposure | 0.5 - 1.5 | Internet-facing vs internal only |

### SLA Definitions

Define clear remediation timelines and communicate them organization-wide:

- **Critical**: Must remediate within 7 days
- **High**: Must remediate within 30 days
- **Medium**: Must remediate within 90 days
- **Low**: Must remediate within 180 days or accept risk

## Governance and Accountability

### Ownership Assignment

Every finding must have an owner. Use these patterns:

- **Service Owner**: Default owner based on affected asset
- **Security Champion**: Designated security contact per team
- **Escalation Path**: Manager → Director → CISO for SLA breaches

### Triage State Definitions

| State | Description |
|-------|-------------|
| New | Finding identified, not yet reviewed |
| Triaged | Reviewed, severity confirmed, owner assigned |
| In Progress | Remediation work started |
| Blocked | Cannot proceed (dependency, resource, etc.) |
| Mitigated | Fix deployed, awaiting verification |
| Closed | Verified fixed or accepted risk |

### Escalation Triggers

- Finding exceeds 50% of SLA with no progress
- Finding exceeds 100% of SLA (automatic escalation)
- Blocked findings with no resolution path after 7 days

## Success Metrics (KPIs)

Track these metrics to measure program effectiveness:

| Metric | Description | Target |
|--------|-------------|--------|
| Mean Time to Remediate (MTTR) | Average days from finding to closure | < SLA by severity |
| Risk Burndown | Reduction in open critical/high findings | 10% monthly reduction |
| Aged Critical Count | Critical findings exceeding SLA | 0 |
| Triage Velocity | Findings triaged per week | > new findings per week |
| False Positive Rate | Findings marked as not applicable | < 10% |

## References

- [NIST SP 800-30 - Risk Assessment](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [NIST SP 800-218 - Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [ISO/IEC 27005 - Information Security Risk Management](https://www.iso.org/standard/75281.html)
- [OWASP ASVS - Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP WSTG - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
