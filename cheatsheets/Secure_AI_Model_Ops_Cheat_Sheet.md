# Secure AI/ML Model Ops Cheat Sheet

## Introduction

This cheat sheet provides practical security guidance for operating and deploying AI/ML systems—including traditional machine learning models and large language models (LLMs).
It helps MLOps, DevOps, and security teams protect the model lifecycle from development to production, covering threats like data poisoning, adversarial input, model theft, and operational abuse.

## Common Security Issues

Data Poisoning – A threat where attackers inject malicious data into training datasets to manipulate model behavior.

Model Inversion & Extraction – Techniques that allow attackers to reconstruct training data or extract model parameters via inference queries.

Adversarial Examples – Slightly modified inputs crafted to mislead model predictions without obvious changes to human observers.

Prompt Injection – A manipulation technique that breaks LLM outputs by injecting malicious input to override or hijack intended behavior.

Unsecured APIs – Publicly exposed inference endpoints lacking authentication, rate limiting, or input validation.

Hardcoded Secrets – The inclusion of sensitive credentials (e.g., API keys, tokens) in source code or notebooks.

Unvalidated Third-party Models – Use of external pre-trained models without verifying integrity, provenance, or trustworthiness.

Open Artifact Stores – Public access to model binaries, datasets, or logs due to misconfigured storage or missing access controls.

Lack of Monitoring & Drift Detection – Absence of systems to detect shifts in model behavior, data distribution, or performance.

Orphaned Deployments – Test or deprecated models left accessible in production environments, often unprotected.

## Real-World Examples

- Data Poisoning via Public Dataset Manipulation: Attackers inject mislabeled samples into open-source datasets. These poisoned samples, when used during training, degrade model accuracy or introduce bias.
- Model Inversion in Healthcare ML: An attacker infers whether a specific individual’s data was part of a medical model’s training dataset.
- Malicious Model Files: A `.pt` or `.pkl` file embedded with malware is uploaded to a pipeline and executed during deserialization.
- Insecure LLM Prompt Injection: Inputs like `"Ignore all previous instructions..."` manipulate chatbot behavior and may leak internal system prompts.
- Leaked API Keys on GitHub: OpenAI or Hugging Face API keys accidentally committed and exploited for free access or abuse.
- Open MLFlow Instance: No authentication on MLFlow or similar tool exposes all models and training logs.
- Adversarial Input Attacks in Vision Systems: Altering a few pixels causes an image classifier to mislabel a stop sign as a speed limit sign.
- Legacy Test Models in Production: Old staging models left running in public cloud endpoints, vulnerable to extraction.

## Security Recommendations

### 1. Model Development & Training

- Use version-controlled, auditable training pipelines (e.g., MLFlow, DVC).
- Validate and sanitize training data.
- Employ differential privacy or data anonymization if training on sensitive data.
- Train using reproducible environments (e.g., containers, virtualenv).

### 2. Secrets & Configurations

- Never hardcode secrets in source code or notebooks.
- Use secret managers (e.g., AWS Secrets Manager, HashiCorp Vault).
- Use environment variables or CI secrets injection.

### 3. Model Storage & Artifacts

- Store models in access-controlled registries.
- Sign model binaries with digital signatures.
- Ensure encryption at rest for model weights and datasets.
- Restrict access to training logs and intermediate outputs.

### 4. Inference API Security

- Apply authentication and authorization (OAuth, API tokens).
- Validate and sanitize all inputs.
- Use rate limiting and abuse detection (e.g. bot detection, anomaly scoring).
- Use structured prompt templates for LLMs to separate instructions from user input.

### 5. Deployment & Infrastructure

- Harden containers and limit capabilities (use distroless images, AppArmor).
- Use CI/CD pipelines that include security scanning.
- Minimize permissions for training and inference jobs (least privilege).
- Isolate environments for development, staging, and production.

### 6. Monitoring & Logging

- Monitor input distribution, output entropy, and latency.
- Detect drift via statistical analysis or shadow models.
- Log requests and access with traceability (avoid logging sensitive data).
- Alert on unusual usage patterns (e.g., scraping, injection attempts).

### 7. Adversarial Robustness

- Include adversarial examples in testing and evaluation.
- Use robust training techniques (e.g., adversarial training, input denoising).
- Monitor model confidence thresholds to identify out-of-distribution inputs.

### 8. Incident Response & Governance

- Define escalation procedures for model abuse or drift.
- Implement rollback mechanisms for model deployments.
- Map threats to OWASP ASVS or Proactive Controls for AI/ML.

## References

- [OWASP LLM Prompt Injection Cheat Sheet](LLM_Prompt_Injection_Prevention_Cheat_Sheet.md)  
- [OWASP ASVS / Proactive Controls](https://owasp.org/www-project-application-security-verification-standard/)  
- [OWASP AISVS](https://owasp.org/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/)
- [NIST AI Risk Management Framework (AI RMF)](https://www.nist.gov/itl/ai-risk-management-framework)  
- [Microsoft Responsible AI Guidelines](https://www.microsoft.com/en-us/ai/principles-and-approach)  
- [Google Threat Modeling](https://services.google.com/fh/files/misc/ds-threat-modeling-security-service-en.pdf)  
- [MITRE ATLAS Framework](https://atlas.mitre.org/)
