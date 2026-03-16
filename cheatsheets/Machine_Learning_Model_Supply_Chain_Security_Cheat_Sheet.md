# Machine Learning Model Supply Chain Security Cheat Sheet

## Introduction

Machine Learning (ML) models are frequently treated as static data, but in many common formats (like Python's Pickle), they are actually executable code. This "Model-as-Code" reality introduces significant supply chain risks, where malicious actors can embed "Pickle Bombs" or backdoors into pre-trained models.

## Primary Risks

### Unsafe Deserialization

Loading a model using standard Python libraries (like `torch.load` or `pickle.load`) can execute arbitrary code hidden within the model file. A hacker can trigger a reverse shell or data exfiltration the moment a developer "loads" a downloaded model.

### Model Poisoning and Backdoors

Attackers can subtly alter model weights so that the model performs normally on most data but triggers a specific, malicious behavior when it sees a "trigger" input.

## Mitigation Strategies

### 1. Mandate Safe Serialization (Safetensors)

Whenever possible, transition from `.pkl` or `.pth` (Pickle-based) formats to the **Safetensors** format.

- **Why:** Safetensors is a "data-only" format. It contains no executable instructions, making it physically impossible to hide a script inside.

### 2. Pre-Ingestion Scanning

Treat every third-party model as "Untrusted Code."

- **Tooling:** Use specialized scanners like `modelscan` or `fickling` to inspect the internal instruction stack (opcodes) of a model for malicious triggers.
- **Environment:** Always perform scanning and initial testing in a network-isolated sandbox.

### 3. Provenance and Integrity

- **Hash Pinning:** Store and verify the SHA-256 hash of every model used in production.
- **Signed Registries:** Only pull models from registries that support cryptographic signing and identity verification.

## Code Examples

### Unsafe vs. Safe Loading

```python
# UNSAFE: Risk of arbitrary code execution
import torch
model = torch.load('malicious_model.pkl')

# SAFE: Only loads numeric tensors
from safetensors.torch import load_file
weights = load_file('safe_model.safetensors')
```


## Scope and Specific Controls

### Out of Scope: Prompt Injection
This cheat sheet focuses on **Model Supply Chain Security** (the integrity of the model artifact itself). **Prompt Injection**, jailbreaking, and direct LLM output manipulation are out of scope. For guidance on those topics, refer to the [OWASP Top 10 for LLM Applications].

### Model Format Conversion Attacks
The process of converting models between frameworks (e.g., PyTorch → ONNX → TensorRT) creates an attack surface.
- **Custom Operator Injection:** Formats like ONNX support custom operators that can be weaponized to execute arbitrary code during model initialization.
- **Guidance:** Use sandboxed environments for conversion and perform security scans on the model both **before** and **after** the format shift.

### Clean-Label Model Poisoning
In clean-label attacks, malicious samples are correctly labeled to evade human audit while strategically shifting the model's decision boundaries. This creates "triggers" where the model performs normally on most data but fails or misclassifies specific inputs chosen by the attacker.

### Weight-Level Integrity Verification
Standard file-level hashing at the time of download is a "point-in-time" check and is insufficient for long-term security.
- **Load-Time Verification:** Hashes must be verified every time the model is loaded from disk into memory to protect against "at-rest" tampering.
- **Tensor-Level Hashing:** For high-security models, implement integrity checks on individual serialized weight tensors.

### Model Bill of Materials (ML-BOM)
Aligning with **NIST SP 800-218 (SSDF)**, an ML-BOM provides a verifiable record of the model's supply chain.
- **Lineage Tracking:** Document the base model, fine-tuning datasets, and framework versions.
- **Digital Signatures:** Ensure the ML-BOM itself is cryptographically signed and linked to the model hash to prevent tampering.
- **Guidance:** Integrate ML-BOM generation into the CI/CD pipeline using standardized formats like CycloneDX or SPDX.
