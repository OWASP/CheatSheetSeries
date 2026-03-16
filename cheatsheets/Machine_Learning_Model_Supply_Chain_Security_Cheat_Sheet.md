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
