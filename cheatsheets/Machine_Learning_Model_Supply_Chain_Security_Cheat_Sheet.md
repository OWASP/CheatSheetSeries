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

This cheat sheet focuses on **Model Supply Chain Security** (the integrity of the model artifact itself). **Prompt Injection**, jailbreaking, and direct LLM output manipulation are out of scope. For guidance on those topics, refer to the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/).

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

### HuggingFace `from_pretrained()` RCE Risk

Many developers assume the `transformers` library is inherently safe. However, the `from_pretrained()` method reads a `config.json` file that can reference custom model classes.
- **The Attack:** If `trust_remote_code=True` is set, the library will download and execute arbitrary Python code (e.g., a `modeling_*.py` file) from the repository immediately upon loading.
- **Example:**

```python
# DANGEROUS: Executes arbitrary code from the remote repo
from transformers import AutoModel
model = AutoModel.from_pretrained("malicious-user/repo-name", trust_remote_code=True)
```

**Defensive Statement:** Never set `trust_remote_code=True` in production environments.

**Registry Controls:** Use Hugging Face's built-in malware scanning and "Pickle Scan" badges to verify model safety at the registry level before downloading.

### Mitigation: Use `weights_only=True`

Starting with PyTorch 2.6, `torch.load()` defaults to `weights_only=True`. This restricts unpickling to a safe subset of Python objects, preventing arbitrary code execution while still using the `.pth` format.

```python
# Safe loading in modern PyTorch
weights = torch.load("model.pth", weights_only=True)
```

### Security Note on Safetensors

While `safetensors` prevents code execution during weight loading, it does **not** solve the trust problem. A malicious repository can still bundle a safe `.safetensors` weight file with a malicious `config.json` that triggers code execution via the `trust_remote_code` flag. Always audit the repository files beyond just the weights.

## Security Scanning Tools

### 1. ModelScan (Protect AI)

Scans models for unsafe "opcodes" without executing them.

```bash
pip install modelscan
modelscan -p ./path_to_model/model.pkl
```

### 2. Fickling (Trail of Bits)

A static analysis tool that decompiles Python pickles to identify malicious intent safely.
Fickling is a specialized tool designed to analyze and "de-pickle" Python object streams to identify malicious opcodes. It can also be used to create "safe" versions of existing pickle files.
**Note:** Fickling is currently less actively maintained than ModelScan; prioritize ModelScan for up-to-date opcode coverage.

```bash
pip install fickling
fickling my_model.pth
```

## References

- [NIST SP 800-218A: AI-Specific Secure Software Development](https://doi.org/10.6028/NIST.SP.800-218A)
- [MITRE ATLAS Framework](https://atlas.mitre.org/)
- [OWASP AI Security Verification Standard (AISVS)](https://owasp.org/www-project-ai-security-verification-standard/)
- [Hugging Face Security Documentation](https://huggingface.co/docs/hub/security)
- [CycloneDX ML-BOM Specification](https://cyclonedx.org/capabilities/mlbom/)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [ModelScan GitHub Repository](https://github.com/protectai/modelscan)
