# AI Model Supply Chain Security Cheat Sheet

## Introduction

AI and machine learning models introduce unique supply chain risks that traditional software supply chain practices do not fully address. Models are distributed as serialized binary artifacts, often downloaded from public hubs, and may carry executable code, embedded credentials, or poisoned weights. This cheat sheet provides actionable guidance for securing the AI model supply chain—from acquisition and storage to deployment and ongoing verification.

This cheat sheet focuses specifically on model artifact security. For broader AI/ML operational security, see the [Secure AI/ML Model Ops Cheat Sheet](Secure_AI_Model_Ops_Cheat_Sheet.md). For general software supply chain guidance, see the [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md).

## Key Risks

- **Unsafe Deserialization**: Formats like Python's `pickle` (used in `.pt`, `.pkl`, `.joblib` files) execute arbitrary code on load. A model file can contain embedded malware that runs the moment it is deserialized.
- **Model Tampering**: Weights or architecture can be modified after publication to introduce backdoors, degrade performance on specific inputs, or exfiltrate data during inference.
- **Unverified Provenance**: Models downloaded from public hubs (Hugging Face, PyTorch Hub, TensorFlow Hub) may lack cryptographic signatures, making it impossible to verify the publisher or detect tampering.
- **Dependency Confusion**: Model files may depend on specific library versions. Attackers can publish malicious packages with matching names to intercept model loading pipelines.
- **Poisoned Pre-trained Weights**: Transfer learning amplifies supply chain risk—a backdoored base model propagates to every downstream fine-tune.
- **Leaked Secrets in Artifacts**: API keys, database credentials, or PII accidentally serialized into model checkpoints, tokenizer configs, or training metadata.

## Real-World Examples

- **Pickle-based Malware on Hugging Face (2024)**: Researchers discovered models on Hugging Face Hub containing pickle payloads that executed reverse shells on deserialization. The models appeared legitimate and had downloads before detection.
- **Backdoored NLP Models**: Academic research has demonstrated that language models can be fine-tuned to behave normally on standard benchmarks while containing hidden triggers that activate on specific input patterns.
- **PyTorch Dependency Attack (2022)**: The `torchtriton` package on PyPI was compromised via dependency confusion, affecting users who installed nightly builds of PyTorch.

## Security Recommendations

### 1. Use Safe Serialization Formats

The most critical defense against model supply chain attacks is avoiding unsafe serialization.

#### Avoid: Pickle-based formats

```python
# DANGEROUS: pickle executes arbitrary code on load
import torch
model = torch.load("model.pt")  # May execute embedded malware

import pickle
with open("model.pkl", "rb") as f:
    model = pickle.load(f)  # Same risk
```

#### Prefer: Safe serialization

```python
# SAFE: safetensors stores only tensor data, no executable code
from safetensors.torch import load_file, save_file

# Save
save_file(model.state_dict(), "model.safetensors")

# Load — no code execution possible
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

```python
# SAFE: ONNX stores computation graphs, not arbitrary code
import onnx
model = onnx.load("model.onnx")
onnx.checker.check_model(model)  # Validates structure
```

**Format comparison:**

| Format | Arbitrary Code Execution | Recommended |
|--------|--------------------------|-------------|
| `safetensors` | No | Yes |
| ONNX | No | Yes |
| `pickle` / `.pt` / `.pkl` | Yes | No |
| `joblib` | Yes | No |
| HDF5 (`.h5`) | Limited risk | Acceptable with validation |

When pickle-based formats are unavoidable (e.g., legacy models), load them in a sandboxed environment with restricted permissions and scan before use.

### 2. Verify Model Provenance

- **Check cryptographic signatures** before loading any model. Hugging Face supports commit signing—verify it.
- **Pin model revisions** to specific commit hashes, not branch names or tags that can be overwritten.

```python
# Pin to a specific revision hash, not "main"
from transformers import AutoModel

model = AutoModel.from_pretrained(
    "organization/model-name",
    revision="a1b2c3d4e5f6"  # Specific commit hash
)
```

- **Maintain an internal model registry** with hash verification for all approved models.
- **Document the chain of custody**: who trained it, on what data, when, and with which library versions.

### 3. Scan Model Artifacts Before Use

- **Run malware scans** on all model files before loading into any environment.
- **Use dedicated model scanning tools** such as [ModelScan](https://github.com/protectai/modelscan) to detect unsafe operations in serialized files.

```bash
# Scan a model file for unsafe operations
pip install modelscan
modelscan --path ./model.pt
```

- **Inspect pickle files** before loading when safe formats are not available:

```python
import pickletools
# Disassemble pickle to inspect operations (read-only, does not execute)
with open("model.pkl", "rb") as f:
    pickletools.dis(f)
```

- **Block known-dangerous pickle opcodes** (`GLOBAL`, `REDUCE`, `BUILD`) that enable code execution.

### 4. Secure Model Storage and Distribution

- Store model artifacts in access-controlled registries with audit logging.
- Encrypt model files at rest and in transit.
- Use checksums (SHA-256) to verify integrity after download.

```bash
# Generate checksum on publish
sha256sum model.safetensors > model.safetensors.sha256

# Verify checksum on download
sha256sum -c model.safetensors.sha256
```

- Restrict write access to model registries—separate roles for publishers and consumers.
- Set retention and expiration policies to prevent orphaned artifacts.
- Never store API keys, credentials, or PII in model checkpoints or config files.

### 5. Secure the Training Pipeline

- **Lock dependency versions** in training environments using pinned requirements files or lock files.
- **Use private package indexes** for internal dependencies to prevent dependency confusion.
- **Verify training data provenance** and integrity with checksums.
- **Reproduce training** from source when possible rather than trusting pre-trained weights.
- **Audit training code** for unintended data leakage into model artifacts (e.g., file paths, environment variables serialized in checkpoint metadata).

### 6. Monitor Deployed Models

- Track model lineage: which base model, training data version, and code version produced each deployment.
- Alert on unexpected model file changes in production (file hash monitoring).
- Maintain a model bill of materials (MBOM) listing all components: base model, fine-tuning data, dependencies, and training infrastructure.
- Periodically re-scan deployed models against updated vulnerability databases.

## References

- [Hugging Face Safetensors](https://huggingface.co/docs/safetensors/)
- [ProtectAI ModelScan](https://github.com/protectai/modelscan)
- [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [NIST AI 100-2e2025 — Adversarial Machine Learning](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [Secure AI/ML Model Ops Cheat Sheet](Secure_AI_Model_Ops_Cheat_Sheet.md)
- [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md)
