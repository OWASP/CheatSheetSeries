# AI Model Supply Chain Security Cheat Sheet

## Introduction

AI models introduce supply chain risks that traditional software practices do not address. Unlike source code or compiled binaries, models are distributed as serialized artifacts that may carry executable code, and their behavior cannot be fully determined through static inspection. This cheat sheet covers the security concerns unique to model artifacts — serialization risks, provenance verification, and model-specific integrity controls.

For broader AI/ML operational security (data poisoning, adversarial inputs, API security), see the [Secure AI/ML Model Ops Cheat Sheet](Secure_AI_Model_Ops_Cheat_Sheet.md). For general dependency and build pipeline guidance, see the [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md).

## Model-Specific Supply Chain Risks

These risks are distinct from traditional software supply chain threats because they arise from the nature of model artifacts themselves:

- **Unsafe Deserialization**: Formats like Python's `pickle` (used in `.pt`, `.pkl`, `.joblib` files) execute arbitrary code on load. A model file can contain embedded malware that runs the moment it is deserialized — this has no equivalent in traditional compiled software distribution.
- **Model Tampering Without Functional Change**: Unlike software binaries, model weights can be subtly modified to introduce backdoors that activate only on specific trigger inputs while passing all standard benchmarks and evaluations.
- **Poisoned Pre-trained Weights**: Transfer learning amplifies supply chain risk. A backdoored base model silently propagates to every downstream fine-tune, and the downstream developer has no reliable way to detect the compromise through normal evaluation.
- **Leaked Secrets in Artifacts**: Model checkpoints may accidentally serialize API keys, file paths, environment variables, or training data samples into metadata that persists through distribution.

## Real-World Examples

- **Pickle-based Malware on Hugging Face (2024)**: Models on Hugging Face Hub were found containing pickle payloads that executed reverse shells on deserialization. The models appeared legitimate and accumulated downloads before detection.
- **PyTorch `torchtriton` Dependency Confusion (2022)**: A malicious `torchtriton` package on PyPI exploited dependency confusion, compromising users who installed PyTorch nightly builds.
- **Backdoored NLP Models**: Academic research has demonstrated language models fine-tuned to behave normally on benchmarks while containing hidden triggers that activate on specific input patterns.

## Security Recommendations

### 1. Require Safe Serialization Formats

The most critical architectural decision for model supply chain security is prohibiting unsafe serialization formats at the organizational level.

| Format | Arbitrary Code Execution | Recommendation |
|--------|--------------------------|----------------|
| `safetensors` | No | Preferred — stores only tensor data |
| ONNX | No | Preferred — stores computation graphs only |
| `pickle` / `.pt` / `.pkl` | **Yes** | Prohibit in policy; sandbox if unavoidable |
| `joblib` | **Yes** | Prohibit in policy |
| HDF5 (`.h5`) | Limited risk | Acceptable with validation |

- Establish an organizational policy requiring safe formats (`safetensors`, ONNX) for all new model artifacts.
- When pickle-based formats are unavoidable (legacy models), load them only in sandboxed environments with restricted permissions and network isolation.
- Integrate format validation into CI/CD gates so unsafe formats are rejected before reaching model registries.

### 2. Verify Model Provenance

- **Pin model revisions to cryptographic commit hashes**, not branch names or tags that can be overwritten. This applies to models loaded from Hugging Face, PyTorch Hub, or any external source.
- **Verify cryptographic signatures** on model artifacts where supported (e.g., Hugging Face commit signing).
- **Maintain an internal model registry** that records approved models with their hashes, origin, and approval status. Treat this as the authoritative source — never load models directly from public hubs in production.
- **Document chain of custody**: who trained the model, on what data, when, with which framework and library versions.

### 3. Scan Model Artifacts Before Use

- **Integrate model-specific scanning tools** (e.g., [ModelScan](https://github.com/protectai/modelscan)) into CI/CD pipelines to detect unsafe operations in serialized files before they reach any runtime environment.
- **Block known-dangerous pickle opcodes** (`GLOBAL`, `REDUCE`, `BUILD`) that enable arbitrary code execution — these can be detected statically without executing the file.
- **Treat model files as untrusted input** with the same rigor applied to user-uploaded files: scan, validate, and isolate before processing.

### 4. Maintain a Model Bill of Materials (MBOM)

Traditional SBOMs do not capture model-specific lineage. Maintain an MBOM for each deployed model that includes:

- **Base model**: origin, version/commit hash, and whether it was pre-trained externally or in-house.
- **Fine-tuning data**: dataset identifiers, versions, and integrity checksums.
- **Training environment**: framework versions, hardware, and dependency snapshots.
- **Downstream lineage**: which production systems consume this model and which models were derived from it.

Use the MBOM to assess blast radius when a vulnerability is disclosed in a base model or training dependency.

### 5. Enforce Integrity Controls in Production

- **Monitor deployed model file hashes** and alert on unexpected changes — a modified model binary in production may indicate compromise.
- **Separate model publishing from model consumption** with distinct roles and access controls in your model registry.
- **Re-scan deployed models periodically** against updated vulnerability databases and scanning rules, since new attack patterns emerge continuously.

## References

- [Hugging Face Safetensors](https://huggingface.co/docs/safetensors/)
- [ProtectAI ModelScan](https://github.com/protectai/modelscan)
- [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [NIST AI 100-2e2025 — Adversarial Machine Learning](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [Secure AI/ML Model Ops Cheat Sheet](Secure_AI_Model_Ops_Cheat_Sheet.md)
- [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md)
