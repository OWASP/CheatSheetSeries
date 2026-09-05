# AI-Powered Advertising Systems Security Cheat Sheet

## Introduction

Modern advertising platforms make AI-driven financial decisions on every ad request. This cheat sheet is a concise checklist of ad-tech-specific controls that stop the AI itself from becoming the attack surface, across every ad-serving mode (programmatic, search, retail media, CTV/OTT which stands for Connected TV and Over-The-Top streaming ads, DOOH or Digital-Out-of-Home screens, direct-sold, native, mobile mediation) and both classical machine learning (ML) and generative AI (including large language models or LLMs, and vision-language models or VLMs) on the live serving path.

Each section pairs the primary controls with a compact threat / defense / evidence / runtime-signal table so a reviewer can trace each threat to how it is stopped, verified, and monitored.

## 1. Gate AI Decisions on Consent

Running a personalization, targeting, ranking, LLM contextual review, or lookalike model is profiling under [GDPR Art. 4(4)](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_4). Gate on the model call, not the identifier write.

- Treat consent as an authorization check, not a model feature.
- Refuse the model call on child-directed traffic (`regs.coppa == 1` under [COPPA](https://www.law.cornell.edu/cfr/text/16/part-312); [California CPRA 1798.120(c)](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.120&lawCode=CIV); [DSA Art. 28](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_28)).
- Consent-scope the training corpus per [IAB Europe TCF](https://iabeurope.eu/transparency-consent-framework/). TC strings are personal data ([CJEU C-604/22](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604)).
- Honor real-time opt-outs at the feature-fetch step: [Sec-GPC](https://globalprivacycontrol.org/), `regs.gpp`, [ATT](https://developer.apple.com/documentation/apptrackingtransparency), [Android Ad ID reset](https://support.google.com/googleplay/answer/3405269).
- Invalidate downstream materializations (segments, lookalike scores, Key/Value (KV) caches used by LLM serving stacks, adapter warm-pools) on opt-out.
- Test for special-category inference from generic inputs ([GDPR Art. 9](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_9), [DSA Art. 26(3)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_26)).
- Route high-stakes categories (employment, housing, credit) through a stricter path per [EU AI Act Art. 6](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_6) plus [Annex III](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#anx_III) point 4(a).

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Model runs on a non-consented user | Consent gate bound to feature-fetch, before the model call | Integration test: non-consented request produces no model invocation | Model-invocation rate per consent state |
| Non-consented rows enter the training corpus | Consent-scope admission; reject unrecognized signals at ingest | Row-level audit sample carries a consent-reason code | Training-admission rate by consent-reason-code |
| Special-category inference from generic inputs | Score outputs for special-category correlation; gate on correlation | Disparate-impact audit on each refresh | Per-classifier output distribution vs. protected class |
| Withdrawn consent but model still runs | Bind check to feature-fetch; invalidate downstream materializations | Withdraw-and-replay regression | Opt-out cache miss/hit rate; stale-cache alert |

## 2. Protect the Corpus (Training and Retrieval)

Training data and Retrieval-Augmented Generation (RAG) indexes are written by adversarial participants at line rate.

- Sign dataset manifests and RAG chunks with an offline key using [OpenSSF Model Signing](https://openssf.org/projects/model-signing/) primitives (sigstore, DSSE, in-toto).
- Tag every training row and RAG chunk with a participant-provenance tag so scoped-rollback ("exclude every row from partner X during window Y") is answerable without re-hashing.
- Pin a fixed set of canonical policy chunks per restricted category (alcohol, gambling, health claims, political, financial services, minors). Every retrieval query in one of these categories must return a minimum number of those pinned chunks; if it does not, the retrieval failed (an attacker likely seeded paragraphs that pushed the guardrail anchors out of the top-k results) and the verdict falls back to the non-LLM rules baseline instead of trusting the LLM's answer.
- Default to MMR (Maximal Marginal Relevance) retrieval, not similarity top-k alone. [Hu et al. 2024, arXiv:2402.07179](https://arxiv.org/abs/2402.07179) show adversarial prefixes override "ignore irrelevant context" instructions.
- Quarantine outcome events past adjudication (fraud, refund, click-validity). Reconcile against post-hoc verdicts. Exclude rows flagged as SIVT (Sophisticated Invalid Traffic, per the [MRC Invalid Traffic Detection and Filtration Guidelines](https://mediaratingcouncil.org/standards-and-guidelines)) from the training corpus even if their event signature was valid at fire time.
- Trigger-scan every refreshed model per [NIST AI 100-2e2025 Section 2.3.3](https://csrc.nist.gov/pubs/ai/100/2/e2025/final). [Hubinger et al. 2024, arXiv:2401.05566](https://arxiv.org/abs/2401.05566) show safety-eval alone is not evidence of trust.
- Refuse to load any unsigned fine-tune adapter. Bind adapter signatures to [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) entries.
- Normalize participant-supplied text (Unicode NFC, strip zero-width, strip bidi-control) before classifier or retrieval indexing.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Corpus or RAG poisoning by adversarial participant | Signed manifests plus participant-provenance tag plus k-of-n anchor verification | Red-team unsigned reversal chunk against reviewer LLM | Chunk signature verdict per retrieval; anchor-missing alert |
| Fine-tune trigger backdoor persists through safety training | [OpenSSF Model Signing (OMS)](https://openssf.org/projects/model-signing/)-signed adapter plus [in-toto](https://in-toto.io/)-attested dataset; held-out trigger-corpus behavioral gate | Trigger-corpus block regression on promotion | Per-adapter promotion-gate block rate |
| Embedding-cluster drown-out via seeded near-neighbor chunks | MMR retrieval; anchor-missing alert; non-LLM rules cross-check | Seed-chunk red-team; assert MMR restores anchors | Top-k anchor-missing rate per cluster |
| Unadjudicated Sophisticated Invalid Traffic (SIVT) events enter training | Quarantine past adjudication window; exclude rows reversed by post-hoc SIVT verdict | Admit-then-reverse regression test on a beacon later SIVT-reversed | Admission lag vs. adjudication lag per mode |

## 3. Protect Inference and the Prompt Boundary

Every scoring surface exposed to a paying partner is a queryable oracle ([Tramèr et al. 2016](https://arxiv.org/abs/1609.02943)).

- Return tier labels, not raw scores, on partner-visible outputs. Money fields required by the protocol (OpenRTB `seatbid.bid.price`, search ad-rank, retail sponsored-rank) must stay precise; guard those with query budgets and probing detection.
- Enforce contractual query budgets technically. Reject-not-coerce out-of-domain feature values.
- Cap inference cost per call, budgeted in dollars per minute ([OWASP LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)).
- Dual-LLM structural handoff on every attacker-controlled text input (publisher HTML, landing page, brief field). A quarantined LLM emits a fixed JSON schema; a privileged LLM reads only the schema. This is the ad-tech-specific relocation of [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) ([MITRE ATLAS AML.T0051](https://atlas.mitre.org/), indirect variant `AML.T0051.001`).
- Cross-check every monetization-changing boolean verdict against a non-LLM rules baseline.
- Ensemble two differently-trained VLMs on submitted images. [Qi et al. 2023](https://arxiv.org/abs/2306.13213) show one adversarial patch can jailbreak an aligned model.
- Run voice-clone detector plus AI-content detector as two gates on submitted audio. Require voice-usage authorization on file.
- On-device LLMs ([Chrome Prompt API](https://developer.chrome.com/docs/ai/prompt-api)) are origin-scoped, not iframe-scoped. Every model output is untrusted at the DOM boundary; [CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) does not inherit into a cross-origin ad iframe.
- Isolate every cache off tenant ID: KV cache (paged-attention serving stacks), RAG index namespace, plan cache, adapter pool ([OWASP LLM02:2025](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)). System-prompt secrecy is not a boundary ([LLM07:2025](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)); enforce thresholds in a deterministic post-processor keyed off the LLM's structured output.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Model extraction by paying partner | Query budgets; tier labels not raw scores on non-money fields; probing-pattern detection | Extraction red-team on shadow model | Per-partner query volume vs. contract rate; score-vs-outcome divergence |
| Prompt injection at publisher HTML, advertiser landing page, or brief field | Dual-LLM handoff plus non-LLM rules cross-check plus payload-class strip | Red-team page corpus with hidden brand-safe-steer payloads | Per-publisher quarantined-vs-baseline disagreement rate |
| Adversarial patch flips VLM policy verdict | Two-VLM ensemble; disagreement-to-HITL on celebrity, trademark, minor-audience tags | Adversarial-patch red-team on held-out corpus | Per-reviewer-version disagreement rate |
| Cross-tenant cache leak (KV, RAG, plan, adapter) | Per-tenant isolation keyed off tenant ID; session-scoped data-access credential | Cross-tenant probe red-team on deployed backend | Cross-tenant cache-hit alarm; identifier Data Loss Prevention (DLP) alerts on model output |
| Denial-of-wallet on paid contextual LLM | Per-partner cost budget in dollars per minute; token caps; tool-loop depth cap | Sponge-input red-team | Per-partner `cost_per_bid` SLO; P99 latency outlier |

## 4. Protect Outcome Events and Agentic Actions

Every outcome callback is money and a training label in one packet.

- Sign every callback with the ad-tech-specific field set: `key_id`, `event_type`, event ID, `timestamp`, monetary value, receiving endpoint. `event_type` must be inside the signed set because the same `impression_id` reuses across event types.
- Use HMAC-SHA256 over length-prefixed serialization, or [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/) with receiver-enforced required-minimum covered-components (Section 3.2.1, Section 7.2.1).
- Dedup on event ID alone within a TTL window; never on `(event_id, timestamp)`.
- Verify HMAC before any payload field influences a control-flow decision.
- Separate financial settlement from training-label materialization.
- Pin the certificate identity to a specific `partner_id`, using the Subject Alternative Name (SAN), Common Name (CN), or Subject Public Key Info (SPKI) hash, not just a trusted issuer. See the [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) for generic JWT hardening.
- Auth incidents are data incidents: rotate credentials, mark exposure-window rows suspect, invalidate per-partner weights, invalidate model artifacts.
- Tier every agentic tool by risk. HITL (human-in-the-loop) approvals bind a six-tuple: actor, tool, target, normalized parameters, timestamp, expiry ([OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)). Generic agentic patterns in the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
- Kill-switch fallback: a warm, pre-deployed rules-based bidder that a single control-plane flip diverts traffic to.
- Quarantine reward events past the fraud-adjudication lag; cap the maximum policy shift per epoch.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Forged outcome event = payment fraud AND poisoned label | Sign every callback with ad-tech-specific field set (`key_id`, `event_type`, event ID, timestamp, value, endpoint); verify HMAC first | CI negative tests: forged, stale, cross-endpoint rejected | Rejected-callback rate per partner |
| `impression_id` re-signed with fresh timestamps to over-credit | Dedup on event ID alone within a TTL window, not on `(event_id, timestamp)` | Re-sign regression test on the same `impression_id` | Per-partner dedup-hit rate |
| Injected-agent budget drain ([OWASP LLM06:2025](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)) | CRITICAL-tier HITL plus [WebAuthn](https://www.w3.org/TR/webauthn-3/) on `campaign.update_budget`; six-tuple binding; policy-service cap outside the prompt | Red-team injection targeting the budget tool | Per-tenant tool-call rate SLO; missing-approval alarm |
| Partner-credential compromise silently poisons rows | Auth-incidents-are-data-incidents runbook: rotate, mark exposure-window rows suspect, invalidate weights and artifacts | Rotation drill; confirm all three data-side actions fire | Per-partner-scoped model-drift monitor after rotation |

## 5. Protect the AI Supply Chain and Generative Provenance

Model artifacts, feature stores, RAG indexes, and generative endpoints are reachable through paths that never cross the ad-serving surface.

- Sign every model artifact with [OpenSSF Model Signing](https://openssf.org/projects/model-signing/). Block deploy on signature failure. Pair signing with a trigger-scan behavioral gate for externally sourced classifiers.
- Bind [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) entries to the participant-provenance tag from Section 2. The ML-BOM is the primary key for the scoped-rollback query.
- Purpose-scope feature-store namespaces. Rotate materialization-write credentials on the production-secrets cadence.
- Verify participant provenance per mode: [ads.txt](https://iabtechlab.com/ads-txt/) and OpenRTB [SupplyChain object](https://github.com/InteractiveAdvertisingBureau/openrtb/blob/main/supplychainobject.md) (programmatic); seller-ID authorization on catalog uploads (retail); advertiser-domain ownership (search); [ads.cert 2.0](https://iabtechlab.com/ads-cert/) or device attestation via [Google Play Integrity](https://developer.android.com/google/play/integrity) or [Apple App Attest](https://developer.apple.com/documentation/devicecheck/dcappattestservice) (CTV).
- Reject VPAID creatives outright in video-programmatic and CTV. VPAID (Video Player-Ad Interface Definition) was a [VAST](https://iabtechlab.com/standards/vast/) extension that let a video ad ship its own JavaScript to run inside the player. Deprecated in VAST 4.1 and replaced by [SIMID](https://iabtechlab.com/simid/) (Secure Interactive Media Interface Definition) in VAST 4.2. Sandboxing VPAID is not viable.
- A platform running its own generative endpoint is a *provider* under [EU AI Act Art. 50(2)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_50). The advertiser-as-brief-author is the *deployer* under Art. 50(4) whenever the creative constitutes a deep fake under [Art. 3(60)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_3).
- Emit the [C2PA 2.1](https://spec.c2pa.org/specifications/specifications/2.1/index.html) manifest with a hard binding over the generator output bytes at egress. Re-sign per rendition (image resize, video Adaptive-Bit-Rate (ABR) ladder step, audio Server-Side Ad-Insertion (SSAI) stitch). Do not rely on soft binding.
- Require a likeness or voice-use authorization artifact on file before the generator accepts a brief that asserts a real person.
- Freeze the generation model version from the control plane during an incident.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Model-artifact tampering | OMS signing on every artifact; trigger-scan gate on externally sourced classifiers | CI signature test; trigger-scan report per model version | Failed-signature-verification alerts on deploy |
| Unauthorized supply-chain provenance (spoofing seller, gaming seller, unowned domain) | Per-mode provenance verification: [`ads.txt`](https://iabtechlab.com/ads-txt/) walk, catalog seller-ID auth, domain ownership, device attestation | Daily provenance-reconciliation report per mode | Per-participant verification failure rate; auto-quarantine above threshold |
| Legacy or unsafe creative format (VPAID JavaScript) | Reject VPAID outright at ingest; require [VAST](https://iabtechlab.com/standards/vast/) 4.2 with [SIMID](https://iabtechlab.com/simid/) for interactivity | Ingest test: VPAID tag rejected; homoglyph fuzz suite | VPAID-rejection dashboard; SIMID adoption metric |
| Missing [Art. 50(2)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_50) provider marking at generation | [C2PA](https://spec.c2pa.org/specifications/specifications/2.1/index.html) hard binding plus machine-readable AI-generated marking at generator egress; re-sign per rendition | Regression: every generator emit produces a signed manifest | Per-asset generator-egress manifest-signed metric |
| Deep-fake composition from legitimate advertiser assets (Art. 3(60)) | Likeness or voice authorization ID required at brief acceptance; per-tenant asset fingerprint registry | Red-team a recombining brief without authorization | Brief-rejected-no-likeness-auth counter |

## References

**Generic mechanics defer to:**

- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP RAG Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP Secure AI/ML Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

**Regulatory anchors:** [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) Art. 4(4), 9, 17; [DSA](https://eur-lex.europa.eu/eli/reg/2022/2065/oj) Art. 26, 28; [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) Art. 3(60), 6, 50; [COPPA](https://www.law.cornell.edu/cfr/text/16/part-312); [California CPRA](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.120&lawCode=CIV); [CJEU C-604/22](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604).

**Standards:** [RFC 9421](https://www.rfc-editor.org/info/rfc9421/) HTTP Message Signatures; [C2PA 2.1](https://spec.c2pa.org/specifications/specifications/2.1/index.html); [OpenSSF Model Signing](https://openssf.org/projects/model-signing/); [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/); [MITRE ATLAS](https://atlas.mitre.org/); [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final); [OpenRTB](https://github.com/InteractiveAdvertisingBureau/openrtb2.x); [VAST](https://iabtechlab.com/standards/vast/) and [SIMID](https://iabtechlab.com/simid/); [MRC IVT Guidelines](https://mediaratingcouncil.org/standards-and-guidelines).

**Adversarial ML anchors:** [Tramèr 2016](https://arxiv.org/abs/1609.02943) (extraction); [Shokri 2017](https://arxiv.org/abs/1610.05820) (membership inference); [Qi 2023](https://arxiv.org/abs/2306.13213) (visual jailbreaks); [Hubinger 2024](https://arxiv.org/abs/2401.05566) (sleeper agents); [Hu 2024](https://arxiv.org/abs/2402.07179) (GGPP retrieval steering).

**OWASP LLM Top 10 (2025):** [LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [LLM02](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), [LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/), [LLM10](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/).
