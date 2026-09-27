# AI-Powered Advertising Systems Security Cheat Sheet

## Introduction

Modern advertising platforms make AI-driven financial decisions on every ad request. This cheat sheet is a concise checklist of ad-tech-specific controls that stop the AI itself from becoming the attack surface. It applies across every ad-serving mode: programmatic served via the [IAB Tech Lab OpenRTB specification](https://github.com/InteractiveAdvertisingBureau/openrtb2.x), search, retail media, CTV/OTT (Connected TV and Over-The-Top streaming ads), DOOH (Digital-Out-of-Home screens), direct-sold, native, and mobile mediation. It covers both classical machine learning (ML) and generative AI on the live serving path, including large language models (LLMs) and vision-language models (VLMs); generic LLM risks are catalogued in the [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/).

Each section pairs the primary controls with a compact threat / evidence / runtime-signal table so a reviewer can trace each threat to how it is verified and monitored.

## 1. Gate AI Decisions on Consent

Running a personalization, targeting, ranking, or lookalike model on personal data is profiling under [GDPR Art. 4(4)](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_4). Contextual review that reads page content and no user data is outside that definition, so do not gate it on profiling consent. That exemption ends the moment its output is joined to a user identifier, so treat the join, not the review, as the point where consent attaches. Gate the identifier write and the model call separately. [ePrivacy Art. 5(3)](https://eur-lex.europa.eu/eli/dir/2002/58/oj) attaches consent to the storage or access itself, so the write needs consent even when no model runs, and the model call is the gate teams usually miss.

- Treat consent as an authorization check, not a model feature.
- Refuse the model call on child-directed traffic based on a classification the platform controls (publisher-side child-directed flag, age-of-majority signal, kids-account tag). OpenRTB `regs.coppa` is sender-declared under [OpenRTB 2.6 §3.2.3](https://github.com/InteractiveAdvertisingBureau/openrtb2.x/blob/main/2.6.md#objectregs) and fails open when omitted, so treat it as a signal that raises the bar rather than as the boundary. Where the platform-controlled classification is unavailable, fail closed and treat the traffic as child-directed. Regulatory anchors are [COPPA](https://www.law.cornell.edu/cfr/text/16/part-312), [California CPRA 1798.120(c)](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.120&lawCode=CIV), and [DSA Art. 28](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_28).
- Consent-scope the training corpus per [IAB Europe TCF](https://iabeurope.eu/transparency-consent-framework/). TC strings are personal data ([CJEU C-604/22](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604)).
- Honor real-time opt-outs at the feature-fetch step: [Sec-GPC](https://globalprivacycontrol.org/), `regs.gpp`, [ATT](https://developer.apple.com/documentation/apptrackingtransparency), [Android Ad ID reset](https://support.google.com/googleplay/answer/3405269).
- Invalidate downstream materializations (segments, lookalike scores, key-value (KV) caches used by LLM serving stacks, adapter warm-pools) on opt-out.
- Test for special-category inference from generic inputs ([GDPR Art. 9](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_9), [DSA Art. 26(3)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_26)).
- Route employment, housing, and credit ads through a stricter path. Targeted employment advertising is named as high-risk under [EU AI Act Art. 6](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_6) plus [Annex III](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#anx_III) point 4(a). Housing ad targeting is governed by the US [Fair Housing Act](https://www.hud.gov/program_offices/fair_housing_equal_opp/fair_housing_act_overview) and the [United States v. Meta Platforms 2022 settlement](https://www.justice.gov/archives/opa/pr/justice-department-secures-groundbreaking-settlement-agreement-meta-platforms-formerly-known) that retired the Special Ad Audience tool used for lookalike targeting on housing ads. Credit ad targeting is governed by the US [Equal Credit Opportunity Act (ECOA)](https://www.consumerfinance.gov/rules-policy/regulations/1002/). Annex III point 5(b) covers creditworthiness scoring, not ad targeting.

| Threat | Evidence | Runtime signal |
|---|---|---|
| Model runs on a non-consented user | Integration test: non-consented request produces no model invocation | Model-invocation rate per consent state |
| Non-consented rows enter the training corpus | Row-level audit sample carries a consent-reason code | Training-admission rate by consent-reason-code |
| Special-category inference from generic inputs | Disparate-impact audit on each refresh | Per-classifier output distribution vs. protected class |
| Withdrawn consent but model still runs | Withdraw-and-replay regression | Opt-out cache miss/hit rate; stale-cache alert |

## 2. Protect the Corpus (Training and Retrieval)

Training data and Retrieval-Augmented Generation (RAG) indexes are written by adversarial participants at line rate.

- Sign dataset manifests and RAG chunks with an offline key using the [in-toto attestation framework](https://github.com/in-toto/attestation) wrapped in a [DSSE envelope](https://github.com/secure-systems-lab/dsse), the same envelope shape [sigstore model-transparency](https://github.com/sigstore/model-transparency) uses for model artifacts.
- Tag every training row and RAG chunk with a participant-provenance tag so scoped-rollback ("exclude every row from partner X during window Y") is answerable without re-hashing.
- Pin a fixed set of canonical policy chunks per restricted category (alcohol, gambling, health claims, political, financial services, minors) as a retrieval-integrity check, not as the boundary. Every retrieval query in one of these categories must return at least k of n pinned anchor chunks (for example, k=3 of n=5, small enough to tolerate index churn, large enough that an attacker must displace a majority of anchors to succeed). The category classification that selects which anchor set to require is itself made from attacker-controlled text, so an attacker who steers classification upstream can skip the check entirely. When a query returns fewer than the required anchors, route to the non-LLM rules baseline instead of the LLM verdict, and treat that baseline as the actual last line of defense.
- Prefer diversity-sampled retrieval such as MMR (Maximal Marginal Relevance) over similarity top-k alone. This is defense-in-depth, not a boundary. [Hu et al. 2024, arXiv:2402.07179](https://arxiv.org/abs/2402.07179) do not evaluate MMR against adversarial prefixes, and their finding that prefixes override "ignore irrelevant context" instructions means the retrieval-layer defense cannot be relied on alone. Combine with the pinned-anchor check above and the non-LLM rules baseline.
- Quarantine outcome events for an adjudication window (24 to 72 hours in common practice, spanning basic post-impression verdicts to click-validity reconciliation), consistent with the adjudication-lag concept in the [MRC Invalid Traffic Detection and Filtration Guidelines](https://mediaratingcouncil.org/standards-and-guidelines). Reconcile against post-hoc verdicts. Exclude rows flagged as SIVT (Sophisticated Invalid Traffic) from the training corpus even if their event signature was valid at fire time.
- Trigger-scan every refreshed model as defense-in-depth, not as the boundary. [NIST AI 100-2e2025 §2.3.3](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) documents that spectral signatures and activation clustering are ineffective against clean-label backdoors, and that semantic or functional triggers pose challenges to trigger-reconstruction and model-inspection approaches which assume fixed patterns. [Hubinger et al. 2024, arXiv:2401.05566](https://arxiv.org/abs/2401.05566) show safety training does not remove them. Provenance (signed weights, known training data, reproducible builds) bounds who can ship a model and keeps rollback scoped, but it does not verify what was trained, because an authorized supplier can sign a backdoored artifact and every signature check still passes. Gate promotion on a held-out trigger corpus built from your own policy taxonomy, and hold blast radius down with staged rollout and per-supplier champion/challenger on a clean holdout.
- Refuse to load any unsigned fine-tune adapter. Bind adapter signatures to [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) entries.
- Normalize participant-supplied text (Unicode NFC, strip zero-width, strip bidi-control) before classifier or retrieval indexing.

| Threat | Evidence | Runtime signal |
|---|---|---|
| Corpus or RAG poisoning by adversarial participant | Red-team unsigned reversal chunk against reviewer LLM | Chunk signature verdict per retrieval; anchor-missing alert |
| Fine-tune trigger backdoor persists through safety training | Trigger-corpus block regression on promotion | Per-adapter promotion-gate block rate |
| Embedding-cluster drown-out via seeded near-neighbor chunks | Seed-chunk red-team; assert MMR restores anchors | Top-k anchor-missing rate per cluster |
| Unadjudicated Sophisticated Invalid Traffic (SIVT) events enter training | Admit-then-reverse regression test on a beacon later SIVT-reversed | Admission lag vs. adjudication lag per mode |

## 3. Protect Inference and the Prompt Boundary

Every scoring surface exposed to a paying partner is a queryable oracle ([Tramèr et al. 2016](https://arxiv.org/abs/1609.02943)).

- Return tier labels, not raw scores, on partner-visible outputs. This raises extraction cost rather than preventing it. [Tramèr et al. 2016](https://arxiv.org/abs/1609.02943) Section 6 extracts models matching the target on over 99 percent of inputs from labels alone, needing up to 100 times more queries, so the query budget is the control. Money fields required by the protocol (OpenRTB `seatbid.bid.price`, search ad-rank, retail sponsored-rank) must stay precise; guard those with query budgets and probing detection.
- Enforce contractual query budgets technically. Reject-not-coerce out-of-domain feature values.
- Cap inference cost per call, budgeted in dollars per minute ([OWASP LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)).
- Dual-LLM structural handoff on every attacker-controlled text input (publisher HTML, landing page, brief field). A quarantined LLM emits a fixed JSON schema; a privileged LLM reads only the schema. This is the ad-tech-specific relocation of [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) ([MITRE ATLAS AML.T0051](https://atlas.mitre.org/techniques/AML.T0051), indirect variant `AML.T0051.001`).
- Cross-check every monetization-changing boolean verdict against a non-LLM rules baseline.
- Run an ensemble of two differently-trained VLMs on submitted images as defense-in-depth, not as the boundary. [Qi et al. 2023](https://arxiv.org/abs/2306.13213) Table 3 shows one image transferring across models, raising Perspective-API toxicity 9 to 23 percentage points over each target's no-attack baseline. The largest gains are between models sharing an LLM backbone and its alignment, so vary the backbone rather than only the weights, and expect both members to agree on some wrong verdicts. Route disagreement and high-risk tags (minors, celebrity likeness, trademark) to human review. The rules-based creative-policy classifier (allowlists, banned-terms lists, structural checks) is the automated floor; human review is the boundary for cases the automated path cannot resolve.
- Run voice-clone detector plus AI-content detector as two gates on submitted audio. Require voice-usage authorization on file.
- On-device LLMs ([Chrome Prompt API](https://developer.chrome.com/docs/ai/prompt-api)) reach only top-level windows and their same-origin iframes. A cross-origin ad iframe gets access only if the page delegates it with `allow="language-model"`, so never add that token to an ad slot. Every model output is untrusted at the DOM boundary; [CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) does not inherit into a cross-origin ad iframe.
- Isolate every cache off tenant ID: KV cache (paged-attention serving stacks), RAG index namespace, plan cache, adapter pool ([OWASP LLM02:2025](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)). System-prompt secrecy is not a boundary ([LLM07:2025](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)); enforce thresholds in a deterministic post-processor keyed off the LLM's structured output.

| Threat | Evidence | Runtime signal |
|---|---|---|
| Model extraction by paying partner | Extraction red-team on shadow model | Per-partner query volume vs. contract rate; score-vs-outcome divergence |
| Prompt injection at publisher HTML, advertiser landing page, or brief field | Red-team page corpus with hidden brand-safe-steer payloads | Per-publisher quarantined-vs-baseline disagreement rate |
| Adversarial patch flips VLM policy verdict | Adversarial-patch red-team on held-out corpus | Per-reviewer-version disagreement rate |
| Cross-tenant cache leak (KV, RAG, plan, adapter) | Cross-tenant probe red-team on deployed backend | Cross-tenant cache-hit alarm; identifier Data Loss Prevention (DLP) alerts on model output |
| Denial-of-wallet on paid contextual LLM | Sponge-input red-team | Per-partner `cost_per_bid` SLO; P99 latency outlier |

## 4. Protect Outcome Events and Agentic Actions

Every outcome callback is money and a training label in one packet.

- Sign every callback with the ad-tech-specific field set: `key_id`, `event_type`, event ID, `timestamp`, monetary value, receiving endpoint. `event_type` must be inside the signed set because the same `impression_id` reuses across event types.
- Use HMAC-SHA256 over length-prefixed serialization, or [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/) with receiver-enforced required-minimum covered-components (Section 3.2.1, Section 7.2.1).
- Cover the request body, not only the named fields. RFC 9421 does not sign message content on its own ([Section 7.2.8](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.8)), so `currency`, `quantity`, and label fields stay malleable while the signature still verifies. Require an [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) `Content-Digest` as a covered component, and revalidate that digest against the received bytes, because verifying the signature alone still admits content substitution. No field outside the covered set may influence a monetary amount or a training label.
- Dedup on event ID alone within a TTL window at least as long as the signature-freshness window (callback age plus clock skew tolerance), 24 hours in common practice to cover late-delivered events. Never on `(event_id, timestamp)`.
- Verify HMAC before any payload field influences a control-flow decision.
- Separate financial settlement from training-label materialization.
- Pin the certificate identity to a specific `partner_id`, using a typed Subject Alternative Name (SAN) entry or the Subject Public Key Info (SPKI) hash, not just a trusted issuer. [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html), which obsoletes RFC 6125, states the Common Name RDN MUST NOT be used to identify a service, and extends that prohibition to other RDNs within the subjectName. See the [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) for generic JWT hardening.
- Auth incidents are data incidents: rotate credentials, mark exposure-window rows suspect, invalidate per-partner weights, invalidate model artifacts.
- Tier every agentic tool by risk. HITL (human-in-the-loop) approvals bind a six-tuple: actor, tool, target, normalized parameters, timestamp, expiry ([OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)). Generic agentic patterns in the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
- Kill-switch fallback: a warm, pre-deployed rules-based bidder. A single control-plane flip diverts campaign traffic to it while the agent is quarantined.
- Quarantine reward events past the fraud-adjudication lag; cap the maximum policy shift per epoch.

| Threat | Evidence | Runtime signal |
|---|---|---|
| Forged outcome event = payment fraud AND poisoned label | CI negative tests: forged, stale, cross-endpoint rejected | Rejected-callback rate per partner |
| `impression_id` re-signed with fresh timestamps to over-credit | Re-sign regression test on the same `impression_id` | Per-partner dedup-hit rate |
| Injected-agent budget drain ([OWASP LLM06:2025](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)) | Red-team injection targeting the budget tool | Per-tenant tool-call rate SLO; missing-approval alarm |
| Partner-credential compromise silently poisons rows | Rotation drill; confirm all three data-side actions fire | Per-partner-scoped model-drift monitor after rotation |

## 5. Protect the AI Supply Chain and Generative Provenance

Model artifacts, feature stores, RAG indexes, and generative endpoints are reachable through paths that never cross the ad-serving surface.

- Sign every model artifact with [OpenSSF Model Signing](https://openssf.org/projects/model-signing/). Block deploy on signature failure. Pair signing with a trigger-scan behavioral gate for externally sourced classifiers.
- Bind [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) entries to the participant-provenance tag from Section 2. The ML-BOM is the primary key for the scoped-rollback query.
- Purpose-scope feature-store namespaces. Rotate materialization-write credentials on the production-secrets cadence.
- Verify participant provenance per mode: [ads.txt](https://iabtechlab.com/ads-txt/) and OpenRTB [SupplyChain object](https://github.com/InteractiveAdvertisingBureau/openrtb/blob/main/supplychainobject.md) (programmatic); seller-ID authorization on catalog uploads (retail); advertiser-domain ownership (search); [ads.cert 2.0](https://iabtechlab.com/ads-cert/) or device attestation via [Google Play Integrity](https://developer.android.com/google/play/integrity) or [Apple App Attest](https://developer.apple.com/documentation/devicecheck/dcappattestservice) (CTV).
- Reject VPAID creatives outright in video-programmatic and CTV. VPAID (Video Player-Ad Interface Definition) was a [VAST](https://iabtechlab.com/standards/vast/) extension that let a video ad ship its own JavaScript to run inside the player. Deprecated in VAST 4.1 and replaced by [SIMID](https://iabtechlab.com/simid/) (Secure Interactive Media Interface Definition) in VAST 4.2. Sandboxing VPAID is not viable.
- A platform that develops a generative endpoint and puts it into service under its own name is a *provider* under [EU AI Act Art. 3(3)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_3), which carries the machine-readable marking duty in [Art. 50(2)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_50). That duty does not apply to the extent the system performs an assistive function for standard editing or does not substantially alter the input data or its semantics. An advertiser using the endpoint under its own authority is a *deployer* under Art. 3(4), which carries the Art. 50(4) disclosure duty whenever the creative constitutes a deep fake under [Art. 3(60)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_3).
- Emit the [C2PA 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_hard_bindings) manifest with a hard binding over the generator output bytes at egress. Re-sign per rendition (image resize, video Adaptive-Bit-Rate (ABR) ladder step, audio Server-Side Ad-Insertion (SSAI) stitch). Do not rely on soft binding.
- Require a likeness or voice-use authorization artifact on file before the generator accepts a brief that asserts a real person.
- Freeze the generation model version from the control plane during an incident.

| Threat | Evidence | Runtime signal |
|---|---|---|
| Model-artifact tampering | CI signature test; trigger-scan report per model version | Failed-signature-verification alerts on deploy |
| Unauthorized supply-chain provenance (spoofing seller, gaming seller, unowned domain) | Daily provenance-reconciliation report per mode | Per-participant verification failure rate; auto-quarantine above threshold |
| Legacy or unsafe creative format (VPAID JavaScript) | Ingest test: VPAID tag rejected; homoglyph fuzz suite | VPAID-rejection dashboard; SIMID adoption metric |
| Missing [Art. 50(2)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_50) provider marking at generation | Regression: every generator emit produces a signed manifest | Per-asset generator-egress manifest-signed metric |
| Deep-fake composition from legitimate advertiser assets (Art. 3(60)) | Red-team a recombining brief without authorization | Brief-rejected-no-likeness-auth counter |

## References

**Generic mechanics defer to:**

- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP RAG Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP Secure AI/ML Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

**Regulatory anchors:** [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) Art. 4(4), 9, 17; [DSA](https://eur-lex.europa.eu/eli/reg/2022/2065/oj) Art. 26, 28; [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) Art. 3(60), 6, 50; [COPPA](https://www.law.cornell.edu/cfr/text/16/part-312); [California CPRA](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.120&lawCode=CIV); [CJEU C-604/22](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604).

**Standards:** [RFC 9421](https://www.rfc-editor.org/info/rfc9421/) HTTP Message Signatures; [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) Digest Fields; [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) service identity in TLS; [C2PA 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_hard_bindings); [OpenSSF Model Signing](https://openssf.org/projects/model-signing/); [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/); [MITRE ATLAS](https://atlas.mitre.org/); [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final); [OpenRTB](https://github.com/InteractiveAdvertisingBureau/openrtb2.x); [VAST](https://iabtechlab.com/standards/vast/) and [SIMID](https://iabtechlab.com/simid/); [MRC IVT Guidelines](https://mediaratingcouncil.org/standards-and-guidelines).

**Adversarial ML anchors:** [Tramèr 2016](https://arxiv.org/abs/1609.02943) (extraction); [Shokri 2017](https://arxiv.org/abs/1610.05820) (membership inference); [Qi 2023](https://arxiv.org/abs/2306.13213) (visual jailbreaks); [Hubinger 2024](https://arxiv.org/abs/2401.05566) (sleeper agents); [Hu 2024](https://arxiv.org/abs/2402.07179) (GGPP retrieval steering).

**OWASP LLM Top 10 (2025):** [LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [LLM02](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), [LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/), [LLM10](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/).
