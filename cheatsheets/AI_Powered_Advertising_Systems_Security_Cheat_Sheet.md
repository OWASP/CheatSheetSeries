# AI-Powered Advertising Systems Security Cheat Sheet

## Introduction

Modern advertising platforms make AI-driven financial decisions on every ad request. Classical machine learning (bid, floor, rank, recommendation, quality-score, attribution, brand-safety, invalid-traffic detection) sits on the live serving path alongside newer LLM, VLM, and generative endpoints. This cheat sheet covers the ad-tech-specific security controls that stop the AI itself from becoming the attack surface, across every ad-serving mode (programmatic RTB, Programmatic Guaranteed, PMP or private marketplace, direct-sold, search, retail media, CTV/OTT, DOOH or digital-out-of-home screens, native, and mobile mediation). LLM refers to a large language model, VLM to a vision-language model.

Generic mechanics defer to existing OWASP cheat sheets: [LLM Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), [RAG Security](https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html), [AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html), [Secure AI/ML Model Ops](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html), [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), and [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html). This sheet owns the ad-tech-specific relocations of those controls.

| Mode / AI touchpoint | Section(s) |
|---|---|
| Consent gates before ad decisions | 1 |
| Training corpora, RAG indexes, fine-tune adapters | 2 |
| Inference oracles, prompt boundaries, cross-tenant isolation | 3 |
| Outcome events, agentic bidders, HITL tool authority | 4 |
| Model artifacts, C2PA provenance, EU AI Act Art. 50 | 5 |

## 1. Gate AI Decisions on Consent

Running a personalization, targeting, ranking, recommendation, quality-score, LLM contextual review, or lookalike model on a user is profiling under [GDPR Art. 4(4)](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_4), regardless of ad-serving mode. Traditional ad-tech gates check consent just before writing a tracking identifier. That is too late: the model has already read features and produced a scored decision. **Gate on the model call itself, not the identifier write.**

- **Treat consent as an authorization check, not a model feature.** A model that receives consent as a feature routes around it via correlated auxiliary features.
- **Refuse the model call on child-directed traffic.** Applied signals vary per mode: `regs.coppa == 1` in [OpenRTB](https://github.com/InteractiveAdvertisingBureau/openrtb2.x) under [COPPA (16 CFR Part 312)](https://www.law.cornell.edu/cfr/text/16/part-312); child-account flag in retail media; kids-profile flag in CTV. [California CPRA section 1798.120(c)](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.120&lawCode=CIV) sets a 16-year opt-in threshold with an actual-knowledge trigger; [DSA Art. 28](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_28) protects minors online.
- **Consent-scope the training corpus and retrieval index.** A model must not train on rows where the user did not consent to the specific Purpose that model implements ([IAB Europe TCF](https://iabeurope.eu/transparency-consent-framework/), Purpose 4 = personalized advertising; TC strings are personal data per [CJEU C-604/22](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604)). Pair [GDPR Art. 17 erasure](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_17) with retraining or approved machine-unlearning. In retail media, purchase history consented for order fulfillment is not automatically consented for advertising training.
- **Honor real-time opt-outs at every AI touchpoint.** Bind the check to the feature-fetch step, before the model call. Batch pipelines that pre-fetch features otherwise keep serving pre-opt-out features minutes after withdrawal. Signals: [Global Privacy Control](https://globalprivacycontrol.org/) `Sec-GPC: 1`; OpenRTB `regs.gpp` with jurisdiction-specific Section IDs from the [IAB GPP Section registry](https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/Section%20Information.md) (SID `2` = TCF EU, `8` = California); [iOS App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency); [Android Advertising ID reset](https://support.google.com/googleplay/answer/3405269).
- **Invalidate downstream materializations on opt-out.** Segment memberships, lookalike scores, cached embeddings, precomputed rankings, retail-recommendation caches, CTV audience segments, LLM KV caches, and adapter warm-pools. Clearing only the ad-serving cache is insufficient.
- **Test models for special-category inference, not just inputs.** [GDPR Art. 9](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_9) defines special-category data; [DSA Art. 26(3)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_26) restricts profiling-based targeting that uses it. A model that infers those categories from generic inputs is inside the restriction. Score outputs for special-category correlation and gate accordingly.
- **Route high-stakes categories through a stricter path.** Employment, housing, and credit ads sit closest to [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) high-risk uses under [Art. 6](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_6) plus [Annex III](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#anx_III) point 4(a) on targeted job advertising.
- **Treat any unrecognized consent signal as no consent, at ingestion.** Silent admission is the poisoning path: once a request enters the training corpus, the next model refresh learns from it even if the ad was blocked at serve time.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Model runs on a non-consented user | Consent gate bound to feature-fetch, before the model call | Integration test: submit non-consented request; assert no model invocation is logged | Model-invocation rate per consent state; alert on `regs.coppa == 1` |
| Non-consented rows enter the training corpus | Consent-scope admission; reject unrecognized signals at ingest | Row-level audit: sample training rows carry a consent-reason code | Training-admission rate by consent-reason-code |
| Special-category inference from generic inputs ([Art. 9](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_9), [DSA 26(3)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_26)) | Score outputs for special-category correlation; gate outputs that correlate | Fairness / disparate-impact audit on each refreshed model | Per-classifier distribution vs. protected class |
| Withdrawn consent but model still runs | Bind check to feature-fetch; invalidate downstream materializations | Withdraw consent; replay a request; assert every materialization invalidated | Opt-out cache miss/hit rate; stale-cache alerts |

## 2. Protect the Corpus (Training and Retrieval)

**Training data and RAG indexes are being written by the outside world at line rate.** Every bid request, search query, purchase event, viewer session, publisher content upload, sensor feed, and beacon is a potential training row; every brand-book PDF, ad-policy chunk, and fine-tune adapter is retrieval or serving material. Paying partners have write access to both.

- **Sign dataset manifests and RAG chunks with an offline key.** [OpenSSF Model Signing (OMS)](https://openssf.org/projects/model-signing/) scopes to model artifacts; its sigstore-bundle plus DSSE plus in-toto primitives extend to per-chunk manifests. Feed the provenance verdict into the reviewer prompt as a first-class input feature so a downgrade to unsigned appears in the classifier's decision string.
- **Tag every training row and RAG chunk with the participant-provenance tag.** The tag (partner ID, supply-chain hop, validation profile) is the primary key for the scoped-rollback query "exclude every row from partner X during window Y" when that partner is later found compromised. No re-hashing of the whole corpus needed.
- **Key per-tenant RAG-index write ACLs off tenant identity, never off prompt or retrieved content.** Prompts collide across tenants on shared taxonomy; tenant IDs do not.
- **k-of-n anchor verification on retrieval.** Every query in a restricted category (alcohol, gambling, health claims, political, financial services, targeted-to-minors) must return at least k of n named prohibited-terms anchors from that category's policy corpus. Retrieval that returns on-topic chunks without the anchors fails closed to the rules baseline.
- **Default to MMR (Maximal Marginal Relevance) or diversity-sampled retrieval, not similarity top-k alone.** An attacker with write access to any RAG corpus (brand-book uploads, ad-policy chunks, plan-cache entries) can plant benign-reading paragraphs engineered to embed close to prohibited-terms query vectors. Under similarity top-k retrieval, those planted paragraphs push the real guardrail anchors out of the top-k retrieved set, leaving the reviewer LLM to decide on the attacker's chunks. Do not rely on "ignore irrelevant context" prompt instructions to compensate; [Hu et al. 2024 (arXiv:2402.07179, GGPP)](https://arxiv.org/abs/2402.07179) show adversarial prefixes override that instruction.
- **Quarantine outcome events past adjudication.** Adjudication lag differs per mode: fraud verdicts (programmatic, CTV, and Digital-Out-of-Home screen networks), return or refund verdicts (retail), click-validity verdicts (search). Rows admitted before adjudication cannot be un-trained without a full retrain. Reconcile against post-hoc verdicts: beacons that passed [HMAC](https://en.wikipedia.org/wiki/HMAC) at fire-time but were later flagged as sophisticated invalid traffic (SIVT) per the [MRC IVT Guidelines](https://mediaratingcouncil.org/standards-and-guidelines) are poisoned labels; exclude, do not down-weight.
- **Trigger-scan every refreshed model and every externally sourced classifier.** Availability poisoning shows up in aggregate outlier detection ([median absolute deviation](https://en.wikipedia.org/wiki/Median_absolute_deviation)) but backdoors ([NIST AI 100-2e2025 Section 2.3.3](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)) do not. Neuron-activation clustering and spectral signatures are the two mature techniques. [Hubinger et al. 2024 (arXiv:2401.05566, "Sleeper Agents")](https://arxiv.org/abs/2401.05566) show supervised fine-tuning, RL, and adversarial training do not remove trigger-conditioned backdoors and can teach models to hide them.
- **Refuse to load any unsigned fine-tune adapter.** Sign the adapter with OMS; sign the fine-tune dataset with in-toto attestation bound to the adapter's [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) entry. Supplier attestation is not a substitute for the platform's own trigger-corpus promotion gate.
- **Normalize participant-supplied text before classifier or retrieval indexing.** Apply Unicode NFC, strip zero-width and bidi-control characters on publisher pages, seller product descriptions, review text, landing-page snippets, and submitted ad copy.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Corpus or RAG poisoning by adversarial participant | Signed manifests plus provenance-as-feature plus k-of-n anchor verification; MMR retrieval | Red-team an unsigned reversal chunk; assert reviewer routes to rules baseline | Chunk signature verdict per retrieval; anchor-missing alert; per-partner distribution drift |
| Backdoor / trigger poisoning ([NIST Section 2.3.3](https://csrc.nist.gov/pubs/ai/100/2/e2025/final), [Hubinger 2024](https://arxiv.org/abs/2401.05566)) | Trigger-scanning per refreshed model; held-out trigger-corpus behavioral gate on externally sourced adapters | Scheduled trigger-scan report per model version | Per-classifier output on fixed adversarial-trigger probe set |
| Publisher-page or landing-page injection into a classifier or generator | NFC plus zero-width plus bidi stripping; crawler-vs-rendered DOM reconciliation; dual-LLM handoff (see Section 3) | Diff test on homoglyph / cloaking corpus | Per-publisher segment-mix drift; per-tenant same-LP headline drift |
| Unadjudicated SIVT-suspect events enter training | Quarantine past adjudication window; reconcile against post-hoc validity | Admit a beacon later SIVT-reversed; assert exclusion from next training set | Admission lag vs. adjudication lag per mode |

## 3. Protect Inference and the Prompt Boundary

**Every scoring surface exposed to a paying partner is an oracle they can query for years at contracted volume.** In classical ML this leaks the bid-shading model, floor model, quality-score model, or sponsored-rank model ([Tramèr et al. 2016, USENIX Security](https://arxiv.org/abs/1609.02943)). In LLMs the same partner also crosses the prompt boundary and can extract the operator's product logic. The defense is architectural: bound how much the model reveals per query, sandbox the prompt path from attacker-controlled text, and isolate every cache off tenant identity.

- **Return tier labels, not raw scores, on any output a partner sees.** For every model score a paying partner reads, bucket into a few tiers (for example "high", "medium", "low") and add small random noise to numeric ranks. Raw scores let a partner reverse-engineer the model over time; tier labels do not. One exception: money fields the protocol requires (`seatbid.bid.price` in OpenRTB, ad-rank in search API responses, sponsored-rank position in retail-media reporting) must stay precise or the market breaks. Guard those with per-partner query budgets and probing detection instead.
- **Enforce contractual query budgets technically.** A partner querying at volumes disproportionate to legitimate transaction volume is doing extraction.
- **Reject-not-coerce feature values at inference.** Out-of-domain values (future timestamps, negative money fields, physically impossible device combinations, product IDs that do not exist) get rejected outright. Blocks a large class of test-time evasion.
- **Cap inference cost per call.** Bound decode, hop, and iteration counts. This is the [OWASP LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/) control on paid per-bid contextual LLM calls; budget per-partner spend in dollars per minute (not RPM); log `cost_per_bid` as an SLO metric.
- **Add differential-privacy noise where per-user scores must be exposed.** Fix the training-time epsilon per model version. Track per-partner epsilon spend across sessions; repeated queries compose.
- **Dual-LLM structural handoff on every attacker-controlled text input.** A quarantined LLM reads publisher HTML, landing-page HTML, or brief text and emits a fixed JSON schema. A privileged LLM reads only the schema. Injected instructions cannot cross the boundary into the model that emits a monetizable verdict. This is the ad-tech-specific relocation of the [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) control ([MITRE ATLAS AML.T0051](https://atlas.mitre.org/), indirect variant `AML.T0051.001`).
- **Cross-check every monetization-changing boolean verdict against a non-LLM rules baseline.** One flipped LLM verdict monetizes unsafe inventory at safe-inventory CPMs. Run two independent evaluators.
- **Ensemble two differently-trained VLMs on submitted images.** [Qi et al. 2023, arXiv:2306.13213](https://arxiv.org/abs/2306.13213) show one visual adversarial example can universally jailbreak an aligned model. Physically realizable patches survive digital preprocessing per NIST AI 100-2e2025 Section 2.2.4. Disagreement routes celebrity, trademark, and minor-audience tags to human review.
- **Run a voice-cloning detector plus an AI-content detector as two gates on submitted audio.** Require voice-usage authorization on file before accepting audio asserting a named real person.
- **Treat on-device LLMs as origin-scoped, not iframe-scoped.** The [Chrome Prompt API](https://developer.chrome.com/docs/ai/prompt-api) is available to top-level windows and same-origin iframes by default. Cross-origin ad iframes reach it only if the publisher explicitly delegates `allow="language-model"`. Every model output is untrusted at the DOM boundary; CSP does not inherit into a cross-origin ad iframe.
- **Isolate every cache off tenant ID, not prompt content.** Key/Value (KV) cache (paged-attention serving backends such as vLLM reuse memory blocks across requests unless keyed off tenant), RAG index namespace, plan cache, and fine-tune adapter pool. Cross-tenant leakage is the [OWASP LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) failure on this surface. System-prompt secrecy is not a boundary either: enforce every threshold in a deterministic post-processor keyed off the LLM's structured output ([OWASP LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)).

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Model extraction by paying partner ([Tramèr 2016](https://arxiv.org/abs/1609.02943)) | Contractual query budgets; coarsened output tiers on non-money fields; probing-pattern detection | Extraction red-team on shadow model | Per-partner query volume vs. contract rate; score-vs-outcome divergence |
| Prompt injection at publisher HTML / landing page / brief field ([LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)) | Dual-LLM handoff plus non-LLM rules cross-check plus payload-class strip | Red-team page corpus with hidden `brand-safe: true` payloads | Per-publisher quarantined-vs-baseline disagreement rate |
| Adversarial patch on submitted creative ([Qi 2023](https://arxiv.org/abs/2306.13213)) | Two-VLM ensemble; disagreement-to-HITL on celebrity, trademark, minor-audience tags | Adversarial-patch red-team on held-out corpus | Per-reviewer-version disagreement rate |
| Cross-tenant leak (KV, RAG, plan, adapter, reporting) | Per-tenant cache isolation keyed off tenant ID; session-scoped data-access credential; per-session adapter load/unload | Cross-tenant probe red-team on deployed backend | Cross-tenant cache-hit alarm; identifier-DLP alerts |
| Denial-of-wallet on paid contextual LLM ([LLM10](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)) | Per-partner cost budget in dollars per minute; token caps; tool-loop depth cap | Sponge-input red-team | Per-partner `cost_per_bid` SLO; P99 latency outlier |

## 4. Protect Outcome Events and Agentic Actions

**Every outcome callback is money and a training label in the same packet.** A forged conversion beacon is payment fraud AND a poisoned training row. When an autonomous agent sits between an LLM and the platform API, that same forged input becomes an argument to `campaign.update_budget`. The signed-callback API boundary and the agent's tool authority are one defensive surface with two entry points.

### Signed callbacks

- **Sign every outcome callback with the ad-tech-specific field set.** Beyond generic signed-webhook hygiene (see the [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)), bind: `key_id`, `event_type`, event ID (`impression_id`, `order_id`, or `click_id`), `timestamp`, monetary value, and receiving endpoint. Ad-tech outcome events reuse the same event ID across event types (an `impression_id` validly appears in impression, viewability, click, and conversion callbacks), so `event_type` must be inside the signed set.
- **Choose one canonicalization and enforce it end-to-end.** Either HMAC-SHA256 over a length-prefixed serialization of the signed fields, or [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/) with the receiver enforcing a required-minimum covered-components set (RFC 9421 Section 3.2.1 *Enforcing Application Requirements*; Section 7.2.1 *Insufficient Coverage*).
- **Dedup on the event ID alone within a TTL window.** Never dedup on `(event_id, timestamp)`; a partner-side signer with a valid key can otherwise re-sign the same `impression_id` with fresh in-window timestamps and credit the same impression many times.
- **Verify the HMAC before any payload field influences a control-flow decision.** Freshness, endpoint-match, and dedup otherwise run on unauthenticated payload input.
- **Separate financial settlement from training-label materialization.** Billing may credit immediately on freshness plus HMAC; the training corpus should not admit the row until adjudication concludes. Sign attribution-model inputs the same way; version the attribution model per participant-provenance window so the scoped-rollback query is answerable.
- **Pin the certificate identity to a specific `partner_id`, not just to a trusted issuer.** Chain-to-trusted-issuer alone lets any cert issued by the same shared CA authenticate as any partner. Pin the SAN (Subject Alternative Name), CN (Common Name), or SPKI (Subject Public Key Info) hash to the concrete `partner_id` your rows are tagged with.
- **Auth incidents are data incidents.** On credential rotation or partner compromise: mark exposure-window rows suspect, invalidate per-partner sample weights and fraud-model features from that partner's traffic, and invalidate signed model artifacts whose training set overlapped the window.

### Agentic tool authority

An HITL (human-in-the-loop) approval is a required human sign-off shown a full action preview before the tool call executes. Every approval binds a six-tuple:

```json
{
  "actor": "user_id or agent_id",
  "tool": "campaign.update_budget",
  "target": "campaign_id=42",
  "normalized_parameters": {"daily_cap_usd": 500},
  "timestamp": "2026-08-30T14:22:11Z",
  "expiry":    "2026-08-30T14:32:11Z"
}
```

An approval for `daily_cap_usd=500` does not authorize `5000`. The policy service canonicalizes parameters server-side so a re-worded injection resolving to the same target does not evade an already-consumed approval. Generic agentic patterns in the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html). Ad-platform tier table:

| Tool | Tier | Approval | Step-up |
|---|---|---|---|
| `campaign.update_budget` | CRITICAL | HITL plus six-tuple action preview | WebAuthn re-auth |
| `brand_exclusion.remove` | CRITICAL | HITL plus six-tuple action preview | WebAuthn re-auth |
| `creative.upload` | HIGH | HITL plus action preview | Session re-auth |
| `campaign.pause` | HIGH | HITL plus action preview | Session re-auth |
| `campaign.report_read`, `insight.generate` | LOW | Auto-approve | None |

- **Bind the per-agent tool allowlist to the agent's issued identity, not the LLM session.** Session compromise cannot expand the allowlist. This is the [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) control on ad-platform tools.
- **Kill-switch to a warm, pre-deployed rules-based bidder.** A single control-plane flip diverts campaign traffic while the agent is quarantined; the kill-switch also freezes the agent's tool allowlist to reporting-only.
- **Quarantine reward events past the fraud-adjudication lag.** Reinforcement-learning and bandit policy updates ingest outcome events only after the invalid-traffic and fraud verdict has landed. Cap the maximum policy shift per epoch.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Forged outcome event = payment fraud AND poisoned label | Sign every callback; bind `key_id`, `event_type`, event ID, timestamp, value, endpoint; verify HMAC first | Negative tests: forged, stale, cross-endpoint callbacks rejected in CI | Rejected-callback rate per partner |
| Injected-agent budget drain ([LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)) | CRITICAL-tier HITL plus WebAuthn on `campaign.update_budget`; tenant-scoped circuit breaker; policy-service cap outside the prompt | Red-team injection targeting the budget tool | Per-tenant tool-call rate SLO; missing-approval alarm on CRITICAL calls |
| Partner-credential compromise silently poisons rows | Auth-incidents-are-data-incidents runbook: mark exposure-window rows suspect, invalidate per-partner weights, invalidate model artifacts | Rotation drill; confirm all three data-side actions fire | Per-partner-scoped model-drift monitor after rotation |
| Forged-outcome reward manipulation of RL/bandit updates | Reward quarantine past fraud lag; per-partner credibility weight; capped policy shift per epoch | Fraud-adjudication feed integrity test | Reward quarantine-release lag; credibility drift |

## 5. Protect the AI Supply Chain and Generative Provenance

**Every model artifact, feature store, RAG index, and generative endpoint is reachable through paths that never cross the ad-serving surface.** A poisoned model loaded at deploy time, an unauthorized write to a feature store, a vendor classifier with a backdoor baked in, or a text-to-image endpoint that emits unmarked AI-generated content are all compromises the runtime controls in Sections 1 through 4 cannot catch.

- **Sign every model artifact with [OpenSSF Model Signing](https://openssf.org/projects/model-signing/).** Block deploy on signature failure. For externally sourced brand-safety and IVT classifiers, pair signing with a trigger-scan behavioral gate; signing tells you who trained the model, not what it learned. Ad platforms routinely swap in third-party classifiers, unlike most industries.
- **Bind ML-BOM entries to the participant-provenance tag from Section 2.** A [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) listing datasets by name only cannot answer "which training rows came from partner X during window Y?" when that partner is later compromised. Treat the ML-BOM as the primary key for the scoped-rollback query.
- **Purpose-scope feature-store namespaces.** A fraud model must not read features materialized for personalization. Different Purpose, different namespace, different access grant. Rotate materialization-write credentials on the production-secrets cadence.
- **Verify participant provenance per mode before training-corpus admission.** Programmatic: walk [ads.txt](https://iabtechlab.com/ads-txt/) and `app-ads.txt`, and the OpenRTB [SupplyChain object](https://github.com/InteractiveAdvertisingBureau/openrtb/blob/main/supplychainobject.md). Retail: verify seller-ID authorization for catalog uploads. Search: verify advertiser-domain ownership. Direct-sold: sign audience-file manifests at ingress. CTV: device-attested telemetry via [Google Play Integrity](https://developer.android.com/google/play/integrity) or [Apple App Attest](https://developer.apple.com/documentation/devicecheck/dcappattestservice) where the platform supports it; otherwise fall back to [ads.cert 2.0](https://iabtechlab.com/ads-cert/) server-to-server auth.
- **A platform that runs its own generative endpoint is a *provider* under [EU AI Act Art. 50(2)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_50).** The marking obligation attaches at generator egress. The advertiser-as-brief-author is the *deployer* under Art. 50(4) whenever the resulting creative constitutes a deep fake under [Art. 3(60)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_3). Publisher is neither. The Art. 50(4) editorial-responsibility carveout attaches only to AI-generated text on matters of public interest, not to image, audio, or video ads.
- **Emit the C2PA manifest with a hard binding over the generator output bytes** on the same call that returns the asset, signed by the platform's generator claim signer. Attach an `action` assertion naming the model version and brief-hash. Re-sign per rendition, carrying the generator's original manifest as an ingredient ([C2PA 2.1](https://spec.c2pa.org/specifications/specifications/2.1/index.html) Section 18.13). Hard bindings are byte-exact, so re-sign at every image resize (C2PA Section 9.2.2) and every video ABR (adaptive-bit-rate) ladder step (C2PA Section 9.2.3), and every audio SSAI (server-side ad-insertion) stitch. Severing the chain strips the Art. 50(2) mark. Do not rely on soft binding: C2PA 2.1 Section 9.3.1 lists no approved algorithm.
- **Require a likeness or voice-use authorization artifact on file before the generator accepts a brief that asserts a real person.** Embed the authorization ID in the manifest's `action` assertion. Detect at generation time when a brief recombines advertiser-supplied stills or voice into a scene never staged; set the deep-fake flag in the manifest and the served ad label regardless of source-consent.
- **Freeze the generation model version from the control plane during an incident.** The serving stack stays deployed; a compromised or newly jailbroken checkpoint stops producing while auction traffic continues. Every generated asset re-enters the full ingestion pipeline; no fast path from generation to serving.

| Threat | Defense | Evidence | Runtime signal |
|---|---|---|---|
| Model-artifact tampering | [OMS](https://openssf.org/projects/model-signing/) on every artifact; block deploy on failure; trigger-scan gate on external classifiers | Signature-verification test in CI; trigger-scan report per model version | Failed-signature-verification alerts on deploy |
| Unauthorized supply-chain provenance (spoofing seller, gaming seller, unowned advertiser domain) | Per-mode provenance verification (`ads.txt`, catalog seller-ID auth, domain ownership, device attestation) | Daily provenance-reconciliation report per mode | Per-participant verification failure rate; auto-quarantine above threshold |
| Missing Art. 50(2) provider marking at generation | C2PA hard binding plus machine-readable AI-generated marking at egress; re-sign per rendition | Regression: every generator emit produces a signed manifest | Per-asset generator-egress manifest-signed metric |
| Deep-fake composition from legitimate advertiser assets ([Art. 3(60)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_3)) | Likeness or voice authorization ID required at brief acceptance; per-tenant asset fingerprint registry | Red-team a recombining brief without authorization | Brief-rejected-no-likeness-auth counter |
| Adversarial text in submitted creative flips classifier verdict | Normalize creative text (NFC, strip zero-width, strip bidi-control) before classifier review and rendering | Homoglyph fuzz suite regressed on the reviewer pipeline | Creative-rejection reasons dashboard |

## References

**Regulatory:**

- [GDPR (Regulation 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj): [Art. 4(4)](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_4), [Art. 9](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_9), [Art. 17](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_17)
- [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj): [Art. 3(60)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_3), [Art. 6](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_6), [Annex III](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#anx_III), [Art. 50](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_50) including 50(2) and 50(4)
- [DSA (Regulation 2022/2065)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj): [Art. 26](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_26), [Art. 28](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_28)
- [COPPA (16 CFR Part 312)](https://www.law.cornell.edu/cfr/text/16/part-312)
- [California CPRA section 1798.120(c)](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.120&lawCode=CIV)
- [CJEU C-604/22 (7 March 2024)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604): TC string is personal data

**Ad-tech specifications:**

- [OpenRTB Specification](https://github.com/InteractiveAdvertisingBureau/openrtb2.x), [SupplyChain object](https://github.com/InteractiveAdvertisingBureau/openrtb/blob/main/supplychainobject.md), [ads.txt](https://iabtechlab.com/ads-txt/), [ads.cert 2.0](https://iabtechlab.com/ads-cert/)
- [IAB Europe TCF](https://iabeurope.eu/transparency-consent-framework/), [IAB Tech Lab GPP Section registry](https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/Section%20Information.md)
- [MRC IVT Guidelines](https://mediaratingcouncil.org/standards-and-guidelines)

**Standards and frameworks:**

- [RFC 8725 JWT BCP](https://www.rfc-editor.org/info/rfc8725/), [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/)
- [OpenSSF Model Signing](https://openssf.org/projects/model-signing/), [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/), [C2PA 2.1 Specifications](https://spec.c2pa.org/specifications/specifications/2.1/index.html)
- [Google Play Integrity](https://developer.android.com/google/play/integrity), [Apple App Attest](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [Chrome Prompt API](https://developer.chrome.com/docs/ai/prompt-api), [Global Privacy Control](https://globalprivacycontrol.org/)

**Adversarial ML anchors:**

- [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final): Adversarial Machine Learning Taxonomy
- [MITRE ATLAS](https://atlas.mitre.org/): technique pages such as `AML.T0051` render in browsers; machine-readable YAML at [mitre-atlas/atlas-data](https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml)
- [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/): [LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [LLM02 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), [LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), [LLM07 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/), [LLM10 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
- [Tramèr et al. 2016, USENIX Security](https://arxiv.org/abs/1609.02943) (extraction), [Shokri et al. 2017, IEEE S&P](https://arxiv.org/abs/1610.05820) (membership inference), [Fredrikson et al. 2015, ACM CCS](https://dl.acm.org/doi/10.1145/2810103.2813677) (model inversion), [Shumailov et al. 2021, EuroS&P](https://arxiv.org/abs/2006.03463) (sponge)
- [Qi et al. 2023, arXiv:2306.13213](https://arxiv.org/abs/2306.13213) (visual adversarial examples), [Hubinger et al. 2024, arXiv:2401.05566](https://arxiv.org/abs/2401.05566) (sleeper agents), [Hu et al. 2024, arXiv:2402.07179](https://arxiv.org/abs/2402.07179) (GGPP retrieval steering)

**Related OWASP cheat sheets:**

- [LLM Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), [RAG Security](https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html), [AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html), [Secure AI/ML Model Ops](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html)
- [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
