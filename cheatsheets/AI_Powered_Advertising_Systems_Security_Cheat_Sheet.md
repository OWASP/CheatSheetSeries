# AI-Powered Advertising Systems Security Cheat Sheet

## Introduction

Modern advertising platforms make AI-driven financial decisions on every ad request: what to bid, which product to rank first, whether a page is brand-safe, whether traffic is real, which touchpoint gets credit for a conversion. This cheat sheet gives builders the specific controls that stop the AI itself from becoming the attack surface. It applies across every ad-serving mode: programmatic, search, retail media, CTV/OTT (Connected TV and over-the-top streaming ads), DOOH (Digital Out-of-Home: billboards and digital screens), direct-sold, native, and mobile mediation. It covers classical machine learning (ML) on the live serving path (bid, floor, rank, recommendation, quality-score, attribution, brand-safety, invalid-traffic (IVT) / fraud detection). Controls specific to large language models (LLMs) and generative AI are in the companion sheet, *LLM & Generative AI Security in Advertising Cheat Sheet*.

## Terminology

Acronyms and specialized terms used throughout this cheat sheet. Each is also glossed inline the first time it appears in the body.

Foundational sources for the vocabulary below: [IAB Tech Lab OpenRTB](https://github.com/InteractiveAdvertisingBureau/openrtb2.x) for the protocol terms, [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) for the adversarial-ML terms, and the [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) for the regulatory terms.

| Term | Meaning |
|---|---|
| **DSP / SSP** | Demand-Side Platform (buyer's software, e.g. The Trade Desk, DV360) / Supply-Side Platform (seller's software, e.g. Magnite, PubMatic, OpenX). |
| **DMP / CDP** | Data Management Platform (third-party audience warehouse) / Customer Data Platform (first-party equivalent a brand runs on its own customers). |
| **MMP** | Mobile Measurement Partner (attribution vendors like AppsFlyer or Adjust). |
| **RTB** | Real-Time Bidding. Per-impression auction, sub-second decision. |
| **PMP** | Private Marketplace. Invitation-only programmatic auction. |
| **CTV / OTT** | Connected TV / Over-The-Top streaming ads. |
| **DOOH** | Digital Out-of-Home. Digital billboards and screens in physical spaces (airports, malls, retail interiors). |
| **IVT / SIVT** | Invalid Traffic / Sophisticated Invalid Traffic (fraud classes; MRC defines SIVT). |
| **MMM / MTA** | Marketing Mix Modeling (aggregate) / Multi-Touch Attribution (per-user). |
| **LTV** | Lifetime Value. Predicted long-term revenue from a user. |
| **Bid-shading** | Algorithm that lowers a buyer's bid to the estimated clearing price. |
| **Floor / floor model** | Minimum price the seller accepts for an impression, and the model that predicts it. Also called the reserve price. |
| **Lookalike** | Model that finds users similar to a seed audience. |
| **Contextual / brand-safety classifier** | Reads publisher page content and assigns advertiser categories or safety verdicts. |
| **OpenRTB** | IAB Tech Lab protocol for programmatic bid requests. |
| **ads.txt / app-ads.txt** | Public files listing authorized sellers of a publisher's inventory (web / mobile-app). |
| **sellers.json** | Public file listing seller identities across a marketplace. |
| **SupplyChain object** | Ordered list of intermediaries that touched a bid request. |
| **ads.cert 2.0** | IAB Tech Lab standard for cryptographic server-to-server ad-tech request authentication. |
| **VAST / VPAID / SIMID** | Video ad standards. VAST is the IAB XML format; VPAID (deprecated) let ads ship JavaScript; SIMID replaced VPAID in VAST 4.2. |
| **TCF / TC string** | IAB Europe Transparency & Consent Framework / its stored consent string. Personal data under CJEU C-604/22. |
| **GPP** | IAB Global Privacy Platform. Container for jurisdiction-specific consent signals in a bid request. |
| **GPC** | Global Privacy Control. Browser HTTP header (`Sec-GPC: 1`) signaling do-not-sell / do-not-share. |
| **GDPR / DSA / EU AI Act** | Regulation (EU) 2016/679 / 2022/2065 / 2024/1689. |
| **COPPA** | US Children's Online Privacy Protection Act. Current rule 90 FR 16918. |
| **CJEU** | Court of Justice of the European Union. |
| **HMAC** | Hash-based Message Authentication Code. Keyed hash for signing. |
| **NFC** | Unicode Normalization Form Canonical. Single canonical form for accented text. |
| **MAD** | Median Absolute Deviation. Outlier statistic that survives heavy-tailed distributions. |
| **Differential Privacy (DP)** | Adds calibrated random noise so outputs cannot be traced back to any single user. Privacy budget measured in "epsilon"; larger accumulated epsilon means weaker protection. |
| **ML-BOM** | ML Bill of Materials. Machine-readable inventory of a model's training data and dependencies (CycloneDX 1.7 defines the format). |
| **Trigger-scanning** | Backdoor-poisoning detection using neuron-activation clustering and spectral signatures. |
| **Champion / challenger** | Two models running side-by-side on the same traffic to detect drift or partner-scoped poisoning. |
| **1P data** | First-party data. Information a company collects directly from its own customers. |
| **Outcome event** | Any callback a partner fires when something happens on the ad-serving path (impression beacons, click pings, conversion beacons, retail purchase confirmations, CTV completion events, attribution postbacks). |
| **Scoped-rollback query** | The exclusion query "exclude every training row that came from partner X during window Y" that runs when a participant is later found compromised. Requires every row to carry a participant-provenance tag. |

## Ad-Serving Architecture and AI Touchpoints

Advertising is not one system. It is a family of markets that share one property: **an AI model sits between the user and the money**. Common roles across every mode:

- **Buyer**: advertiser or their agent. A **DSP** (Demand-Side Platform, e.g. The Trade Desk, DV360, Amazon DSP) is software that buys ad slots on the advertiser's behalf via the [OpenRTB protocol](https://github.com/InteractiveAdvertisingBureau/openrtb2.x). Wants to reach a user at a price.
- **Seller**: publisher, retailer, streaming service, DOOH network, app developer. Owns the place the ad shows up: a web page, an app screen, a video-ad break, a search-results page, a product-listing page, a billboard slot.
- **Middleman**: **SSP** (Supply-Side Platform, e.g. Magnite, PubMatic, OpenX; software that sells the seller's inventory), exchange, ad server, retailer ad platform, mediation network (routes app ad requests across multiple ad networks), attribution vendor (measures which ad drove which conversion). Runs the marketplace or the measurement.
- **User**: the person the ad reaches, or the query the ad answers.

**Ad-serving modes and their AI touchpoints:**

| Mode | Where AI decides | Example models |
|---|---|---|
| **Programmatic RTB** (Real-Time Bidding: per-impression auction) | Bid (what a buyer offers for a single impression), floor (the minimum price the seller will accept for that impression; the SSP sets it per-user, per-slot, sometimes per-buyer), brand-safety, IVT, targeting | Bid model (predicts what to bid), floor model (predicts the floor price; also called the reserve price), bid-shading (algorithm that lowers a buyer's bid down to the estimated clearing price so they do not overpay), lookalike (finds users similar to a seed audience), contextual classifier (reads the publisher's page content and decides which advertiser categories the page fits: "auto-intender", "cooking", etc.) |
| **Programmatic Guaranteed / PMP** (Private Marketplace: invitation-only auction) | Delivery pacing (spending budget evenly over a flight), forecasting, brand-safety, IVT | Pacing model, forecast model, IVT classifier |
| **Direct-sold / Insertion Order** | Audience matching, inventory forecast, creative selection, pacing | Audience model, forecast model, creative-selection model |
| **Search advertising** | Query intent, quality score (search-engine ranking signal), ad rank (position an ad appears in), click-fraud detection | Intent classifier, quality-score model, click-fraud classifier |
| **Retail media** | Product-recommendation rank, sponsored-product rank (paid product placement in results), LTV (predicted customer Lifetime Value), purchase prediction | Rec ranker, sponsored-rank model, LTV model |
| **CTV / OTT streaming** | Content-context matching, ad-pod optimization (ordering and mixing the sequence of ads shown in a single commercial break), viewer measurement, cross-device linking | Context classifier, ad-pod optimizer, measurement model |
| **DOOH** (digital billboards and screens in airports, malls, roadsides, and retail interiors) | Crowd / audience prediction (from cameras or mobile-signal sensors), dayparting (time-of-day scheduling), creative optimization | Crowd classifier, dayparting model |
| **Native / sponsored content** | Content-audience matching, engagement prediction, native safety | Matching model, engagement predictor, safety classifier |
| **Mobile SDK / mediation** | Waterfall optimization (deciding which ad network to try first), user LTV, on-device selection | Waterfall model, LTV predictor |
| **All modes** | Attribution (crediting the ad exposures that led to a conversion), brand-safety, audience segmentation, budget pacing, IVT | Attribution: **MMM** (Marketing Mix Modeling, aggregate models that estimate how much each channel contributed to total sales) or **MTA** (Multi-Touch Attribution, per-user models that credit each ad exposure along the conversion path); brand-safety classifier (decides whether a placement is safe for a given advertiser, e.g. no car ads next to a plane-crash story, no beer ads next to alcohol-recovery content); segmentation model; IVT classifier |

**Three properties make securing AI in advertising distinctive, regardless of mode:**

1. **Your adversary is inside your permission perimeter.** Whichever mode you run (programmatic, search, retail media, direct-sold), the entity probing your model is a paying customer with contracted access. The DSP watches your floor prices to reverse-engineer your bid-shading. The search advertiser games your quality score. The retail seller manipulates your product-rank model. You cannot block them like a scraper; the defense is to bound how much your model gives away per query.
2. **Training data is adversary-writable participant traffic.** In ad-tech, models learn from whatever the outside world sends you: bid requests, search queries, purchase events, viewer telemetry, publisher-supplied content, DOOH sensor feeds. Every participant in the market has write access to your next model refresh, right now, at line rate.
3. **Every decision moves money on the live path.** Every mode runs against a hard latency budget: the timeout the SSP declares in programmatic bidding, sub-second ranking in retail and search, playback deadlines for CTV ad-pod selection. Defenses that add compute per decision get expensive fast at scale, and a model that times out becomes a real denial-of-service vector.

**Scope.** Sections apply broadly across the modes above; individual bullets name programmatic, search, retail media, CTV, direct-sold, DOOH, or SDK examples where the manifestation differs. The companion sheet covers the controls specific to large language models and generative AI: prompt injection, retrieval-augmented generation, agentic bidders, and generative creative provenance.

## 1. Gate Every Model Call on Consent

**In an AI-powered stack, the model call is itself the regulated processing event.** Running a personalization, targeting, ranking, recommendation, quality-score, or lookalike model on a user is profiling under [GDPR Art. 4(4)](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_4), regardless of whether the mode is programmatic, search, retail, CTV, or direct-sold. Traditional ad-tech gates run consent checks just before the system writes a tracking identifier (browser cookie, mobile ad ID, hashed-email), which is the point where identity gets persisted. That is too late for AI: the model has already read the user's features and produced a scored decision by the time you get there. Run the consent check earlier, on the model call itself.

**Controls:**

- **Treat consent as an authorization check, not a model feature.** A model that receives consent as a feature learns to route around it via correlated auxiliary features. Applies to every AI touchpoint that reads user data: bid model, search intent model, retail recommender, CTV context classifier, DOOH audience predictor.
- **Refuse the model call on child-directed traffic.** Signals vary per mode: `regs.coppa == 1` (the OpenRTB flag for a child-directed impression under the US [Children's Online Privacy Protection Act, as amended in 2025](https://www.federalregister.gov/documents/2025/04/22/2025-05904/childrens-online-privacy-protection-rule)) for programmatic; child-account flag in retail media; kids-profile flag in CTV; safe-search-with-child-account in search. Stripping identifiers is not enough: a model with device, context, or content features still produces a personalized output. Route child-flagged traffic to a rules-based path with no AI invocation.
- **Consent-scope the training corpus.** A model must not train on rows where the user did not consent to the specific Purpose that model implements. (Under the Interactive Advertising Bureau (IAB) Europe [Transparency & Consent Framework (TCF)](https://iabeurope.eu/transparency-consent-framework/), whose stored Transparency & Consent (TC) strings are personal data under [CJEU C-604/22](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604) where they can reasonably be linked to an identifier, "Purposes" are numbered categories of processing; Purpose 4 = *use profiles to select personalised advertising*.) A model trained on non-consented data stays contaminated even if inference is gated later, so pair [GDPR Art. 17 (Right to erasure)](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_17) with a retraining or approved machine-unlearning cycle. The Purpose-scope rule also applies within a single participant: in retail media, a shopper's purchase history is consented for order fulfillment, not automatically for advertising training. Treat those as separate Purposes with their own retention windows and training-admission flags.
- **Honor real-time opt-outs at every AI touchpoint, not just at the ad-serving gate.** Users can withdraw consent through several channels; each of them must gate the model call:
    - **Browser.** The [Global Privacy Control](https://globalprivacycontrol.org/) `Sec-GPC: 1` HTTP header, signaling do-not-sell / do-not-share under US state laws.
    - **Bid request.** State-law opt-out flags carried inside `regs.gpp`, the OpenRTB [Global Privacy Platform](https://iabtechlab.com/gpp/) string. The [IAB GPP Section Information registry](https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/Section%20Information.md) maps each Section ID to a state law.
    - **Retailer.** The shopper's opt-out preferences on the retailer's site.
    - **Streamer.** The viewer's personalization-off setting on the streaming service.
    - **Device OS.** iOS [App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency) or Android's [Advertising ID reset / opt-out](https://support.google.com/googleplay/answer/3405269).

    Bind the check to the feature-fetch step, which runs before the model call. Pipelines that pre-fetch features and cache them for a batch run will otherwise keep serving pre-opt-out features minutes after the user withdrew consent; the ad-serving gate looks correct even though the model has already run on stale-consent data.
- **Invalidate downstream materializations on opt-out:** segment memberships, lookalike scores, cached embeddings, precomputed rankings, retail-recommendation caches, CTV audience-segment memberships. Clearing only the ad-serving cache is not enough. If the user's identity still sits inside a lookalike segment, an audience-segment table, or a retail-recommendation store, the next ad decision reads it right back out and personalizes to them again. The serving-side cache is the wrong layer to invalidate.
- **Test models for special-category *inference*, not just special-category *inputs*.** [GDPR Art. 9](https://eur-lex.europa.eu/eli/reg/2016/679/oj#art_9) defines special-category data (health, sexual orientation, religion, ethnicity, political opinion, biometrics, genetics) as data that carries extra restrictions. The EU Digital Services Act ([DSA](https://eur-lex.europa.eu/eli/reg/2022/2065/oj)), at [Art. 26(3)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj#art_26), restricts ad targeting based on profiling that uses that data. A model that infers those categories from generic inputs is inside the restriction. Applies to every classifier: contextual, brand-safety, retail-recommendation (health-adjacent products), search-intent, CTV genre-preference. Score model outputs for special-category correlation and gate accordingly.
- **Route high-stakes campaign categories through a stricter path.** Employment, housing, and credit ads sit closest to [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) high-risk uses. Under [Art. 6](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#art_6) plus [Annex III](https://eur-lex.europa.eu/eli/reg/2024/1689/oj#anx_III) point 4(a), AI systems used to place targeted job advertisements are explicitly listed as high-risk. This applies across modes: a job ad delivered via search, retail media, or direct-sold is under the same obligation as one placed programmatically.
- **Treat any consent signal you don't recognize as "no consent", and enforce that at the moment the request arrives, not later at the ad-decision boundary.** Once a request is written to your training corpus, the next model refresh will learn from it even if the ad itself was blocked at serve time; silent admission is the poisoning path. The rule surfaces differently per mode. In programmatic, drop any bid request whose GPP Section ID your parser doesn't recognize. Each Section ID maps to one jurisdiction's consent rules (`2` = TCF EU, `8` = California), and the registry grows every time a US state passes a new privacy law. In retail media, the equivalent is an unrecognized retailer consent flag; in CTV, an unrecognized platform consent state. Whatever the mode, the discipline is the same: reject at the door, log the reason code, and never let the row enter the corpus.

| Threat | Defense | Evidence it works | Runtime signal |
|---|---|---|---|
| Model runs on a non-consented user | Consent gate before the model call; check bound to feature-fetch, not to the ad-serve decision | Integration test: submit a non-consented request; assert no model invocation is logged | Model-invocation rate per consent state; alert on any invocation on `regs.coppa == 1` |
| Non-consented rows enter the training corpus and contaminate the next refresh | Consent-scope training-corpus admission; reject unrecognized consent signals at ingest and drop the row | Row-level audit: sample training rows and confirm each carries a consent-reason code permitting the model's Purpose | Training-admission rate by consent-reason-code, per partner; alert on rejection-rate spikes |
| Model output infers a special category (GDPR Art. 9, DSA Art. 26(3)) from generic inputs | Score model outputs for special-category correlation; gate outputs that correlate | Fairness / disparate-impact audit against protected classes on each refreshed model | Per-classifier output distribution monitoring; alert on distribution shift against a protected class |
| Consent withdrawn but the model still runs (on cached features or a materialized segment) | Bind the consent check to feature-fetch; invalidate downstream materializations (segments, lookalike scores, embeddings) on withdrawal | Test: withdraw consent, replay a request, confirm every materialization is invalidated within the staleness bound | Opt-out cache miss/hit rate; stale-cache alerts |
| High-stakes campaign category (employment / housing / credit) processed on the standard path | Route those categories through elevated review + logging; apply high-risk-AI controls where AI Act Annex III point 4(a) applies | Documented routing rules; audit log of every campaign classification | Alert on any employment / housing / credit campaign that took the standard path |

## 2. Protect the Training Corpus

**Your training data is being written by the outside world, live, in real time, in every ad-serving mode.** Every bid request, search query, purchase event, viewer session, publisher content upload, sensor feed, and beacon is a potential training row, and every adversary who participates has write access.

**Cross-mode training-corpus surfaces:**

| Mode | Adversary-writable training rows |
|---|---|
| Programmatic | Bid requests; outcome events (impression beacons, click pings, conversion beacons, viewability events) |
| Search | Queries, clicks, dwell time, landing-page-quality signals |
| Retail media | Product-catalog uploads, purchase events, cart events, seller-supplied metadata, review text |
| Direct-sold | Publisher-supplied audience segments, publisher content, first-party data uploads |
| CTV / OTT | Viewer telemetry, completion signals, cross-device linkage events |
| DOOH | Sensor feeds (crowd counts, dayparting), audience-panel data |
| Native / sponsored | Publisher-supplied engagement events (scroll depth, dwell, in-content clicks), sponsored-content topical labels supplied by the publisher |
| Mobile SDK / mediation | SDK-reported install events, in-app engagement events, waterfall-outcome telemetry |
| All modes | Attribution beacons, brand-safety label feedback, IVT verdicts, **pacing/forecast telemetry** (delivery-vs-plan gaps, inventory-forecast residuals; poisoned pacing data teaches the model to over- or under-serve a specific advertiser or supply source) |

**Controls:**

- **Sign dataset manifests with an offline key the data store cannot access, and include the participant-provenance tag per row.** The [OWASP Secure AI/ML Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html) covers the generic model-artifact-integrity baseline: digital signatures on model artifacts and access-controlled registries. The ad-tech-specific requirement is that the signed manifest binds each row to its participant-provenance tag (partner ID, supply-chain hop, validation profile). That tag is what makes the scoped-rollback query ("exclude every row that came from partner X during window Y") answerable without re-hashing the whole corpus. A generic signed manifest without provenance tagging still lets you detect *whether* rows changed, but not *which partner's* rows to exclude on a compromise.
- **Quarantine outcome feedback until adjudication concludes.** The quarantine window must exceed the mode's adjudication lag: fraud adjudication (programmatic, CTV, DOOH), return or refund adjudication in retail (a conversion's label can flip weeks later), click-validity adjudication (search), engagement re-scoring (native). Rows admitted before adjudication cannot be un-trained without a full retrain or unlearning cycle.
- **Reconcile outcome events against post-hoc validity verdicts before admitting them to training.** When an event that passed verification at fire-time is later reclassified as invalid, the label it produced is poisoned. Exclude the row from training; do not just down-weight it. Concrete cases per mode:
    - **Programmatic / CTV:** a beacon that passed signature verification ([HMAC](https://en.wikipedia.org/wiki/HMAC)) but referenced an impression later flagged as sophisticated invalid traffic (SIVT, defined in the [MRC Invalid Traffic Detection and Filtration Guidelines](https://mediaratingcouncil.org/standards-and-guidelines)).
    - **Retail media:** a purchase later reversed for fraud.
    - **Search:** a click later charged back as invalid.
- **Exclude a compromised participant's rows at the next retrain.** When a participant is later found compromised or bad-acting (a spoofing SSP, a gaming retail seller, a fraudulent search advertiser, a compromised publisher feed, a gaming SDK partner), the participant-provenance tag from the signed manifest is the primary key: run the scoped exclusion query and retrain without their rows.
- **Run trigger-scanning on every refreshed model to catch backdoor attacks; aggregate-based defenses miss them by design.** Availability poisoning degrades a model's overall accuracy and shows up in outlier detection such as [median absolute deviation (MAD)](https://en.wikipedia.org/wiki/Median_absolute_deviation). [Backdoors (NIST AI 100-2e2025 Section 2.3.3)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf) work differently. An attacker plants a **trigger** (a specific input pattern, say a particular `device.sua` combination or a rare keyword) that forces the model to a wrong output whenever the trigger appears. On every other input the model behaves normally, so overall accuracy and aggregate distributions look clean, and aggregate-only monitors see nothing wrong. **Neuron-activation clustering** and **spectral signatures** are the two mature trigger-scanning techniques. Applies to every classifier: brand-safety, contextual, retail-recommendation, search-quality, IVT, CTV context.
- **Normalize participant-supplied text before classifier inference.** Apply Unicode [NFC normalization](https://unicode.org/reports/tr15/), strip zero-width characters, and strip [bidirectional-control characters](https://en.wikipedia.org/wiki/Bidirectional_text#Unicode_bidi_algorithm) on publisher pages (programmatic), seller product descriptions and reviews (retail media), landing-page snippets (search), and creative text (all modes). Attackers use homoglyphs (a Cyrillic `а` swapped in for Latin `a`) and adversarial-suffix payloads to slip content past classifier keyword filters.
- **Reconcile crawler vs. rendered view.** Server-side cloaking shows one page to your crawler and another to users. Refuse contextual segments derived from pages whose crawler view diverges from a headless-render view. Analogous concern in retail media: reconcile the API-returned product description with the customer-facing rendered product page.
- **Run champion/challenger monitoring on clean holdout traffic.** It catches drift and slow-burn poisoning across all modes. A challenger model runs beside the incumbent on the same traffic, and a gap between them that opens on one partner's segment is the signal.

| Threat | Defense | Evidence it works | Runtime signal |
|---|---|---|---|
| Availability poisoning: adversary shifts aggregate distributions via live traffic writes | Signed dataset manifests with participant-provenance tags; MAD-based outlier detection on incoming rows | Injected-poisoning red-team on a canary corpus; confirm the manifest signature blocks unsigned writes | Per-partner distribution drift on ingest; alert on rejection-rate spikes |
| Backdoor / trigger poisoning: adversary plants a feature combination that flips output only for trigger-carrying inputs (NIST Section 2.3.3) | Trigger-scanning (neuron-activation clustering, spectral signatures) on every refreshed model; behavioral test on a held-out trigger corpus for externally sourced classifiers | Scheduled trigger-scan report per model version; sign-off gate blocks deploy on scan failure | Per-classifier output on a fixed adversarial-trigger probe set; alert on a shift for one partner only |
| Publisher-page poisoning: adversarial page content shifts a contextual or brand-safety classifier's segment assignment | NFC + zero-width + bidi-control stripping applied to publisher page text before classifier inference; reconcile crawler DOM vs. rendered DOM | Diff test on a page corpus with homoglyphs / cloaking; assert stripping and DOM-reconciliation both fire | Per-publisher segment-mix vs. engagement-rate divergence; investigate publishers whose mix drifts in their own favor |
| Spoofed-supply provenance: a compromised or spoofing seller writes training rows tagged as trusted | Partner-provenance tag on every row (partner, supply-chain hop, validation profile); scoped-rollback query pre-built | Rollback drill: mark a partner as compromised, confirm the exclusion query filters the tagged rows on the next retrain | Per-partner training-row admission rate; alert on any partner exceeding its historical baseline |
| Unadjudicated outcome events (SIVT-suspect beacons, unrefunded purchases) enter training | Quarantine outcome feedback until the mode's adjudication window closes; reconcile against post-hoc validity verdicts before admission | Test: admit a beacon later reversed by SIVT, confirm it is excluded from the next training set | Training-admission lag vs. adjudication lag per mode; alert when admission runs ahead of adjudication |

## 3. Protect Models at Inference

**In ad-tech, model inference is a public-facing product.** Every scoring surface you expose to a paying partner is an oracle they can query legitimately, at contracted volume, for years. The DSP watches the price on your bid response, the search advertiser observes where their ad ranked, the retail seller measures how your sponsored-rank model treated their listing. Each observation is legal traffic under your contract, and each one gives them a data point about your model. In a normal API-security setting you would rate-limit or block a client that queried a model this heavily; in ad-tech that client is your paying customer, and cutting them off is not an option. The defense is architectural: bound how much your model reveals per query, detect the query patterns that signal extraction intent, and cap the compute spent per query so an adversary cannot exhaust your latency or cost budget.

In this section, *inference* means running the model to produce an output: the model call, seen from the model's side of the boundary.

**Cross-mode inference oracles:**

| Mode | Oracle surface | What leaks |
|---|---|---|
| Programmatic | Bid request → bid response | Bid model, floor model |
| Search | Query + advertiser + creative → ad rank | Quality-score model, ad-rank model |
| Retail media | Product query → sponsored rank + organic rank | Recommendation ranker, sponsored-rank model |
| CTV | Ad-pod slot → chosen ad | Context classifier, ad-pod optimizer |
| All modes | Audience-overlap / lookalike API | Audience-membership + segment definitions |
| All modes | Attribution reporting API | Attribution model + user-outcome joins |

**Threats a participant runs against you at inference (same taxonomy, every mode):**

| Threat | Mode-specific example |
|---|---|
| **Extraction**: attacker reconstructs a copy of your model by querying it and observing outputs | Programmatic: attacker rebuilds your bid-shading model from the bids they see clear the auction. Search: attacker rebuilds your quality-score model (the model that decides which ad appears in which rank position for a query) by watching where their own ads land. Retail: attacker rebuilds your sponsored-rank model (the model that decides which paid-placement product appears above organic results) by uploading probe listings and watching the rank changes. |
| **Membership inference**: attacker asks "was this user in your training set?" and can tell | Audience-overlap API in any mode; retail-audience membership |
| **Attribute inference / model inversion**: attacker recovers sensitive attributes (health condition, income) from a model's generic scores | Any classifier that ranks user propensity; DSA Art. 26(3) applies to inferred attributes |
| **Test-time evasion**: attacker crafts an input that gets the wrong answer from a model, on purpose | Floor-probing (bidding just below the floor repeatedly to reverse-engineer it; programmatic); quality-score gaming (search); ranking manipulation (retail); brand-safety adversarial suffixes (all modes) |
| **Sponge / latency-adversarial**: attacker feeds inputs designed to make the model burn maximum compute per call | Long text triggers longer decoding in an LLM classifier; deep-tree features force worst-case cost in an ensemble classifier (an ensemble being a group of models whose outputs are combined). The threat applies to every ensemble or LLM classifier. |

**Controls:**

- **Coarsen output tiers on every scoring surface exposed to partners.** Bucket segment scores into a few tiers; jitter ranks; expose tier labels ("high / medium / low") rather than raw probabilities. This does *not* apply to money fields required by the protocol: `seatbid.bid.price` in OpenRTB (the bid amount the buyer submits for the impression), ad-rank values in search API responses, sponsored-rank position in retail-media reporting. Coarsening the money field breaks the market. Protect the money path with probing detection and query budgets instead.
- **Enforce contractual query budgets technically.** A partner querying your models at volumes disproportionate to their legitimate transaction volume is doing extraction. This applies whether the partner is a DSP, a search advertiser using a bulk API, a retail seller, or an SDK partner running mediation.
- **Detect probing patterns.** Single-feature perturbation at volume from one partner is adversarial exploration. Watch for near-identical requests with one feature varied. The signature looks the same in programmatic (bid requests), search (query variations), and retail (product-listing probes).
- **Bound feature values at inference; reject rather than coerce.** Reject out-of-domain feature values outright: future timestamps, negative money fields, physically impossible device combinations, product IDs that do not exist, query strings past length caps. This blocks a large class of evasion inputs before they reach the model.
- **Cap inference cost per call.** Bound decode, hop, and iteration counts inside the model call. Detect per-partner inference-latency and cost outliers; feed sustained outliers into the rate limiter.
- **Add differential-privacy (DP) noise during training where per-user scores must be exposed.** DP is a mathematical technique that adds calibrated random noise so outputs cannot be traced back to any single user. The cumulative privacy loss is measured by a budget called **epsilon**; the larger the accumulated epsilon, the weaker the protection. Fix the training-time epsilon per model version. Where a reporting or overlap interface answers per-user or small-cohort queries through a DP mechanism, track per-partner and per-model epsilon spend across sessions; repeated queries compose.
- **Enforce a per-partner cost budget on any paid third-party AI API call** (dollars per minute, not just requests per minute). Any mode that routes brand-safety, contextual, or recommendation decisions through a third-party LLM or vision API is exposed to economic denial-of-wallet.
- **Monitor score-vs-realized-outcome divergence per partner.** An extraction adversary stops caring about realized outcomes; their pattern optimizes for the model's *score*, not the conversion, purchase, or click. Applies across modes: DSP behavior vs. actual click-through, search-advertiser behavior vs. actual quality-score outcomes, retail-seller behavior vs. actual purchase rate, SDK-partner behavior vs. actual LTV.

| Threat | Defense | Evidence it works | Runtime signal |
|---|---|---|---|
| Extraction: partner reconstructs model behavior from bid/query stream | Contractual query budgets enforced technically; coarsened output tiers on non-money fields; probing-pattern detection | Extraction red-team on a shadow model; measure how many partner queries approach the budget | Per-partner query volume vs. contracted rate; alert on outliers |
| Membership inference on audience-overlap / lookalike APIs | k-anonymity thresholds on segment-size responses; DP noise where per-user scores must be exposed; per-partner epsilon budget tracked across sessions | Membership-inference red-team against a holdout audience set on the deployed model | Per-partner epsilon spend; alert when partner-model epsilon budget is close to exhaustion |
| Attribute inference / model inversion produces DSA Art. 26(3) special-category outputs from generic inputs | Score model outputs for special-category correlation; suppress or gate the output | Correlation audit per refresh; disparate-impact tests on protected classes | Alert on classifier output correlating with any protected class beyond threshold |
| Test-time evasion: floor-probing, quality-score gaming, brand-safety adversarial suffixes | Feature-envelope validation at ingress (reject-not-coerce for out-of-domain values); score-vs-realized-outcome divergence monitoring per partner | Adversarial-input CI suite; validation-envelope tests | Per-partner score-vs-outcome divergence; alert when divergence exceeds threshold |
| Sponge / latency-adversarial input burns disproportionate inference compute | Cap decode / hop / iteration counts per model call; per-partner cost + latency outlier detection wired into rate limiter | Sponge-input test suite with crafted worst-case payloads | Per-partner inference cost + latency P99; alert on outliers |
| Denial-of-wallet on paid third-party AI APIs used inside the ad-decision path | Per-partner cost budget with circuit breaker (dollars per minute, not just requests per minute); token caps on any LLM call | Budget-exhaustion drill; confirm circuit breaker fails over to a rules baseline | Cost-per-partner metric; circuit-breaker state dashboard |

## 4. Protect Outcome Events and the API Boundary

**Every outcome callback your infrastructure receives is money and a training label in the same packet.** A forged conversion beacon is payment fraud *and* a poisoned training row, in every ad-serving mode. A compromised API boundary is the fastest route into your training pipeline: whatever an attacker writes across that boundary becomes tomorrow's training data before you can rotate the credential that let them in.

This section uses two working terms. **Outcome event** covers any callback a partner fires when something happens on the ad-serving path: impression beacons, click pings, conversion beacons, retail purchase confirmations, CTV completion events, attribution postbacks. (the training-surface table in Section 2 lists mode-specific examples of these; the general term extends the same idea to retail and search cases.) **API boundary** covers every server-to-server integration point where those callbacks (plus bid requests, retail-media API calls, search-partner API calls, DOOH scheduling calls, mediation SDK traffic) reach your infrastructure.

### Outcome-event signing

Generic signed-webhook hygiene (HMAC construction, freshness bounds, replay protection, constant-time comparison) is well-covered in the OWASP crypto guidance and shared-secret patterns; the ad-tech-specific requirements on top of that baseline:

- **Bind `event_type` into the signature, not just the event ID.** Ad-tech outcome events are polymorphic in a way generic webhooks are not: the same `impression_id` can validly appear in an impression callback, a viewability callback, a click callback, and a conversion callback. If `event_type` is not in the signed set, a captured impression beacon can be replayed as a conversion (and become a poisoned training label as well as payment fraud). Sign at minimum: `key_id`, `event_type`, event ID (`impression_id`, `order_id`, or `click_id`), `timestamp`, monetary value (`payout_micros` or currency-amount), and the receiving endpoint. Use HMAC-SHA256 over a length-prefixed canonicalization, or use [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/). If you use RFC 9421, the receiver must enforce a required-minimum covered-components set (RFC 9421 Section 3.2.1 *Enforcing Application Requirements*; Section 7.2.1 *Insufficient Coverage* explains why).
- **Dedup on the event ID alone within a TTL window**, never on `(event_id, timestamp)`. This is ad-tech-specific: a partner-side signer that holds a valid key can otherwise re-sign the same `impression_id` with fresh in-window timestamps and credit the same impression many times. That is different behavior from a generic webhook, where the sender is trusted not to re-sign.
- **Verify the HMAC first, before any payload field influences a control-flow decision.** Ad-tech outcome flows chain freshness → endpoint-match → dedup → credit; running any of those on an unauthenticated `timestamp` or `endpoint` value is trusting adversary input.

### Label integrity for training

- **Separate financial settlement from training-label materialization.** Billing may credit immediately on freshness+HMAC; the training corpus should not admit the row until adjudication concludes (fraud in programmatic and CTV; return/refund in retail; click-validity in search).
- **Weight training samples by per-partner label credibility.** Score partners on historical clawback, refund, and invalid-click rates, and feed that score as a sample weight in the next training cycle.
- **Cap per-user influence in training** (per-user gradient clipping). Bounds the damage from a burst of forged conversions.
- **Protect attribution-model integrity.** MMM and MTA models train on the outcome events above. Poisoned outcome events poison every attribution decision downstream, which in turn poisons budget allocation across every ad-serving mode. Sign attribution inputs the same way; version the attribution model per participant-provenance window so scoped rollback is possible.

### API-boundary authentication

Generic JWT hardening (algorithm confusion, signature verification, key trust) is covered in the [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); the two ad-tech-specific requirements on top of that baseline, plus the mTLS pinning below:

- **Pin the certificate identity to a specific `partner_id`, not just to a trusted issuer.** Chain-to-trusted-issuer alone lets any cert issued by the same shared CA authenticate as any partner, which is a real problem in ad-tech because many DSP, SSP, and retail-media partners buy certificates from the same handful of enterprise CAs. Pin the SAN, CN, or SPKI hash to the concrete `partner_id` your rows are tagged with, so an attacker cert cannot silently become a different partner in your training-corpus provenance.
- **Auth incidents are data incidents in an AI stack.** On credential rotation or partner compromise, three things happen in lockstep: (1) mark training rows attributed to that partner during the exposure window as suspect, retrain or exclude on the next refresh; (2) invalidate per-partner sample weights, credibility scores, and fraud-model features derived from that partner's traffic during the window; (3) invalidate signed model artifacts whose training set overlapped the window. Rotating the credential ends the auth incident; leaving the poisoned rows in the corpus does not end the data incident.

| Threat | Defense | Evidence it works | Runtime signal |
|---|---|---|---|
| Forged outcome event = payment fraud AND poisoned training label in one packet | Sign every outcome callback; bind `key_id`, `event_type`, event ID, `timestamp`, monetary value, and endpoint; verify HMAC before any payload field is trusted | Negative tests: forged, stale, and cross-endpoint callbacks all rejected in CI | Rejected-callback rate per partner; alert on spikes |
| Impression callback replayed as a click, conversion, or completion | `event_type` bound in the signed set; receiver only accepts each event ID once per TTL | Replay test: capture a signed impression callback, replay it against a click endpoint, confirm rejection | Cross-event-type replay attempts logged; alert on repeat offenders |
| `impression_id` re-signed with fresh timestamps to credit the same impression many times | Dedup on event ID alone within a TTL window, not on `(event_id, timestamp)` | Test: submit multiple fresh-timestamp signatures for the same `impression_id`; assert only one credits | Per-partner dedup-hit rate; alert on partners with high hit rates |
| Partner-credential compromise silently poisons training rows for the exposure window | Auth-incidents-are-data-incidents runbook: mark exposure-window rows suspect + retrain, invalidate per-partner sample weights + fraud features, invalidate model artifacts whose training set overlapped the window | Rotation drill: simulate credential compromise; confirm all three data-side actions fire | Per-partner-scoped model-drift monitor; alert if drift persists after rotation |
| Attribution model (MMM / MTA) poisoned via contaminated outcome events | Sign attribution-input feeds the same way; version the attribution model per participant-provenance window so scoped rollback is possible | Rollback drill on the attribution model with an induced poisoned window | Attribution-model divergence vs. incremental-lift experiments; alert on divergence per partner |

## 5. Protect the AI Supply Chain

An attacker can compromise your models without touching a single user request. Model files, feature stores, audience data stores, and classifier pipelines are all reachable through paths that never cross the ad-serving surface: a poisoned artifact loaded at deploy time, an unauthorized write to a feature store, a vendor-supplied classifier that arrives with a backdoor already baked in. This section covers the five supply-chain surfaces specific to AI in ad-tech: model artifacts, the feature and audience-data stores, the fraud and quality classifiers, the creative pipeline those classifiers review, and the participant-provenance verification that decides which rows become training data at all.

### Model artifacts

Generic model-artifact hygiene (preferring inert file formats, signing artifacts before deploy, keeping an ML bill of materials) is covered by the [OWASP Secure AI/ML Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html). Two ad-tech-specific rules go on top of that baseline:

- **Trigger-scan every externally sourced classifier before it reaches the serving path.** Vendor-supplied brand-safety and IVT classifiers are the highest-risk artifact class in ad-tech: they arrive pre-trained on a corpus you did not control, and signing them (via [OpenSSF Model Signing](https://openssf.org/projects/model-signing/)) verifies who trained the model but not what it learned. Pair signing with the trigger-scanning behavioral test from Section 2 for every vendor artifact. Ad platforms routinely swap in third-party brand-safety and IVT classifiers, unlike most other industries.
- **Bind ML-BOM entries to the participant-provenance tag from Section 2.** A [CycloneDX 1.7 ML-BOM](https://cyclonedx.org/capabilities/mlbom/) that lists datasets by name only cannot answer the operational question "which training rows came from partner X during window Y?" when that partner is later compromised. Treat the ML-BOM as the primary key for scoped retraining, not just an audit deliverable.

### Feature store and audience data store

- **Purpose-scope namespaces.** A fraud model must not read features materialized for personalization. A retail sponsored-rank model must not read features materialized for organic recommendation. A search quality-score model must not read features materialized for retargeting. Different Purpose, different namespace, different access grant.
- **Version-pin feature schemas per model version in the model registry.**
- **Feature-store and audience-store outputs are personal data.** Segment memberships, lookalike scores, predicted attributes, retail-audience assignments, CTV cross-device linkages, and search-user-cohort assignments are all model outputs regulated as personal data under GDPR and multiple US state laws. The consent gate applies to reads, not only to model calls.
- **Write access is a persistent poisoning surface.** Rotate materialization-write credentials with the same cadence as production secrets. Applies to every audience data store: retail **1P data** (first-party data, meaning information a company collects directly from its own customers), publisher 1P data, **DMPs** (Data Management Platforms, third-party audience-data warehouses that ingest data from many sources), **CDPs** (Customer Data Platforms, first-party equivalents that a brand runs against its own customers), and mobile stores fed by **MMPs** (Mobile Measurement Partners, attribution vendors like AppsFlyer or Adjust).

### Fraud / IVT and quality classifiers

- **These classifiers are themselves attack targets, on both the evasion and poisoning axes:** programmatic IVT and SIVT classifiers; search click-fraud classifiers; retail fake-review and gaming-seller classifiers; CTV viewer-fraud classifiers; DOOH crowd-count spoofing detectors; SDK install-fraud classifiers.
- **Train exclusively on verified-clean traffic.** If adversaries can write to the training data, they teach the classifier that adversarial behavior is legitimate.
- **Run champion/challenger comparisons on a clean holdout per partner.** A detection model that degrades only on one partner's traffic is a poisoning or evasion signal.
- **Refresh training corpora with generative-AI-driven traffic samples.** Behavioral classifiers trained before 2024 rarely include synthetic-interaction distributions.
- **Verify request authenticity in two tiers.** Where the platform offers device attestation, require a token bound to a challenge your own server just issued; accept only fresh attestations, never relayed ones. Examples: [Google Play Integrity](https://developer.android.com/google/play/integrity), [Apple App Attest](https://developer.apple.com/documentation/devicecheck/dcappattestservice). Where the platform does not offer device attestation (most Smart-TV OSes and set-top boxes today), fall back to authenticating the supply path itself with cryptographic server-to-server auth like [ads.cert 2.0](https://iabtechlab.com/ads-cert/) in programmatic, or equivalent partner-auth mechanisms in retail media and search, combined with behavioral-signal scoring on the request itself.

### Ad creative and content validation

Creative reaches three AI consumers regardless of mode: LLM/classifier review (see the companion *LLM & Generative AI Security in Advertising Cheat Sheet*), the renderer (defer to the [CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) and [XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) cheat sheets), and the provenance chain (also the companion sheet). For the classifier-hygiene rules that belong in this sheet:

- **Normalize creative text to NFC and strip zero-width and bidi-control characters** before review *and* rendering. Applies to programmatic display creatives, search ad copy, retail product descriptions and titles, CTV **VAST** creative metadata (Video Ad Serving Template, the IAB standard XML format for video ads), native content copy, and DOOH creative captions.
- **Two-tier review.** Deterministic filters (denylists, landing-page checks, the normalization above) run first, LLM semantic review runs second, with confidence thresholding between them.
- **Reject VPAID creatives outright** in video-programmatic and CTV. **VPAID** (Video Player-Ad Interface Definition) was a VAST extension that let a video ad ship its own JavaScript to run inside the player (the source of most malicious-video-ad incidents). VPAID was deprecated in VAST 4.1 and replaced by **SIMID** (Secure Interactive Media Interface Definition, a locked-down interactivity API) in VAST 4.2. Sandboxing VPAID is not viable; reject.

### Supply / participant provenance for training-data admission

- **Programmatic:** verify `ads.txt` and `app-ads.txt` on every request, walk the full OpenRTB **SupplyChain** object, and exclude training rows from spoofing sellers on the next retrain. `ads.txt` is a public file at a website's root listing which sellers may sell its ad inventory; `app-ads.txt` is the mobile-app equivalent, which lives on the app developer's *website* domain and is resolved through an app-store lookup of the OpenRTB `app.bundle` (the app's store package ID). The SupplyChain object is the ordered list of intermediaries that touched a bid request, letting the buyer verify every hop back to the publisher.
- **Retail media:** verify seller-ID authorization for product-catalog uploads; enforce provenance of purchase-history joins; exclude gaming-seller training rows on retrain.
- **Search:** verify advertiser-domain ownership for landing-page-quality signals used in training.
- **Direct-sold:** verify first-party audience-data provenance from publisher partners; sign the audience-file manifest at ingress.
- **CTV / OTT:** verify device-attestation origin for viewer telemetry; treat unattested telemetry as lower-credibility training signal.
- **All modes:** every training row carries its participant-provenance tag; when a participant is compromised or excluded, the tag is the primary key for scoped retraining.

| Threat | Defense | Evidence it works | Runtime signal |
|---|---|---|---|
| Model-artifact tampering: swapped, resigned, or backdoored model reaches the deploy pipeline | OpenSSF Model Signing on every artifact; block deploy on signature failure; pair signing with a trigger-scan gate for externally sourced classifiers | Signature-verification test in CI; trigger-scan report attached to every model version | Failed-signature-verification alerts on deploy; per-artifact scan-status dashboard |
| Feature-store write compromise: poisoned feature values contaminate every model that reads the namespace | Purpose-scope namespaces; version-pin feature schemas per model version; rotate materialization-write credentials on the production-secrets cadence | Access-audit report + write-permission tests; scoped-write review at each rotation | Unauthorized-write alerts on the feature store; write-credential-age monitor |
| IVT / brand-safety / quality classifier evasion or poisoning by adversary participant | Train on verified-clean traffic only; champion/challenger on clean holdout per partner; refresh with generative-AI-driven traffic samples | Champion/challenger accuracy diff per partner on a fixed adversarial holdout | Per-partner classifier-accuracy divergence; alert on any partner-only drop |
| Vendor-supplied classifier arrives with a training-corpus history you did not control | Trigger-scan every externally sourced classifier before it reaches the serving path; ML-BOM row for every vendor artifact with its provenance | Behavioral test on a held-out trigger corpus; ML-BOM completeness check at deploy | ML-BOM drift alerts; per-vendor-classifier accuracy on the adversarial holdout |
| Legacy or unsafe creative format (e.g. VPAID JavaScript) reaches the renderer | Reject VPAID outright; normalize creative text (NFC, zero-width, bidi-control) before classifier review and rendering | Ingest test: submit a VPAID tag, confirm rejection; homoglyph fuzz suite | Creative-rejection reasons dashboard; alert on any VPAID that got past the gate |
| Unauthorized supply-chain provenance: spoofing seller (programmatic), gaming seller (retail), unowned advertiser domain (search) writes trusted training rows | Per-mode provenance verification: `ads.txt` / `app-ads.txt` walk (programmatic); seller-ID authorization on catalog uploads (retail); advertiser-domain ownership (search); signed audience manifests (direct-sold); device-attested telemetry (CTV) | Daily provenance-reconciliation report per mode | Per-participant provenance-verification failure rate; auto-quarantine above threshold |

## References

**Regulations:**

- [GDPR (Regulation 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj): profiling under Art. 4(4); erasure under Art. 17
- [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj): high-risk classification under Art. 6; Annex III point 4(a) (targeted job advertising); Art. 50 transparency
- [DSA (Regulation 2022/2065)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj): Art. 26(1), 26(3), 28(2)
- [COPPA Rule 90 FR 16918](https://www.federalregister.gov/documents/2025/04/22/2025-05904/childrens-online-privacy-protection-rule): compliance date 22 April 2026
- [CJEU C-604/22 (ECLI:EU:C:2024:214, 7 March 2024)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62022CJ0604): TC string is personal data

**Ad-tech specifications:**

- [OpenRTB Specification](https://github.com/InteractiveAdvertisingBureau/openrtb2.x) (IAB Tech Lab)
- [ads.txt](https://iabtechlab.com/ads-txt/) and [sellers.json](https://iabtechlab.com/sellers-json/)
- [OpenRTB SupplyChain Object specification](https://github.com/InteractiveAdvertisingBureau/openrtb/blob/main/supplychainobject.md)
- [IAB Europe TCF](https://iabeurope.eu/transparency-consent-framework/)
- [IAB Tech Lab GPP Section Information registry](https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/Section%20Information.md)
- [VAST](https://iabtechlab.com/standards/vast/), [SIMID](https://iabtechlab.com/simid/)
- [ads.cert 2.0](https://iabtechlab.com/ads-cert/)

**Standards and frameworks:**

- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/info/rfc8725/)
- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/)
- [OpenSSF Model Signing](https://openssf.org/projects/model-signing/)
- [CycloneDX 1.7 ML-BOM](https://cyclonedx.org/capabilities/mlbom/)
- [safetensors](https://github.com/safetensors/safetensors)
- [Google Play Integrity](https://developer.android.com/google/play/integrity), [Apple App Attest](https://developer.apple.com/documentation/devicecheck/dcappattestservice)

**Adversarial ML anchors:**

- [NIST AI 100-2e2025: Adversarial Machine Learning Taxonomy](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Tramèr et al. 2016, USENIX Security](https://arxiv.org/abs/1609.02943): model extraction
- [Shokri et al. 2017, IEEE S&P](https://arxiv.org/abs/1610.05820): membership inference
- [Fredrikson et al. 2015, ACM CCS](https://dl.acm.org/doi/10.1145/2810103.2813677): model inversion
- [Shumailov et al. 2021, EuroS&P](https://arxiv.org/abs/2006.03463): sponge examples

**Related OWASP cheat sheets:**

- *LLM & Generative AI Security in Advertising Cheat Sheet*: proposed companion sheet covering prompt injection, RAG, generative endpoints, agentic bidders, and deepfake defenses
- [Secure AI/ML Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html)
- [AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
