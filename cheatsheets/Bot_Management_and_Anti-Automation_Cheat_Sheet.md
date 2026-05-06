# Bot Management and Anti-Automation Cheat Sheet

## Introduction

Modern web applications face a continuous stream of automated traffic that is not a Distributed Denial of Service event but is still abusive: credential stuffing, content scraping, inventory hoarding (scalping), fake account creation, gift-card enumeration, card testing, fake reviews, click fraud, and skewed analytics. The OWASP **Automated Threats to Web Applications** project (OAT-001 through OAT-021) catalogues these patterns.

This cheat sheet provides defensive guidance that goes beyond the [Credential Stuffing Prevention Cheat Sheet](Credential_Stuffing_Prevention_Cheat_Sheet.md) and addresses the full spectrum of automated abuse. It focuses on architecture, signals, response strategy, and CAPTCHA alternatives.

The objective is **not to block all bots** (search engine crawlers, monitoring agents, and accessibility tools are legitimate) but to raise the cost of abusive automation while keeping legitimate users and bots unaffected.

## Common Threats and Risks

- **OAT-008 Credential Stuffing** — replaying breached username/password pairs.
- **OAT-011 Scraping** — large-scale content, price, or PII extraction.
- **OAT-005 Scalping / Inventory Hoarding** — buying limited stock for resale.
- **OAT-019 Account Creation** — fake accounts at signup endpoints.
- **OAT-012 Cashing Out** — using stolen accounts to extract value.
- **OAT-001 Carding** — testing stolen card numbers via low-value purchases.
- **OAT-003 Ad Fraud** — fake clicks and impressions.
- **OAT-002 Token Cracking** — brute-forcing gift cards, vouchers, coupons.
- **OAT-015 Denial of Inventory** — adding items to cart to deplete stock.
- **OAT-014 Vulnerability Scanning** — automated probing for weaknesses.
- **Skewed business metrics** — bots polluting A/B tests, recommendations, fraud models.
- **Privacy violations** — over-collecting fingerprinting data to defend against bots.

## Threat Modeling Before Controls

Before adding tooling, identify which OAT categories apply to your application and which endpoints are at risk. A login form, a search page, a checkout, and a public API have very different threat profiles and defenses.

| Endpoint type | Primary OAT risk | Suggested first control |
|---|---|---|
| Login | OAT-008 Credential Stuffing | Rate limit + breached-password check + MFA |
| Signup | OAT-019 Account Creation | Email/phone verification + velocity limits |
| Search / catalog | OAT-011 Scraping | Rate limit per identity + behavioral signal |
| Checkout / cart | OAT-005 Scalping, OAT-001 Carding | Queue + purchase limits + 3D Secure |
| Public API | OAT-011, OAT-014 | API keys + per-key quotas + signed requests |
| Comments / reviews | OAT-020 Account Aggregation, spam | Reputation + delayed publishing |

## Layered Defense Architecture

A single control is brittle. Combine controls at three layers:

1. **Edge layer** — CDN, WAF, or anti-bot service: IP reputation, ASN filtering, TLS fingerprint (JA3/JA4), HTTP/2 fingerprint, basic rate limits.
2. **Application layer** — session-aware rate limits, identity-bound quotas, behavioral signals, honeypots, CAPTCHA challenges.
3. **Backend / business layer** — anomaly detection on transactions, account-velocity rules, fraud scoring, async review queues.

A request that looks human at one layer (good IP, valid CAPTCHA) may still fail at another (10 checkouts in 30 seconds with different cards).

## Rate Limiting and Quotas

Rate limiting is the foundational control. Apply it at multiple keys, not just IP.

- **Per IP** — coarse, defeated by residential proxy networks but still useful as a floor.
- **Per session / cookie** — defeated by cookie clearing, useful against unsophisticated bots.
- **Per authenticated identity** — most reliable; applies after login.
- **Per endpoint** — the login endpoint deserves a tighter limit than the home page.
- **Per ASN or geo** — useful when traffic from datacenter ASNs is unexpected.

Use a token-bucket or sliding-window algorithm. Avoid fixed-window counters: they allow bursts at boundary times.

A correct login-endpoint rate limit applies **two independent buckets**, both of which must be under their threshold for the request to pass:

- **Per-username bucket** — limits attempts against any single account regardless of source IP. Defends a targeted account from a distributed attack.
- **Per-IP (or per-IP+ASN) bucket** — limits the volume of attempts originating from one source against any account. Defends against credential-stuffing sweeps that try one password per account.

A common mistake is to use a single bucket keyed on the *combination* of IP and username (e.g., `login:<ip>:<user>`). This creates one bucket per pair, which means a single IP can attempt the threshold against an unlimited number of usernames before any limit fires — exactly the credential-stuffing pattern you were trying to stop. Always check the two buckets separately.

When a limit is hit, return a generic `429 Too Many Requests`. Avoid `Retry-After` values precise enough to schedule retries against. Do not include diagnostic detail (which bucket fired, remaining attempts) — that information is useful only to attackers tuning their tooling.

## Device and Network Fingerprinting (Privacy-Aware)

Fingerprinting helps detect bots that rotate IPs but reuse client environments. Use **passive, network-level** signals first; resort to client-side fingerprinting only when necessary.

Network signals (no client cooperation needed):

- **JA3 / JA4** — TLS ClientHello fingerprint. Headless tooling often produces uncommon JA3 values.
- **HTTP/2 fingerprint (Akamai)** — frame ordering, settings, priorities.
- **Client Hints (`Sec-CH-UA-*`)** — declared but verifiable against TLS fingerprint.

Browser-side signals (last resort, with consent where required):

- WebGL renderer string, canvas hash, font list, audio context — strong but invasive.
- Page-level behavioral telemetry (mouse paths, scroll, focus) — collect only on sensitive flows.

**Privacy guidance:**

- Document fingerprinting in your privacy notice; some jurisdictions (EU/UK ePrivacy, CCPA) require disclosure or opt-out.
- Hash or truncate any fingerprint before storage; do not retain raw values that enable re-identification.
- Set short retention windows (hours to days) for anti-bot signals — long enough to detect, short enough to limit surveillance risk.
- Avoid fingerprinting authenticated, low-risk traffic (a logged-in user reading their own profile does not need to be fingerprinted again).

## CAPTCHA and Its Modern Alternatives

Visible CAPTCHAs (image grids, distorted text) are accessibility-hostile, machine-solvable by ML, and outsourced to human solver farms for fractions of a cent per solve. Treat them as a **last-resort step-up**, not a primary defense.

Prefer the following alternatives or layer them:

- **Cryptographic attestation tokens** — Privacy Pass (RFC 9576), Apple Private Access Tokens, and emerging device-attestation APIs. The client proves "I am a real device on a known platform" without identifying the user.
- **Invisible risk scoring** — Cloudflare Turnstile, reCAPTCHA v3, hCaptcha Enterprise. The provider returns a score; you decide the threshold.
- **Proof of Work (PoW)** — the client must compute a hash that costs single-digit milliseconds for a human but accumulates significantly across thousands of bot requests. Useful for unauthenticated, expensive endpoints.
- **WebAuthn / Passkeys** — for high-value flows, possession of a registered authenticator is a far stronger bot signal than any CAPTCHA.

Example Proof of Work challenge (server side):

```javascript
import { randomBytes, createHash } from 'crypto';

// Issue: client receives `challenge` and must find a `nonce`
// such that sha256(challenge || nonce) starts with N zero bits.
function issuePoW(difficultyBits = 18) {
  return {
    challenge: randomBytes(16).toString('hex'),
    difficulty: difficultyBits,
    expiresAt: Date.now() + 60_000,
  };
}

function verifyPoW(challenge, nonce, difficultyBits) {
  const hash = createHash('sha256')
    .update(challenge + nonce)
    .digest();
  // Count leading zero bits.
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) { bits += 8; continue; }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits >= difficultyBits;
}
```

Tune `difficultyBits` so a real client spends a few hundred milliseconds; raise it under attack.

## Honeypots and Tarpits

Cheap, effective, and zero impact on legitimate users.

- **Hidden form fields** — a `<input type="text" name="website" />` styled `display:none` and labeled "leave blank." Bots fill it; humans do not. Reject the submission.
- **Robots.txt traps** — disallow a bait path in `robots.txt`; treat any traffic to it as malicious (well-behaved crawlers respect the directive; abusive ones do not).
- **Tarpitting** — for detected bots, do not return `403`. Slow responses progressively (e.g., `setTimeout(send, 5000 + jitter)`). The bot's throughput collapses without telegraphing detection.
- **Canary content** — embed unique, watermarked records on listing pages. If they appear elsewhere, you have proof of scraping and a fingerprint of the scraper.

```html
<!-- Honeypot field. Real users never see or fill this. -->
<div aria-hidden="true" style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden;">
  <label for="company_url">Leave this field empty</label>
  <input type="text" id="company_url" name="company_url" tabindex="-1" autocomplete="off" />
</div>
```

Server side: if `company_url` is non-empty, silently drop the request or route to a tarpit.

## Defending Specific Flows

### Account creation (OAT-019)

- Verify email **before** the account is usable; do not just send a confirmation, gate features behind it.
- Check email against disposable-domain lists (refresh weekly).
- For phone verification, check the carrier type — VoIP numbers are abundant and cheap.
- Apply a per-IP, per-ASN, per-device-fingerprint signup velocity limit (e.g., 3 per hour).
- Reject signup if the email's local-part has high entropy and recent-creation domain.

### Login (OAT-008)

- Apply per-username **and** per-IP limits with separate windows.
- Check the submitted password against breach corpora (e.g., HaveIBeenPwned k-Anonymity API) — do not block, but require a step-up.
- On suspicious patterns, require MFA even for low-risk users.
- See the [Credential Stuffing Prevention Cheat Sheet](Credential_Stuffing_Prevention_Cheat_Sheet.md) for full guidance.

### Inventory / scalping (OAT-005, OAT-015)

- **Waiting room / virtual queue** for limited drops — randomized admission, tokens bound to session and identity.
- **Per-account purchase limits** enforced server side, including identity proxies (same payment method, same shipping address, same device).
- **Hold time** — inventory in cart must be paid for within N seconds or released; prevents cart-camping.
- **Address and payment dedup** at order time using normalized hashes (street + zip, BIN + last4 + holder hash).

### Public APIs

- API keys with rotating secrets, **not** static bearer tokens checked in to client code.
- Per-key quotas advertised in `X-RateLimit-*` headers so well-behaved clients self-throttle.
- Request signing (e.g., HMAC of method + path + timestamp + body) to prevent replay and require a stable secret.
- Tier APIs explicitly: a public catalogue endpoint may serve cached, slightly-delayed data; partner APIs serve realtime data with an authenticated key.

## Response Strategy: Don't Always Block

Hard blocks teach attackers what worked. A graduated response is more durable.

| Confidence | Response |
|---|---|
| Low (suspicious) | Log; serve normally; flag the session |
| Medium | Step-up: CAPTCHA, MFA, or PoW challenge |
| High | Tarpit (slow responses), serve stale or randomized data |
| Very high | Soft-block specific actions (e.g., disable checkout, allow browsing) |
| Confirmed abuse | Account hold + manual review; do not delete to allow forensics |

For scrapers specifically, returning **plausible but slightly wrong data** (price ±1%, fake stock counts) poisons the dataset and is often more damaging to the business case for scraping than a 403.

## Logging and Monitoring

Bot incidents are detected post-hoc almost as often as in real time. Log enough to investigate.

For each request to a sensitive endpoint, capture:

- Timestamp, request ID, route, status code.
- Client IP, ASN, country.
- TLS fingerprint (JA3/JA4) and HTTP/2 fingerprint.
- User-Agent (raw, plus parsed family/version).
- Authenticated identity (or session ID hash).
- Decision and signals (e.g., `bot_score=0.87`, `rule=login_velocity`).

Mask credentials and PII in logs (see the [Logging Cheat Sheet](Logging_Cheat_Sheet.md)).

Build dashboards for: requests-per-second by endpoint, 4xx/5xx rate, fail rate by route, signup-to-purchase funnel, login success rate. Sudden shifts (more than 3-sigma) on these are bot signals.

```python
# Minimal structured log record for an anti-bot decision.
import json, hashlib, time

def log_decision(req, score, decision, rule):
    record = {
        "ts": int(time.time() * 1000),
        "route": req.path,
        "ip": req.remote_addr,
        "asn": req.headers.get("X-ASN"),  # set by your edge
        "ja4": req.headers.get("X-TLS-JA4"),
        "ua": req.headers.get("User-Agent"),
        "session": hashlib.sha256(
            (req.cookies.get("sid") or "").encode()
        ).hexdigest()[:16],
        "score": score,
        "decision": decision,   # allow | challenge | tarpit | block
        "rule": rule,
    }
    print(json.dumps(record))
```

## Privacy and Compliance

Anti-bot defenses collect data. Treat them like any other data-processing activity.

- Document the lawful basis (legitimate interest is typical) and the categories of data collected.
- Apply **data minimization**: collect what you need to score the request and discard the rest.
- Set a short retention period for raw signals; aggregate for longer-term analytics.
- If you use a third-party anti-bot vendor, list them as a sub-processor and review their DPIA.
- Do not block users solely because their browser is hardened (privacy-respecting users often look "bot-like"). Prefer challenge to block.
- Provide an accessible alternative when challenging users with CAPTCHAs (audio CAPTCHA, support contact).

## Anti-Patterns to Avoid

- Blocking all traffic with non-standard User-Agents — breaks legitimate research, accessibility, and integration tools.
- Relying solely on a single edge vendor "magic box" — when it tunes wrong, your entire site goes down or opens up.
- Storing raw fingerprints indefinitely.
- CAPTCHAs at every login attempt — destroys conversion and trains users to solve mechanically.
- "Hidden" anti-bot rules with no logging — you cannot tune what you cannot see.
- Hard-blocking on first signal, with no graduated response — gives attackers a clean signal to iterate against.

## Checklist

- [ ] Map application endpoints to the OWASP Automated Threats (OAT) catalogue.
- [ ] Apply rate limits at IP, identity, and endpoint levels, using a sliding window.
- [ ] Layer defenses across edge, application, and business logic.
- [ ] Use TLS/HTTP-level fingerprints before resorting to browser fingerprinting.
- [ ] Replace visible CAPTCHAs with attestation tokens, invisible scoring, or PoW where possible.
- [ ] Add honeypot fields and tarpit responses for high-confidence detections.
- [ ] Verify email and phone numbers at signup; track signup velocity.
- [ ] Enforce per-account purchase, address, and payment-method limits on scarce inventory.
- [ ] Sign API requests; advertise quotas via `X-RateLimit-*` headers.
- [ ] Log decisions with signals; build anomaly dashboards.
- [ ] Mask PII and rotate raw signal storage on a short schedule.
- [ ] Document anti-bot processing in your privacy notice.
- [ ] Provide accessibility alternatives to any user-facing challenge.

## References

- [OWASP Automated Threats to Web Applications (OAT)](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [OWASP Credential Stuffing Prevention Cheat Sheet](Credential_Stuffing_Prevention_Cheat_Sheet.md)
- [OWASP Logging Cheat Sheet](Logging_Cheat_Sheet.md)
- [OWASP Authentication Cheat Sheet](Authentication_Cheat_Sheet.md)
- [OWASP Multifactor Authentication Cheat Sheet](Multifactor_Authentication_Cheat_Sheet.md)
- HaveIBeenPwned — [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
