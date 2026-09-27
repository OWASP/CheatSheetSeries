# Webhook Security Guidelines Cheat Sheet

## Introduction

Webhooks are HTTP callbacks that allow a server to push event notifications to a registered client endpoint. Because they accept unauthenticated inbound HTTP traffic by default, every layer of the delivery pipeline must be deliberately hardened.

Security controls apply to **both sides**: the publisher (sending events) and the subscriber (receiving and processing events).

---

## Threat Model Summary

| Threat | Primary Control |
|---|---|
| Spoofed / forged events | HMAC signature verification |
| Replay attack | Timestamp + event-ID deduplication |
| Secret leakage | Secrets manager, log redaction |
| SSRF via callback URL | IP/hostname allowlisting on publisher |
| Denial of service | Rate limiting, async queues |
| Duplicate processing | Idempotent event handlers |
| Man-in-the-middle | TLS 1.2+ with valid CA certificate |
| Payload injection | Input validation, schema enforcement |

---

## Controls

### 1. Transport Security

All webhook traffic must be encrypted in transit. An unencrypted connection allows any network observer to read payloads and steal signing secrets.

- **Require HTTPS** on every webhook endpoint — reject plain HTTP.
- Enforce **TLS 1.2 or higher**; disable TLS 1.0/1.1 and weak cipher suites.
- Use a certificate from a trusted CA — reject self-signed certificates in production.
- As a publisher, validate the subscriber's certificate before delivery.

See [Transport Layer Security Cheat Sheet](../cheatsheets/Transport_Layer_Security_Cheat_Sheet.md).

---

### 2. Signature Verification (HMAC)

Signing lets the subscriber confirm that a delivery came from the legitimate publisher and that the body was not tampered with.

**Publisher:**

- Generate a random signing secret (≥ 32 bytes) per registered webhook.
- Compute `HMAC-SHA256` over the raw request body (include a timestamp — see Section 5).
- Send the hex digest in a dedicated header (e.g., `X-Hub-Signature-256`).

**Subscriber:**

- Read the **raw** request body _before_ your framework parses it.
- Recompute the HMAC locally and compare using a **constant-time function** (`hmac.compare_digest`, `MessageDigest.isEqual`) — never use `==`.
- Return `401` on mismatch; do not reveal why validation failed.

> ❌ String equality comparison (`sig == expected`) is vulnerable to timing attacks.

#### Canonicalization Pitfalls

Verify signatures against the **exact raw bytes received**. Any transformation before verification can invalidate the signature.

Do not:

- Reformat or pretty-print JSON
- Reorder fields
- Change whitespace or line endings
- Convert character encodings

---

### 3. Secret Management

A compromised signing secret lets an attacker forge valid webhook deliveries indefinitely. Treat webhook secrets with the same care as database credentials or API keys.

- Store signing secrets in a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager). See [Secrets Management Cheat Sheet](../cheatsheets/Secrets_Management_Cheat_Sheet.md).
- **Never** hard-code secrets in source code, config files, or container images.
- Use **per-webhook secrets** — a single shared secret is a single point of failure.
- Redact secrets from all logs and error responses.

#### Secret Rotation

Abrupt rotation causes delivery failures if the new secret is deployed before the subscriber has updated. Use a **dual-secret window** to avoid downtime:

1. Generate the new secret.
2. Configure the publisher to sign with both old and new secrets (or include both signatures in the header).
3. Update the subscriber to accept either.
4. After confirming delivery with the new secret, revoke the old one.
5. Return `4xx` on requests signed only with the revoked secret.

---

### 4. Authentication (Defence in Depth)

HMAC signing verifies payload integrity but does not authenticate the transport connection itself. Layering an additional authentication mechanism limits exposure if a signing secret is ever compromised.

Layer one or more of the following on top of HMAC signing:

| Method | When to Use |
|---|---|
| **Mutual TLS (mTLS)** | High-assurance, machine-to-machine pipelines |
| **Bearer token / API key** | Simple integrations; store in secrets manager, rotate regularly |
| **OAuth 2.0** | User-delegated flows; validate `exp`, `aud`, `iss` on every request |
| **IP allowlisting** | Additional layer; fragile when publisher IPs rotate — not a sole control |

See [OAuth2 Cheat Sheet](../cheatsheets/OAuth2_Cheat_Sheet.md) for OAuth-specific guidance.

---

### 5. Replay Attack Protection

A valid captured request can be re-delivered by an attacker. Signature verification alone does not prevent this — a replayed request carries a valid signature. Binding the signature to a short-lived timestamp closes this window.

- Include a Unix timestamp in the signed material; transmit it in the signature header (e.g., `t=<unix_ts>,v1=<digest>`).
- **Reject** requests whose timestamp differs from server time by more than ±5 minutes.
- For higher assurance: cache recently seen event IDs for **at least the length of the timestamp validation window** (e.g., Redis with TTL ≥ 5 minutes) and reject duplicates.

---

### 6. Idempotency and Duplicate Event Handling

Publishers retry on network failures — your endpoint may receive the same event more than once. Processing a payment or sending a notification twice can cause real harm, so idempotency is a correctness concern as much as a security one.

- Use the platform-provided **event ID** (e.g., `event_id`, `delivery_id`) as an idempotency key.
- Persist processed event IDs and skip re-processing on a duplicate.
- Return `HTTP 200` immediately for known duplicates to stop re-delivery.
- Design downstream operations (DB writes, emails, payments) to be **idempotent by default**.

---

### 7. SSRF Prevention (Publisher Side)

When your application delivers webhooks to user-supplied URLs, an attacker can register an internal IP address or cloud metadata endpoint as the target, using your server as a proxy to probe the internal network.

- **Resolve the hostname to an IP before delivery**; block:
    - Loopback: `127.0.0.0/8`, `::1`
    - RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
    - Link-local / Cloud IMDS: `169.254.0.0/16` (includes `169.254.169.254`)
    - Internal DNS names (e.g., `metadata.google.internal`)
- **Re-resolve immediately before the HTTP request** to prevent DNS rebinding.
- **Disable HTTP redirects** or validate every redirect target against the same rules.
- **Allowlist schemes** — accept `https://` only; block `file://`, `gopher://`, `ftp://`, etc.

See [Server-Side Request Forgery Prevention Cheat Sheet](../cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md).

---

### 8. Rate Limiting

Without rate limiting, a misconfigured publisher or a malicious actor can flood your endpoint and cause a denial of service. Both sides of the pipeline need protection.

**Publisher:** Implement per-subscriber delivery rate limits with exponential back-off and a maximum retry count.

**Subscriber:**

- Apply rate limiting at the API gateway or application layer.
- Return `429 Too Many Requests` with a `Retry-After` header when the limit is exceeded.
- Decouple ingestion from processing with an async queue (SQS, Kafka, RabbitMQ) to absorb traffic spikes without dropping events.

---

### 9. Input Validation

Treat every incoming payload as untrusted input regardless of the source IP or a valid signature. A signed payload can still contain malicious field values that exploit downstream processing.

- Reject requests with an unexpected `Content-Type`.
- Enforce a **maximum payload size** to prevent memory exhaustion.
- Validate the payload against a **strict schema** (allowlisted fields, typed values) before processing.
- **Validate before processing and apply context-appropriate output encoding** — e.g., parameterised queries for SQL, escaped output for HTML rendering.

See [Input Validation Cheat Sheet](../cheatsheets/Input_Validation_Cheat_Sheet.md) and [Injection Prevention Cheat Sheet](../cheatsheets/Injection_Prevention_Cheat_Sheet.md).

---

### 10. HTTP Method Restriction

Webhook endpoints should only accept `POST` requests. Allowing other methods unnecessarily expands the attack surface and may expose unintended framework behaviour.

- Accept **only the methods required** — typically `POST`.
- Return `405 Method Not Allowed` for all others.
- Explicitly disable `PUT`, `DELETE`, `PATCH`, `TRACE`, and `OPTIONS` unless needed.

---

### 11. CSRF Considerations

Webhook endpoints must be **exempted from framework CSRF token checks** because the publisher is a server, not a browser, and cannot supply a CSRF token. However, removing CSRF protection without a replacement leaves the endpoint open — HMAC signature verification serves as the functional equivalent.

- Scope the CSRF exemption to the webhook route only — do not disable it globally.
- Ensure HMAC verification is in place before granting the exemption.

---

### 12. Fail Securely

Error responses are visible to the sender. Leaking internal details — exception messages, stack traces, or field names — can aid an attacker in crafting more targeted requests.

- Return `200` only after the event has been acknowledged (queued or processed).
- Return `400` for malformed payloads; `401`/`403` for signature failures.
- **Never** return stack traces or verbose error details in HTTP responses — log them server-side.
- Set up alerting for events that repeatedly fail processing (dead-letter queue).

---

### 13. Logging and Monitoring

Logs are your primary tool for detecting abuse, diagnosing integration failures, and responding to incidents. Log enough to be useful, but avoid logging secrets or full payloads that may contain sensitive customer data.

**Log:**

- Timestamp, source IP, HTTP method, response status, event ID, event type, and processing latency.

**Do NOT log:**

- Full request bodies (may contain PII), signing secrets, or raw `Authorization` header values.

**Alert on:**

- Spike in signature verification failures (may indicate scanning or an attacker probing the endpoint).
- Sustained `4xx`/`5xx` delivery errors (processing failures or upstream misconfiguration).
- Deliveries arriving from unexpected source IPs.

See [Logging Cheat Sheet](../cheatsheets/Logging_Cheat_Sheet.md).

---

### 14. Event Ordering

Webhook events may arrive out of order due to retries, queueing, or network delays. Building your handler assuming in-order delivery leads to subtle data consistency bugs — for example, processing a `payment.failed` event before the corresponding `payment.created`.

- Do not assume chronological delivery order.
- Use event timestamps or sequence numbers in the payload when ordering matters.
- When consistency is critical, fetch the current object state from the publisher API rather than relying solely on the event payload.

---

## Quick Reference Checklist

| Control | Publisher | Subscriber |
|---|---|---|
| TLS 1.2+ with valid CA certificate | ✅ | ✅ |
| HMAC-SHA256 signature on every delivery | ✅ Sign | ✅ Verify (constant-time) |
| Per-webhook secret in secrets manager | ✅ | ✅ |
| Dual-secret rotation window | ✅ | ✅ |
| Timestamp in signed material | ✅ Include | ✅ Enforce ±5 min window |
| Event-ID deduplication (replay protection) | — | ✅ |
| Idempotent event processing | — | ✅ |
| SSRF validation on callback URLs | ✅ | — |
| Rate limiting | ✅ Throttle/backoff | ✅ 429 + async queue |
| Schema validation | — | ✅ |
| POST-only, 405 for others | — | ✅ |
| No verbose errors in responses | — | ✅ |
| Structured logs (no secrets) | ✅ | ✅ |

---

## Security Testing

The following test cases cover the most common webhook security defects. Run these against your implementation before going to production and after any significant change to your webhook handling code.

- **Invalid or missing signature** — endpoint must return `401`, not `200`.
- **Replay attempt** — resubmit a captured request after the tolerance window; endpoint must reject it.
- **Duplicate event ID** — send the same event twice; only one should be processed.
- **Oversized payload** — send a payload exceeding your size limit; endpoint must return `400` or `413`.
- **SSRF callback URL** (publisher side) — attempt to register `http://169.254.169.254/` as a webhook URL; delivery must be blocked.
- **Secret rotation** — verify both the old and new secret are accepted during the dual-secret window, and only the new one is accepted after revocation.

---

## Related OWASP Cheat Sheets

- [Transport Layer Security Cheat Sheet](../cheatsheets/Transport_Layer_Security_Cheat_Sheet.md)
- [Secrets Management Cheat Sheet](../cheatsheets/Secrets_Management_Cheat_Sheet.md)
- [Server-Side Request Forgery Prevention Cheat Sheet](../cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Input Validation Cheat Sheet](../cheatsheets/Input_Validation_Cheat_Sheet.md)
- [Injection Prevention Cheat Sheet](../cheatsheets/Injection_Prevention_Cheat_Sheet.md)
- [Cross-Site Request Forgery Prevention Cheat Sheet](../cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Logging Cheat Sheet](../cheatsheets/Logging_Cheat_Sheet.md)
- [OAuth2 Cheat Sheet](../cheatsheets/OAuth2_Cheat_Sheet.md)
- [Denial of Service Cheat Sheet](../cheatsheets/Denial_of_Service_Cheat_Sheet.md)
- [Threat Modeling Cheat Sheet](../cheatsheets/Threat_Modeling_Cheat_Sheet.md)

---

## References

- [Stripe: Webhook Signature Verification](https://stripe.com/docs/webhooks/signatures)
- [GitHub: Securing Your Webhooks](https://docs.github.com/en/webhooks/using-webhooks/securing-your-webhooks)
- [Standard Webhooks Specification](https://www.standardwebhooks.com/)
- [OWASP SSRF Prevention](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [webhook.site — Testing Tool](https://webhook.site/)
