# Webhook Security Cheat Sheet

## Introduction

Webhooks are HTTP callbacks: a **publisher** pushes event notifications to a URL that a **subscriber** registered, so both parties run HTTP servers ([Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#what-are-webhooks)). A webhook endpoint is therefore a public, unauthenticated `POST` handler unless you add the authentication yourself, and a publisher that delivers to user-supplied URLs is an outbound request engine that attackers will try to aim at your internal network.

This cheat sheet covers both sides. It shows how to prove that a delivery is genuine, stop replays and duplicate processing, keep signing secrets safe, and prevent the publisher from being used as a proxy.

## Threat Model Summary

Forged deliveries are the headline threat: without verification, an attacker can post fake events that trigger order fulfillment, account access, or record changes, as [Stripe's webhook documentation](https://docs.stripe.com/webhooks#verify-events) warns. Signature verification is the first control to implement; the others close the gaps it leaves.

| Threat | Primary control |
|---|---|
| Forged events | Hash-based message authentication code using SHA-256 (HMAC-SHA256), verified on every delivery |
| Replay of a captured delivery | Authenticated timestamp with a tolerance window plus authenticated event-ID deduplication, where the publisher's protocol supports them |
| Signing secret leakage | Secrets manager, one secret per webhook, log redaction, immediate revocation and replacement |
| Server-side request forgery (SSRF) through a subscriber-supplied callback URL | `https://`-only scheme allowlist plus a deny-list of every non-public address range, enforced on the resolved IP at connect time |
| Denial of service | Rate limiting, payload size limit, asynchronous processing |
| Duplicate processing | Idempotent handlers keyed on the event ID |
| Eavesdropping or tampering in transit | Transport Layer Security (TLS) 1.2 or higher with a certificate from a trusted certificate authority (CA) |
| Malicious payload content | Schema validation, then parameterized queries and output encoding downstream |

## Authenticating Deliveries

### Transport Security

- Require HTTPS on every webhook endpoint and reject plain HTTP. A signature proves authenticity but does not encrypt the payload, so anyone on the network path can read an unencrypted delivery ([Standard Webhooks: Enforcing HTTPS](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#enforcing-https)).
- Enforce TLS 1.2 or higher with a certificate from a trusted CA. Large publishers already refuse anything weaker: [Stripe](https://docs.stripe.com/webhooks#receive-events-with-an-https-server) validates the subscriber's certificate and only negotiates TLS 1.2 and 1.3.
- As a publisher, verify the subscriber's certificate on every delivery. GitHub, which lets users turn this check off, [recommends leaving SSL verification enabled](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#use-https-and-ssl-verification).
- Protocol version and cipher suite configuration is covered in the [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md).

### Signature Verification

Signing lets the subscriber confirm that a delivery came from the legitimate publisher and that the body was not modified in transit.

Publisher:

- Generate a cryptographically random signing secret for each registered webhook. 32 bytes is a sound default; the [Standard Webhooks signature scheme](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#signature-scheme) specifies 24 to 64 bytes.
- For a new protocol, use a documented signature scheme that authenticates the event ID, delivery timestamp, and raw request body together, such as [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#signature-scheme). Existing providers use different formats: [GitHub](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#validating-webhook-deliveries) signs the raw body only; [Stripe](https://docs.stripe.com/webhooks#verify-signature) signs the timestamp and body, including the event ID in that body.
- During planned secret rotation, sign with every active secret and send one signature per secret (see Secret Rotation below).

Subscriber:

- Use the publisher's maintained verification library when available and follow its exact signing format. Supply the raw request body before your framework parses it. Re-serializing JSON, reordering fields, changing whitespace or line endings, or converting the character encoding all invalidate the signature ([Stripe](https://docs.stripe.com/webhooks#verify-signature)).
- Recompute the HMAC and compare it with a constant-time function such as `hmac.compare_digest`, `crypto.timingSafeEqual`, or `MessageDigest.isEqual`. Never use `==`: it leaks timing information and can turn the endpoint into a signing oracle ([GitHub](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#validating-webhook-deliveries), [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#verifying-signatures)).
- When the header carries several signatures, accept the delivery if any one of them matches. Publishers send one signature per active secret during rotation, and this rule is what makes rotation safe in either order ([Standard Webhooks: Webhook headers](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#webhook-headers-sending-metadata-to-consumers)).
- Accept only the signature scheme you expect (Stripe's `v1`, for example) and ignore any other scheme in the header, to prevent downgrade attacks ([Stripe](https://docs.stripe.com/webhooks#verify-signature)).
- Return `401` when the signature is missing or does not match, and do not say why.

### Secret Management

A leaked signing secret lets an attacker forge deliveries until it is revoked. Treat webhook secrets like database credentials.

- Store signing secrets in a secrets manager and never hard-code them in source, configuration files, or container images ([GitHub: Securely storing the secret token](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#securely-storing-the-secret-token)). See the [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md).
- Use a distinct secret per registered webhook so one leak exposes one integration; Stripe, for example, [generates a unique secret for each endpoint](https://docs.stripe.com/webhooks#endpoint-secrets).
- Redact secrets and signature header values from logs and error responses.

#### Secret Rotation

On suspected compromise, revoke the old secret immediately and replace it, following the Secrets Management Cheat Sheet's [incident response guidance](Secrets_Management_Cheat_Sheet.md#92-remediation). Accepting a compromised secret during an overlap still permits forged deliveries.

For planned rotation, an overlap window in which both secrets are valid avoids failed deliveries. Stripe supports immediate expiration or an overlap of [up to 24 hours](https://docs.stripe.com/webhooks#roll-endpoint-secrets), signing with every active secret during that time. To rotate:

- Generate the new secret.
- Configure the publisher to sign with both secrets and send both signatures.
- Load the new secret on the subscriber. Because the subscriber already accepts any matching signature, the two sides can switch in either order inside the window.
- Once deliveries verify with the new secret, revoke the old one.
- Return `401` for deliveries signed only with a revoked secret.

### Additional Authentication (Defense in Depth)

HMAC signing authenticates the payload, not the connection. Layer one of these on top when a leaked signing secret must not be enough to reach the endpoint:

| Method | When to use |
|---|---|
| Mutual TLS (mTLS) | High-assurance machine-to-machine pipelines; see [Client Certificates and Mutual TLS](Transport_Layer_Security_Cheat_Sheet.md#client-certificates-and-mutual-tls) |
| Static bearer token or API key | Simple integrations; store it in the secrets manager and rotate it like a signing secret |
| OAuth 2.0 client credentials | When both parties support OAuth, use the [client credentials grant](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4) to obtain an access token. Validate it using the authorization server's supported mechanism and require permission to deliver to this webhook. For JSON Web Token (JWT) access tokens using the [RFC 9068 profile](https://www.rfc-editor.org/rfc/rfc9068.html#section-4), apply its complete validation rules, including token type; see the [OAuth2 Cheat Sheet](OAuth2_Cheat_Sheet.md) |
| IP allowlisting | Extra layer only. Publishers such as [Stripe](https://docs.stripe.com/webhooks#verify-events) and [GitHub](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#allow-githubs-ip-addresses) publish their delivery addresses, but ranges change and a shared egress IP is not proof of identity |

## Replay, Duplicates, and Abuse

### Replay Attack Protection

A captured delivery carries a valid signature, so signature verification alone does not stop repeated processing. For protocols with authenticated delivery timestamps and event IDs, such as [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#signature-scheme):

- Publisher: include a Unix timestamp in the signed material, send it next to the signature, and generate a fresh timestamp and signature for every retry ([Stripe: Preventing replay attacks](https://docs.stripe.com/webhooks#replay-attacks)).
- Subscriber: reject deliveries whose authenticated timestamp differs from your clock by more than a small tolerance. Five minutes is the default in Stripe's libraries; keep your clock synchronized with Network Time Protocol (NTP) so the window is meaningful.
- Subscriber: after signature and freshness validation, cache authenticated event IDs to prevent repeated processing inside the window ([Standard Webhooks: Verifying signatures](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#verifying-signatures)). Keep each ID for at least twice the tolerance, 10 minutes for a 5-minute window: a delivery whose timestamp is 5 minutes ahead of your clock is accepted now and stays acceptable for another 10 minutes. This short replay cache does not replace the persisted processing record described below.

[GitHub's body-only signature](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#validating-webhook-deliveries) does not authenticate a delivery timestamp or the `X-GitHub-Delivery` header. That header helps identify ordinary redeliveries but does not provide the authenticated replay guarantee above. Follow the provider's documented protocol and make downstream effects idempotent.

### Idempotency and Duplicate Events

Publishers retry on failure, Stripe for [up to three days with exponential backoff](https://docs.stripe.com/webhooks#automatic-retries), so every endpoint receives some events more than once. Processing a payment or sending a notification twice causes real harm.

- After verifying the delivery, persist processed event IDs and skip repeats ([Stripe: Handle duplicate events](https://docs.stripe.com/webhooks#handle-duplicate-events)). Retain this record across the publisher's retry period. GitHub's [`X-GitHub-Delivery`](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#use-the-x-github-delivery-header) identifies ordinary redeliveries but is not a signed event ID.
- Return `200` for an authenticated duplicate that has already been durably queued or processed; do not repeat its side effects.
- Make downstream side effects (database writes, emails, payments) idempotent by default.
- Do not assume in-order delivery. Fetch the object's current state from the publisher's API when an event may be stale. Use a sequence or version field only when the publisher documents its ordering guarantees; timestamps alone may not establish order ([Stripe: Event ordering](https://docs.stripe.com/webhooks#event-ordering)).

### Rate Limiting

Without limits, a misconfigured publisher or an attacker can flood the endpoint. Both sides need protection.

- Publisher: apply per-subscriber delivery limits, exponential backoff with jitter, and a maximum retry count, and disable endpoints that keep failing for days ([Standard Webhooks: Deliverability and reliability](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#deliverability-and-reliability)).
- Subscriber: rate limit at the API gateway or application layer and answer excess traffic with `429 Too Many Requests` and a `Retry-After` header ([RFC 6585 section 4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4)).
- Subscriber: acknowledge fast and process through an asynchronous queue. GitHub expects a `2xx` [within 10 seconds](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#respond-within-10-seconds), and Stripe recommends [an asynchronous queue](https://docs.stripe.com/webhooks#handle-events-asynchronously) to absorb delivery spikes.
- Subscribe only to the event types you handle; listening for everything multiplies load and hands you data you never needed to hold ([GitHub: Subscribe to the minimum number of events](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#subscribe-to-the-minimum-number-of-events)).

### SSRF Prevention (Publisher Side)

When subscribers register their own callback URLs, an attacker registers an internal address or the cloud metadata endpoint and uses your delivery workers as a proxy into your network. Webhook senders are [especially exposed](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#server-side-request-forgery-ssrf) because accepting arbitrary URLs is the feature.

- Allowlist the scheme: accept `https://` only.
- Block every non-public destination: resolve the hostname and reject any address that is not globally reachable, at minimum the deny-list in the [Server-Side Request Forgery Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#deny-list-last-resort) including the IPv6 equivalents, plus internal hostnames such as `metadata.google.internal`. The IANA [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry) special-purpose address registries include both globally reachable and non-globally-reachable ranges; consult each entry's Globally Reachable field.
- Validate the address you actually connect to. Re-resolving the name just before the request does not close the DNS rebinding gap, because the HTTP client resolves it again when it connects and can receive a different answer. Either resolve once, validate the IP, and connect to that exact IP while sending the original hostname in the `Host` header and Server Name Indication (SNI), or validate inside the client's connect hook using the same lookup for validation and connection. The [DNS pinning guidance in the SSRF cheat sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#case-2---application-can-send-requests-to-any-external-ip-address-or-domain-name) covers this case.
- Disable redirects, or apply the same checks to every redirect target. Stripe simply [treats redirect responses as failed deliveries](https://docs.stripe.com/webhooks#fix-http-status-codes).
- Isolate delivery workers or their egress proxy in a network segment that cannot reach internal services, as recommended by [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#server-side-request-forgery-ssrf). An egress proxy such as [Smokescreen](https://github.com/stripe/smokescreen) can enforce destination checks.

## Endpoint Hardening

### Input Validation

- A valid signature proves who sent the payload, not that its contents are safe. Enforce a maximum body size, reject unexpected `Content-Type` values, and validate against a strict schema before processing, following the REST Security Cheat Sheet's [Input validation](REST_Security_Cheat_Sheet.md#input-validation) and [Validate content types](REST_Security_Cheat_Sheet.md#validate-content-types) sections. Publishers should keep payloads small; the Standard Webhooks specification recommends [under 20 KB](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md#payload-size).
- Downstream, use parameterized queries for SQL ([Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md)) and context-appropriate output encoding wherever payload fields are rendered as HTML ([Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)).

### HTTP Method Restriction

- Accept `POST` only and answer every other method with `405 Method Not Allowed`, as described in [Restrict HTTP methods](REST_Security_Cheat_Sheet.md#restrict-http-methods) in the REST Security Cheat Sheet.

### Cross-Site Request Forgery (CSRF) Considerations

- Exempt the webhook route, and only that route, from framework CSRF token checks: the publisher is a server that cannot obtain a token, so the check only blocks legitimate deliveries ([Stripe: Exempt webhook route from CSRF protection](https://docs.stripe.com/webhooks#csrf-protection)).
- Put signature verification in place before granting the exemption; it is the replacement control. See the [Cross-Site Request Forgery Prevention Cheat Sheet](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

### Fail Securely

- Return `200` only after the event is durably queued or processed, `400` for malformed payloads, and `401` for signature failures, with a generic body and no stack traces or internal detail, as in the REST Security Cheat Sheet's [Error handling](REST_Security_Cheat_Sheet.md#error-handling) section.
- Route events that repeatedly fail processing to a dead-letter queue and alert on it instead of dropping them.

### Logging and Monitoring

Logs are how you detect probing and diagnose integration failures, but full payloads and secrets must stay out of them.

- Log the timestamp, source IP, HTTP method, response status, event ID, event type, and processing latency.
- Do not log full request bodies (they often contain personal data), signing secrets, or `Authorization` and signature header values; see [Data to exclude](Logging_Cheat_Sheet.md#data-to-exclude) in the Logging Cheat Sheet.
- Alert on spikes in signature failures (someone is probing the endpoint), sustained `4xx` or `5xx` responses (processing failure or misconfiguration), and deliveries from unexpected source addresses.

## Quick Reference Checklist

Stripe's and GitHub's best-practice pages ([Stripe](https://docs.stripe.com/webhooks#best-practices), [GitHub](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)) cover the subscriber side of their own platforms; use this table to check both sides of any integration.

| Control | Publisher | Subscriber |
|---|---|---|
| TLS 1.2 or higher with a trusted CA certificate | Yes | Yes |
| HMAC-SHA256 signature on every delivery | Sign | Verify with a constant-time comparison |
| One secret per webhook, stored in a secrets manager | Yes | Yes |
| Planned rotation with an overlap window | Sign with every active secret | Accept any matching signature |
| Compromised secret | Revoke and replace immediately | Stop accepting the revoked secret |
| Authenticated timestamp and event ID | Include when designing the protocol | Enforce freshness and deduplication where supported by the provider |
| Replay cache retention | n/a | At least twice the timestamp tolerance; keep a separate processing record across retries |
| Idempotent, order-independent processing | n/a | Yes |
| SSRF checks on callback URLs at connect time | Yes | n/a |
| Rate limiting | Throttle, back off, cap retries | `429` plus an asynchronous queue |
| Payload size limit and schema validation | Keep payloads small | Yes |
| `POST` only, `405` for other methods | n/a | Yes |
| Generic errors: `400` malformed, `401` bad signature | n/a | Yes |
| Structured logs without secrets or full bodies | Yes | Yes |

## Security Testing

Run these tests before going to production and after any change to webhook handling code:

- Missing or invalid signature: the endpoint returns `401`, not `200`.
- Replay protection: for protocols with authenticated timestamps and event IDs, verify that stale deliveries fail freshness checks and an already accepted event cannot trigger side effects twice. A valid duplicate already durably queued or processed receives `200`.
- Duplicate event ID: deliver the same event twice and confirm it is processed once. GitHub's redelivery feature reuses the original [`X-GitHub-Delivery`](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks#use-the-x-github-delivery-header) value, which makes it a convenient duplicate test.
- Oversized payload: exceed your size limit and expect `400` or `413`.
- SSRF (publisher side): register an `http://` URL, `https://169.254.169.254/`, `https://127.0.0.1/`, an internal hostname, and a public hostname that resolves to a private address; every one must be rejected at registration or blocked at delivery time. [WSTG-INPV-19](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery/) describes the test cases and the filter bypasses to try, such as alternative IP encodings.
- Secret rotation: both secrets are accepted during planned overlap; a revoked or compromised secret is no longer accepted.
- Use the publisher's own test tooling where it exists, such as [`stripe trigger`](https://docs.stripe.com/webhooks#trigger-test-events), to exercise the handler with genuine signed deliveries.

## References

- [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
- [Stripe: Receive Stripe events in your webhook endpoint](https://docs.stripe.com/webhooks)
- [GitHub: Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [GitHub: Best practices for using webhooks](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry)
- Related OWASP cheat sheets: [Transport Layer Security](Transport_Layer_Security_Cheat_Sheet.md), [Secrets Management](Secrets_Management_Cheat_Sheet.md), [Server-Side Request Forgery Prevention](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md), [REST Security](REST_Security_Cheat_Sheet.md), [Input Validation](Input_Validation_Cheat_Sheet.md), [Injection Prevention](Injection_Prevention_Cheat_Sheet.md), [Query Parameterization](Query_Parameterization_Cheat_Sheet.md), [Cross Site Scripting Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md), [Cross-Site Request Forgery Prevention](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md), [Logging](Logging_Cheat_Sheet.md), [OAuth2](OAuth2_Cheat_Sheet.md), [Denial of Service](Denial_of_Service_Cheat_Sheet.md), [Threat Modeling](Threat_Modeling_Cheat_Sheet.md)
