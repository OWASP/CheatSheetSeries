# Micro-Frontend Security Cheat Sheet

## Introduction

Micro-frontends combine independently deployed features in a host application, also called a shell. Separate repositories and deployment teams do not create browser security boundaries: the [same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy) separates origins, not individual features within a page.

This cheat sheet covers the security decisions involved in composing these applications:

- Choose which features may share the host's browser privileges.
- Limit communication and data sharing between applications.
- Enforce authorization on the server for every request.
- Control which remote code each host release loads.

For general browser security controls, see the [Web Frontend Security Cheat Sheet](Web_Frontend_Security_Cheat_Sheet.md).

## Choose and Enforce Runtime Boundaries

Document the origin, deployment owner, and required data access of each micro-frontend before choosing a composition mechanism.

| Composition | Security decision |
| --- | --- |
| Remote JavaScript loaded into the host, including Module Federation | Trust the remote with the host page's privileges. A different download origin does not sandbox the executing code. |
| Web Components in the host page | Treat components as part of the same application. Shadow DOM (Document Object Model) and scoped styles do not isolate their scripts from the host. |
| Cross-origin iframe | Use when the feature must be separated from the host's DOM and origin storage. Restrict its capabilities and explicitly control messages crossing the boundary. |
| HTML fragments assembled on a server or at the edge | Review fragments and their scripts as host content. Assembly before delivery does not create a browser isolation boundary. |

### Isolate Features with Different Trust Levels

Serve a less-trusted feature from a dedicated origin in an iframe. Apply an [iframe sandbox](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#sandbox), granting only capabilities the feature requires. Leave top-level navigation and popup permissions disabled unless necessary.

Do not combine `allow-scripts` and `allow-same-origin` for content on the host's own origin; that combination can let the embedded application remove its sandbox. `allow-same-origin` preserves the frame's original origin; it does not make a cross-origin frame same-origin with the host.

Without `allow-same-origin`, a sandboxed document has an opaque origin, reported as `"null"` in messages. Do not trust `"null"` as a sender identity. If sensitive messaging requires an identifiable origin, use a dedicated cross-origin frame with a sandbox policy that preserves that origin.

Origin separation limits direct access to the host's DOM and storage. It does not authorize backend requests or make data deliberately sent to the frame confidential from that frame.

### Control Remote Code and Deployments

For remotes executing in the host page, treat permission to publish a remote as permission to change the host's running application:

- Load only approved HTTPS remote URLs from host-controlled configuration. Do not let query parameters or other untrusted input choose executable code.
- Select immutable, reviewed releases, including entry scripts and their dependent chunks. Keep a known-good release available for rollback.
- Separate deployment credentials for the shell and each remote. This limits direct changes to other deployments, but does not contain a compromised remote already trusted to execute in the shell. See the [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md).
- Use [Subresource Integrity](Third_Party_Javascript_Management_Cheat_Sheet.md#subresource-integrity) where the loader supports it. Verify coverage of dynamically loaded chunks; checking an entry script alone does not verify everything it later loads. Integrity checks detect changed bytes, not malicious behavior in an approved release.
- Apply the host's [Content Security Policy (CSP)](Content_Security_Policy_Cheat_Sheet.md) to remote loading. A permitted script source is still trusted code; CSP does not isolate one allowed micro-frontend from another.

## Restrict Cross-Application Communication

Apply the general [web messaging guidance](HTML5_Security_Cheat_Sheet.md#web-messaging) to every host/frame pair: set an exact `targetOrigin`, match `event.origin` exactly, and validate message data. In addition, following the [postMessage security guidance](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns):

- Define a small message contract for each pair. Accept only the message types and payload fields that the receiving feature needs.
- Check `event.source` against the expected frame's `contentWindow` or the expected parent window, not only the origin. Several frames can share one origin.
- Pass the minimum data needed for the operation. Avoid broadcasting credentials or sensitive state to every feature.

These checks identify the sending origin and window, not the current user's permissions. A message requesting a privileged operation must still lead to server-side authorization. They also do not protect against compromised code running inside the expected sender.

A shared in-page event bus has no browser-enforced identity boundary between its participants. Do not use event names or application identifiers as proof of authority.

## Enforce Backend Authorization and Limit Shared Data

### Authorize Every Request on the Server

Neither the shell nor a remote micro-frontend can enforce authorization in client-side code. Route guards, hidden controls, and client-side role checks only affect presentation and can be bypassed.

Enforce permissions for the requested operation, resource, and tenant on every backend request, regardless of which frontend initiated it. Do not trust a role, tenant identifier, or permission flag supplied by the shell or a remote. Use a shared server-side policy where appropriate so independently developed features apply consistent checks. See the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md#validate-the-permissions-on-every-request).

### Keep Sensitive State Out of Shared Runtimes

Browser storage is [separated by origin](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy#cross-origin_data_storage_access). Storage key prefixes, separate state stores, and component boundaries do not provide security isolation between scripts in the same page. Treat data exposed in the page or origin storage as available to every remote executing there.

Keep session identifiers out of `localStorage` and `sessionStorage`. When using a backend-for-frontend, keep upstream access tokens on the server and use a session cookie configured according to the [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md#cookies). An `HttpOnly` cookie prevents JavaScript from reading the cookie, but compromised code in the host can still make authenticated requests. Apply [cross-site request forgery protection](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) to cookie-authenticated operations.

Return only data the authenticated user is authorized to access. Clear shared state and cached responses on logout or tenant changes to avoid displaying stale data. This cleanup does not replace backend tenant checks or protect information already exposed to a compromised remote.

## References

- [MDN: Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Same-origin_policy)
- [MDN: postMessage Security Concerns](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns)
- [MDN: iframe Sandbox](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#sandbox)
