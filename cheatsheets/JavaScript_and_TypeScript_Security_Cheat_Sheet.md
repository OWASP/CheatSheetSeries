# JavaScript and TypeScript Security Cheat Sheet

## Introduction

This cheat sheet lists secure development practices for JavaScript and TypeScript that apply everywhere the language runs: browsers, hybrid apps, server-side Node.js, and any other runtime that implements the language ([MDN JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript)). It covers language-level pitfalls (dynamic code execution, prototype pollution, regular expressions), client-side sinks, and TypeScript-specific false confidence. Rules that are equally valid on the client and the server are stated once here; backend and runtime hardening stays in the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md), which this sheet links to instead of duplicating.

## Related Cheat Sheets (Top-Level Links)

- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md) - backend and runtime guidance.
- [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) - output encoding rules per context.
- [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md) - client-side XSS sinks and sources.
- [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md) - managing external scripts.
- [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md) - TLS configuration.
- [OWASP Cheat Sheet Series index](https://cheatsheetseries.owasp.org/) - start here for the full catalog.

## Dangerous Language Surface

### `eval`, `Function`, and `with`

Never build code from strings. See [MDN's eval guidance](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval). `eval` and `new Function` execute arbitrary code with the current runtime's privileges, so any attacker-influenced input reaching them is code injection ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)). In browsers, `setTimeout` and `setInterval` with a string argument compile it the same way through implied `eval`.

- Parse data with `JSON.parse`, never `eval`.
- Replace dynamic dispatch with static maps of functions instead of constructing calls from names.
- Do not use the `with` statement. It makes scope unpredictable, is forbidden in strict mode, and blocks engine optimizations.
- Enforce this statically with the `no-eval`, `no-implied-eval`, and `no-new-func` lint rules.
- In browsers, block string compilation with an enforced Content Security Policy whose `script-src` directive, or `default-src` fallback, omits both `'unsafe-eval'` and `'trusted-types-eval'`. A report-only policy does not block execution ([CSP `EnsureCSPDoesNotBlockStringCompilation`](https://w3c.github.io/webappsec-csp/#can-compile-strings)).
- CSP is a browser-side control and does not apply to server-side runtimes, so the lint rules remain the primary enforcement everywhere.

### Evil Regex (ReDoS)

Nested quantifiers such as `(a+)+`, and repeated ambiguous alternatives such as `^(a|aa)*$`, can make matching take exponential time on crafted input, consuming CPU and potentially blocking the executing thread or event loop ([CWE-1333](https://cwe.mitre.org/data/definitions/1333.html)). Whether a pattern is actually exploitable depends on the surrounding expression and the failing input, not just the quantified group.

- Prefer well-tested validators over hand-written patterns for emails, URLs, and similar inputs.
- Keep patterns linear: avoid nested quantifiers and ambiguous alternation over the same characters.
- Cap untrusted input length before matching, and reject rather than sanitize when input does not match.
- For the attack mechanics and detection tooling, see the [OWASP ReDoS guidance](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS); use linear-time patterns as the primary control and input-length caps as defense in depth.

### Strict Mode

Ship ES modules (strict by default) or declare `'use strict'`, as described in [MDN's strict mode documentation](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode). Strict mode turns silent mistakes into errors: assignment to undeclared variables throws, `this` stays `undefined` in plain functions instead of becoming the global object, and `with` is rejected. It does not fix injection, XSS, or prototype pollution; treat it as hygiene, not a security boundary.

## Object and Property Safety (Including Prototype Pollution)

Prototype pollution ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)) occurs when attacker-controlled keys such as `__proto__`, `constructor`, or `prototype` reach a recursive merge or path setter and modify an object's prototype. This can alter the behavior of objects that inherit from that prototype. These are the JavaScript-specific essentials only; the full protection guidance lives in the dedicated [Prototype Pollution Prevention Cheat Sheet](Prototype_Pollution_Prevention_Cheat_Sheet.md).

- Never pass untrusted input to a recursive merge or `set-by-path` helper, and reject the key segments `__proto__`, `constructor`, and `prototype` before writing.
- Use a `Map` with `set`, `get`, and `has` for untrusted dictionary keys, keeping entries separate from object properties ([MDN prototype pollution defenses](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution#use_map_and_set_instead)). If an object is required, create it with `Object.create(null)` so it has no prototype.
- Validate parsed or copied untrusted data against a schema before use, and drop `__proto__` keys first: `Object.assign` applies them through the prototype setter and mutates the target's prototype, while spread creates a silent own property.

## DOM Sinks and Output Context

Injecting attacker-controlled strings into HTML, script, or URL contexts is cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)). Follow the [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) for per-context encoding and the [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md) for client-side sources and sinks.

- Build DOM with `textContent` and `createElement` instead of `innerHTML` or `insertAdjacentHTML`.
- When HTML must be rendered, sanitize with a maintained allowlist sanitizer and enforce [Trusted Types](https://w3c.github.io/trusted-types/dist/spec/) with no permissive default policy.
- Framework auto-escaping has explicit bypasses that must never receive untrusted input: React `dangerouslySetInnerHTML`, Vue `v-html`, and Angular `bypassSecurityTrustHtml` and its siblings.

## Async Error Handling, Messaging, and Origin Checks

Not every promise failure is a defect. An *expected* failure is part of a function's contract, such as a lookup that returns `null` for a missing key or a parse that throws on malformed input; handle it where the caller decides what to do, with a `try`/`catch` around `await` or a `.catch` on the terminal link of the chain, and return a typed result or a documented error. An *unhandled* rejection is a promise that rejects with no handler attached, so the failure propagates past the call site and is usually a bug: browsers report it in the console and fire an `unhandledrejection` event, while Node.js behavior depends on its unhandled-rejection mode and may terminate the process ([MDN promise rejection events](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises#promise_rejection_events)). Keep promise chains flat with a terminal error handler so genuinely unexpected rejections stay visible, and do not silence them with an empty `catch`. Server-side specifics live in the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md) and are not repeated here.

For `postMessage`, the receiver must verify `event.origin` against an explicit allowlist, check `event.source` when a conversation partner is expected, and validate `event.data` against the expected schema before acting on it. The sender must pass an exact `targetOrigin`, never `"*"` for sensitive data ([MDN postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)). Prefer narrow `MessageChannel` ports over broadcast messaging where the design allows it.

## TypeScript-Specific Caveats

Types are erased at runtime, so TypeScript alone enforces nothing against a malicious or malformed caller.

- Treat `any` as a hole in every check. `unknown` is the safe default for values of unknown type, because it forces you to narrow before use, whereas `any` disables type checking for that value ([TypeScript Handbook: `unknown`](https://www.typescriptlang.org/docs/handbook/2/functions.html#unknown)).
- Type assertions (`as`) and non-null assertions (`!`) silence the compiler without changing runtime values; do not use them on untrusted data.
- Enable `strict` in `tsconfig.json` (plus `noUncheckedIndexedAccess` where affordable) to catch accidental unsafety in your own code. It is a code-quality control, not a trust boundary.
- Validate at every trust boundary (network responses, `postMessage` payloads, storage reads) with a runtime schema validator. The validated type should flow from the schema, not from a parallel hand-written interface.

## Linting and Dependency Tooling

- Lint with [`typescript-eslint`](https://typescript-eslint.io/) recommended sets plus `no-eval`, `no-implied-eval`, and `no-new-func`. Keep dependencies updated so new rules apply.
- Pin versions with a lockfile, review dependency changes, and monitor advisories. Frontend dependency-review specifics overlap with the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md).
- For third-party scripts loaded from a CDN, pin a Subresource Integrity hash with `crossorigin` handling per the [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md).

## References

- [MDN: Window.postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [TypeScript Handbook: unknown](https://www.typescriptlang.org/docs/handbook/2/functions.html#unknown)
- [W3C Trusted Types](https://w3c.github.io/trusted-types/dist/spec/)
