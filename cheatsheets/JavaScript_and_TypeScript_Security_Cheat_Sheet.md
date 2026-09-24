# JavaScript and TypeScript Security Cheat Sheet

## Introduction

This cheat sheet lists secure development practices for JavaScript and TypeScript that apply everywhere the language runs: browsers, hybrid apps, and any non-Node.js runtime ([MDN JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript)). It covers language-level pitfalls (dynamic code execution, prototype pollution, regular expressions), client-side sinks, and TypeScript-specific false confidence. Backend and runtime hardening stays in the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md), which this sheet links to instead of duplicating.

## Related Cheat Sheets (Top-Level Links)

- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md) - backend and runtime guidance.
- [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) - output encoding rules per context.
- [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md) - client-side XSS sinks and sources.
- [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md) - managing external scripts.
- [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md) - TLS configuration.
- [OWASP Cheat Sheet Series index](https://cheatsheetseries.owasp.org/) - start here for the full catalog.

## Dangerous Language Surface

### `eval`, `Function`, and `with`

Never build code from strings. `eval` and `new Function` execute arbitrary code with the current runtime's privileges, so any attacker-influenced input reaching them is code injection ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)). In browsers, `setTimeout` and `setInterval` with a string argument compile it the same way through implied `eval`.

- Parse data with `JSON.parse`, never `eval`.
- Replace dynamic dispatch with static maps of functions instead of constructing calls from names.
- Do not use the `with` statement. It makes scope unpredictable, is forbidden in strict mode, and blocks engine optimizations.
- Enforce this with a Content Security Policy without `unsafe-eval`, and with the `no-eval`, `no-implied-eval`, and `no-new-func` lint rules.

### Evil Regex (ReDoS)

Nested quantifiers such as `(a+)+`, and repeated ambiguous alternatives such as `^(a|aa)*$`, can make matching take exponential time on crafted input, consuming CPU and potentially blocking the executing thread or event loop ([CWE-1333](https://cwe.mitre.org/data/definitions/1333.html)). Whether a pattern is actually exploitable depends on the surrounding expression and the failing input, not just the quantified group.

- Prefer well-tested validators over hand-written patterns for emails, URLs, and similar inputs.
- Keep patterns linear: avoid nested quantifiers and ambiguous alternation over the same characters.
- Cap untrusted input length before matching, and reject rather than sanitize when input does not match.
- For the attack mechanics and detection tooling, see the [OWASP ReDoS guidance](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS); use linear-time patterns as the primary control and input-length caps as defense in depth.

### Strict Mode

Ship ES modules (strict by default) or declare `'use strict'`. Strict mode turns silent mistakes into errors: assignment to undeclared variables throws, `this` stays `undefined` in plain functions instead of becoming the global object, and `with` is rejected. It does not fix injection, XSS, or prototype pollution; treat it as hygiene, not a security boundary.

## Object and Property Safety (Including Prototype Pollution)

Prototype pollution ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)) occurs when attacker-controlled keys such as `__proto__`, `constructor`, or `prototype` reach a recursive merge or path setter and modify an object's prototype. This can alter the behavior of objects that inherit from that prototype. The full protection guidance lives in the dedicated [Prototype Pollution Prevention Cheat Sheet](Prototype_Pollution_Prevention_Cheat_Sheet.md); the rules below are the JavaScript-specific essentials.

- Use a `Map` instead of a plain object when keys come from untrusted input.
- Create key-value dictionaries with `Object.create(null)` so there is no prototype to pollute or inherit from.
- In any recursive merge or `set-by-path` helper, reject the key segments `__proto__`, `constructor`, and `prototype` before writing.
- When parsing JSON, pass a `reviver` that drops those keys, and validate the result against a schema before use.
- When copying untrusted data, drop `__proto__` keys first: `Object.assign` applies them through the prototype setter (mutating the target's prototype), while spread defines them as silent own properties. Either way, validate the copy against a schema before use.
- Consider freezing `Object.prototype` as defense in depth, early in startup. It can break libraries that extend built-in prototypes, so verify it against your dependency set first.

## DOM Sinks and Output Context

Injecting attacker-controlled strings into HTML, script, or URL contexts is cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)). Follow the [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) for per-context encoding and the [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md) for client-side sources and sinks.

- Build DOM with `textContent` and `createElement` instead of `innerHTML` or `insertAdjacentHTML`.
- When HTML must be rendered, sanitize with a maintained allowlist sanitizer and enforce [Trusted Types](https://w3c.github.io/trusted-types/dist/spec/) with no permissive default policy.
- Framework auto-escaping has explicit bypasses that must never receive untrusted input: React `dangerouslySetInnerHTML`, Vue `v-html`, and Angular `bypassSecurityTrustHtml` and its siblings.

## Async Error Handling, Messaging, and Origin Checks

Unhandled promise rejections hide failures and may terminate some runtimes: browsers generally surface them in the console, while Node.js behavior depends on its unhandled-rejection mode ([MDN promise rejection events](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises#promise_rejection_events)). Keep promise chains flat with a terminal error handler, and treat every rejection as a bug to fix rather than noise to suppress. Server-side specifics live in the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md) and are not repeated here.

For `postMessage`, the receiver must verify `event.origin` against an explicit allowlist and check `event.source` when a conversation partner is expected. The sender must pass an exact `targetOrigin`, never `"*"` for sensitive data ([MDN postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)). Prefer narrow `MessageChannel` ports over broadcast messaging where the design allows it.

## TypeScript-Specific Caveats

Types are erased at runtime, so TypeScript alone enforces nothing against a malicious or malformed caller.

- Treat `any` as a hole in every check. Default to `unknown` and narrow it before use ([TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/2/everyday-types.html)).
- Type assertions (`as`) and non-null assertions (`!`) silence the compiler without changing runtime values; do not use them on untrusted data.
- Enable `strict` in `tsconfig.json` (plus `noUncheckedIndexedAccess` where affordable) to catch accidental unsafety in your own code. It is a code-quality control, not a trust boundary.
- Validate at every trust boundary (network responses, `postMessage` payloads, storage reads) with a runtime schema validator. The validated type should flow from the schema, not from a parallel hand-written interface.

## Linting and Dependency Tooling

- Lint with [`typescript-eslint`](https://typescript-eslint.io/) recommended sets plus `no-eval`, `no-implied-eval`, and `no-new-func`. Keep dependencies updated so new rules apply.
- Pin versions with a lockfile, review dependency changes, and monitor advisories. Frontend dependency-review specifics overlap with the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md).
- For third-party scripts loaded from a CDN, pin a Subresource Integrity hash with `crossorigin` handling per the [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md).

## References

- Issue [#2337](https://github.com/OWASP/CheatSheetSeries/issues/2337) - proposal and discussion.
- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md).
- [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md).
- [MDN: eval](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval) - why direct and indirect `eval` differ and why both are discouraged.
- [MDN: Strict mode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode) - what strict mode changes.
- [MDN: window.postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) - origin and source validation.
- [W3C Trusted Types](https://w3c.github.io/trusted-types/dist/spec/) - sink allowlisting for DOM injection.
- [TypeScript Handbook: Everyday Types](https://www.typescriptlang.org/docs/handbook/2/everyday-types.html) - `any` versus `unknown`.
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html).
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html).
- [CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html).
- [CWE-1333: ReDoS](https://cwe.mitre.org/data/definitions/1333.html).
