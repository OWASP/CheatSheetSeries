# JavaScript and TypeScript Security Cheat Sheet

## Introduction

This is a DRAFT skeleton for issue [#2337](https://github.com/OWASP/CheatSheetSeries/issues/2337) (New CS proposal: JavaScript and TypeScript Cheat Sheet).

Scope (per issue discussion): client-side JavaScript and TypeScript threats plus language-level fundamentals that a frontend developer will not find under a `Node.js` title. This sheet cross-references (not duplicates) the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md). Prototype pollution currently lives in neither sheet and is a structural reason for this split.

> TODO: expand introduction (2-4 sentences, developer audience, US English) once outline is approved.

## Related Cheat Sheets (Top-Level Links)

Top-level entry point with prominent links to related sheets:

- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md) - backend / runtime guidance; this sheet links there instead of duplicating it.
- [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).
- [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md).
- [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md).
- [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md).

> TODO: confirm final related-sheet list with reviewers.

## Dangerous Language Surface

> TODO: fill guidance + short illustrative snippets. Keep code minimal and architectural-first per `CONTRIBUTING.md`.

### `eval`, `Function`, and `with`

> TODO: explain why `eval` / `new Function` / `with` are dangerous, safer alternatives (JSON parse, static dispatch, scoped access).

### Evil Regex (ReDoS)

> TODO: evil-regex patterns, linear-time alternatives, timeout / match limits, validator reuse. Cross-link Node.js sheet section where overlapping.

### Strict Mode

> TODO: `'use strict'` / ES-module strict-by-default benefits, what it does and does not fix.

## Object and Property Safety (Including Prototype Pollution)

> TODO: detection / prevention guidance.

- Frozen prototypes (`Object.freeze(Object.prototype)` considerations).
- `Map` over plain objects for untrusted keys.
- Guarded merge / parse (`__proto__`, `constructor`, `prototype` keys, JSON reviver, schema validation).
- `Object.create(null)`, property descriptors where relevant.

> TODO: note that prototype pollution is currently in neither the Node.js sheet nor this skeleton; this section is the new sheet's distinct contribution.

## DOM Sinks and Output Context

> TODO: `innerHTML` / `insertAdjacentHTML` / sink-vs-context escaping. Link (not duplicate) `Cross_Site_Scripting_Prevention` and `DOM_based_XSS_Prevention` sheets.

## Async Error Handling, Messaging and Origin Checks

> TODO: flat promise chains / `async` error handling xref (Node.js sheet has overlapping guidance — link, do not copy), `postMessage` origin / source validation.

## TypeScript-Specific Caveats

> TODO: types erased at runtime, `any` / assertion escape hatches, `strict` config as a security control (not a boundary), validation at boundaries still required.

## Linting and Dependency Tooling

> TODO: linters / secure defaults / dependency review. Link Node.js sheet tooling where overlapping.

## References

- Issue [#2337](https://github.com/OWASP/CheatSheetSeries/issues/2337) - proposal and discussion (`ofri-peretz` 9-subsection count, `jmanico` top-level link request).
- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md).
- [Third Party JavaScript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md).

> TODO: add authoritative refs (MDN, CWE, standards) as sections are filled.
