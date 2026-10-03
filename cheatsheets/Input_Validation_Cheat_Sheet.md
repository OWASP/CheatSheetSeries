# Input Validation Cheat Sheet

## Introduction

Input validation checks whether data meets an application's requirements before the application uses it. It reduces the risk of malformed data, invalid business operations, and excessive resource consumption. [OWASP's Proactive Control C3](https://top10proactive.owasp.org/archive/2024/the-top-10/c3-validate-input-and-handle-exceptions/) distinguishes validation from the additional defenses needed when using that data:

- Use [parameterized queries](SQL_Injection_Prevention_Cheat_Sheet.md) for SQL and [context-aware output encoding](Cross_Site_Scripting_Prevention_Cheat_Sheet.md#output-encoding) to prevent cross-site scripting (XSS).
- Check [authorization](Authorization_Cheat_Sheet.md) separately: a valid account identifier does not mean the caller may access that account.

## Input Validation Strategies

Validate both **syntax** (the expected type and format) and **semantics** (whether the value makes sense for the operation). For example, a booking needs valid dates and an end date after its start date. [CWE-20](https://cwe.mitre.org/data/definitions/20.html) describes these checks, including consistency between related fields.

Define rules for each field:

| Input | Rules to enforce |
| --- | --- |
| Fixed choices | Exact membership in the allowed set, including values submitted from drop-down menus |
| Numbers and dates | Expected type, accepted format, and minimum and maximum values |
| Strings | Length limits and the characters or structure required by the field |
| Objects | Allowed fields, required fields, and rules for missing or null values |
| Arrays | Minimum and maximum item counts and validation of every item, including nested objects |

### Allowlist vs Denylist

Define what the application accepts and reject values outside those rules. Do not try to recognize every malicious string. Blocking apostrophes, for example, rejects legitimate names without making a database query safe. For free-form comments, an allowlist can permit broad Unicode text while limiting its length; it need not restrict users to letters and digits.

## Implementing Input Validation

### Parse Safely, Then Validate

Apply request size limits before buffering or parsing input, and configure parser limits such as maximum nesting depth. JSON explicitly supports [implementation limits on size, depth, and numbers](https://www.rfc-editor.org/info/rfc8259/#section-9). A schema check after parsing cannot protect a parser that has already exhausted resources.

Use a maintained parser for the expected format, handle parsing failures, and validate the resulting values before business processing or storage. Configure parsers for untrusted input; see [XML External Entity Prevention](XML_External_Entity_Prevention_Cheat_Sheet.md#general-guidance) and [Deserialization](Deserialization_Cheat_Sheet.md). Converting text to an integer only establishes a type: it does not establish an acceptable quantity.

Decode according to the protocol before checking field rules. Validate the representation that will actually be used, and avoid decoding it again downstream; [CWE-20](https://cwe.mitre.org/data/definitions/20.html) explains how inconsistent decoding can invalidate earlier checks.

### Validate Structured Data

Use your framework's validators or a schema validator to enforce field rules. For JSON, explicitly configure [required and additional properties](https://json-schema.org/understanding-json-schema/reference/object); listing a property alone neither requires it nor rejects unknown fields. Apply schemas to nested objects and use [item schemas and array length limits](https://json-schema.org/understanding-json-schema/reference/array). Keep business checks, such as date ordering, alongside these structural checks.

Reject invalid requests with a clear error; do not continue with partially validated data. Bind only intended input fields to application objects; see [Mass Assignment](Mass_Assignment_Cheat_Sheet.md).

### Validating Free-form Unicode Text

Agree on a character encoding across components and reject malformed input. Preserve legitimate punctuation and scripts in names and comments. Where a field requires Unicode normalization for consistent comparison, define and apply the same policy before validation, storage, and comparison. [Unicode Standard Annex #15](https://www.unicode.org/reports/tr15/) defines the normalization forms and warns that compatibility normalization can erase meaningful distinctions. Normalization is not sanitization and does not replace output encoding.

### Regular Expressions (Regex)

Use regular expressions for simple, structured fields. Require a match of the entire value, using an API such as [Python's `fullmatch`](https://docs.python.org/3/library/re.html#re.fullmatch) where available. Check the engine's character classes and newline behavior rather than assuming patterns behave identically across languages.

Bound input length before matching, avoid patterns with excessive backtracking, and use a non-backtracking engine or a match timeout where supported. Test valid, invalid, and near-matching values; [Microsoft's regex guidance](https://learn.microsoft.com/en-us/dotnet/standard/base-types/best-practices-regex) explains why near-matches can cause denial of service. Treat a timeout as validation failure.

### Validating Rich User Content

When accepting user-authored HTML, use a maintained [HTML sanitization library](Cross_Site_Scripting_Prevention_Cheat_Sheet.md#html-sanitization). Input validation and regular expressions cannot replace that control.

### File Upload Validation

Treat the submitted filename and content type as untrusted metadata. Validate filenames after protocol decoding; an allowed extension alone does not establish safe content. Follow the [File Upload Cheat Sheet](File_Upload_Cheat_Sheet.md) for content checks, size limits, storage, and safe serving.

### Email Address Validation

Use a maintained email validation library compatible with the addresses your mail system supports. Format validation does not prove mailbox access. Follow [Email Validation and Verification](Email_Validation_and_Verification_Cheat_Sheet.md) for comparison policies, ownership verification, and email change workflows.

## Common Pitfalls

- **Client-only checks:** Validate on the server even when the browser checks the same fields. [Client-side validation is bypassable](https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Forms/Form_validation); use it for immediate feedback.
- **Trusting internal sources:** Validate data from internal APIs, partner feeds, queues, and stored records when it crosses a trust boundary. An internal transport does not establish that a value meets the receiving component's rules ([CWE-20](https://cwe.mitre.org/data/definitions/20.html)).
- **Denylisting or “cleaning” input:** Apply field-specific acceptance rules. Removing suspicious characters can change meaning and still does not provide query parameterization or output encoding.
- **Stopping at parsing or outer fields:** Test rejected ranges, missing fields, invalid nested items, and oversized arrays, not just malformed syntax.
- **Assuming regex or Unicode normalization makes data safe:** Check whole-value matching and resource limits; keep normalization consistent with the field's meaning.
- **Trusting upload metadata:** Use the file upload controls above; checking a filename is not checking the file's contents.
- **Logging rejected input verbatim:** Record the failure and relevant metadata without secrets or full request bodies. Escape any retained untrusted values for the log format to prevent log injection; see [Logging: Event collection](Logging_Cheat_Sheet.md#event-collection) and [Data to exclude](Logging_Cheat_Sheet.md#data-to-exclude).

## References

- [OWASP Top 10 Proactive Controls 2024: C3 — Validate all Input & Handle Exceptions](https://top10proactive.owasp.org/archive/2024/the-top-10/c3-validate-input-and-handle-exceptions/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [Unicode Standard Annex #15: Unicode Normalization Forms](https://www.unicode.org/reports/tr15/)
