# Server-Side Template Injection Prevention Cheat Sheet

## Introduction

Server-Side Template Injection (SSTI) happens when a server-side template engine evaluates untrusted input as template code instead of rendering it as data (Common Weakness Enumeration [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)). Engines such as Jinja2, Twig, and FreeMarker have their own expression languages, so injected syntax runs with the engine's access to application objects. Depending on the engine and its configuration, the impact ranges from reading sensitive data and files to remote code execution.

Untrusted input crosses into template code in three ways:

- **Input becomes template source.** Untrusted data, such as request parameters, stored user content, or third-party files, is concatenated into a template string, even inside an expression like `"Hello {{" + name + "}}"`, or passed to a string-to-template API such as Jinja2's `from_string()` or Flask's `render_template_string()`.
- **A template evaluates input as code.** A fixed template passes a value to a feature that parses strings as template code, such as FreeMarker's `?interpret` and `?eval` built-ins or Twig's `template_from_string()` function.
- **Input chooses the template.** User input selects a template name, path, or include target, which can make the engine load files it should not.

Do not try to filter template syntax out of input. Syntax differs between engines and contexts, so a denylist will miss payloads.

This cheat sheet covers prevention. To test a running application, use the [OWASP Web Security Testing Guide (WSTG-INJT-18)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection/).

## Prevention

### Treat templates as code

Keep templates with the application source, review changes to them like code, and never build them from untrusted data. Do not let untrusted data choose a template name, path, or include target either: map the user's choice to a fixed list of template names on the server. If users must author templates, follow the User-Supplied Templates section below.

### Pass untrusted input only as data

Render a fixed template and pass user values as named variables, the same way a parameterized query keeps data out of SQL.

### Keep the render context minimal

A template can read everything in its render context and, depending on the engine, call methods on the objects you pass. Pass only the values a template needs. Do not pass secrets, configuration, service clients, or objects whose methods have side effects. This limits what an injected template can reach, but it does not stop code execution in an engine that is not sandboxed.

### Prefer the least powerful engine

Choose an engine that [limits the power of its expressions, function calls, or commands](https://cwe.mitre.org/data/definitions/1336.html#Potential_Mitigations), such as a logic-less engine like Mustache, unless you need more. Custom helpers and lambdas you register still run as application code.

### Keep output escaping on

Auto-escaping helps prevent [cross-site scripting](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) in HTML output. It does not prevent SSTI, because escaping applies to the values a template prints, not to template code the engine has already parsed. Keep it enabled and never mark untrusted values as safe.

### Find vulnerable template code

- Inventory every place the application renders templates, including email and notification bodies, PDF and report generation, prompts for large language models, and every feature that lets users create or edit templates. Treat templates that ship in third-party files as templates you did not write.
- Search for string-to-template APIs and features, such as Jinja2's `from_string()`, Flask's `render_template_string()`, Twig's `createTemplate()` and `template_from_string()`, and FreeMarker's `Template` constructor and `?interpret` and `?eval` built-ins. Also search for code that builds template source or template names from input.
- For each call site, confirm that untrusted data reaches only render variables and that no template passes it to a feature that evaluates strings as code.

## Engine Configuration

Frameworks can change engine defaults, so check the effective settings in your application. For other engines, consult their documentation for restrictions on untrusted templates.

| Engine | Restrictions for untrusted templates |
| --- | --- |
| Jinja2 | Use [`SandboxedEnvironment`](https://jinja.palletsprojects.com/en/stable/sandbox/), or `ImmutableSandboxedEnvironment` to also block changes to lists, sets, and dictionaries. Restrict attributes further by overriding `is_safe_attribute()`, and decorate dangerous methods with `unsafe()`. |
| Twig | Twig treats templates as trusted code, so its [sandbox](https://twig.symfony.com/doc/3.x/sandbox.html) is the only boundary for untrusted authors. Give the sandbox its own environment and a strict `SecurityPolicy` that allowlists the tags, filters, functions, tests, methods, and properties templates may use. The `Sandbox` class requires Twig 3.29 or later. Never allow [`template_from_string()`](https://twig.symfony.com/doc/3.x/functions/template_from_string.html) in sandboxed templates. |
| FreeMarker | Follow the [FAQ on uploaded templates](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security): set the `?new` class resolver to `ALLOWS_NOTHING_RESOLVER`, not `SAFER_RESOLVER`; keep `?api` disabled (the default), restrict member access with `SimpleObjectWrapper` or a `WhitelistMemberAccessPolicy`, disable DOM node wrapping, and use a template loader that only loads approved files. |

## User-Supplied Templates

Some products let users write templates by design, such as email builders, content management system themes, and report designers. Treat this as a privileged feature that runs user-written code:

- Limit template editing to authorized roles and log template changes for audit.
- Render with the engine's sandbox or restricted configuration from the table above and keep the engine up to date.
- Register only filters, functions, and globals that are safe to call with any arguments a template author chooses. The sandbox does not limit what your own code does once it is called.
- Contain what the sandbox does not. As [Twig's documentation explains](https://twig.symfony.com/doc/3.x/sandbox.html#what-the-sandbox-does-not-protect-against), a sandbox does not limit CPU or memory use or make the rendered output safe, and Jinja2 and FreeMarker give the same warning about resources. Treat the output as untrusted, and render in an isolated process or container with time and memory limits, no secrets, and restricted network access.

## References

- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [Twig Documentation: Twig Sandbox](https://twig.symfony.com/doc/3.x/sandbox.html)
- [Apache FreeMarker FAQ: Can I allow users to upload templates?](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security)
