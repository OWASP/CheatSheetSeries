# Server-Side Template Injection Prevention Cheat Sheet

## Introduction

Server-Side Template Injection (SSTI) occurs when untrusted input is evaluated by a server-side template engine as template code instead of being rendered as data. MITRE catalogs this weakness in the Common Weakness Enumeration (CWE) as [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html), which lists "Server-Side Template Injection" as the alternate term for injection into a server-side template engine.

Template engines such as Jinja2, Twig, and FreeMarker (among [the engines named by CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)) parse their own expression and statement syntax on the server, so attacker-supplied syntax can change what the engine evaluates. Impact depends on the engine and its configuration, ranging from disclosing files and application data to [remote code execution](https://portswigger.net/web-security/server-side-template-injection#what-is-the-impact-of-server-side-template-injection).

This cheat sheet covers **prevention**: how to design, write, and configure template handling so that untrusted input can never become template code. For finding SSTI in a running application (detection, engine identification, and exploitation), use the [OWASP Web Security Testing Guide: Testing for Server-side Template Injection (WSTG-INJT-18)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection/).

Key points:

- Treat template source as code: never build, extend, or select a template from user input.
- Pass untrusted values to templates as data and let the engine escape them for the output context.
- Configure the engine for auto-escaping and expose each template only to the data it needs.
- If users must be able to write templates, render them in a sandbox, isolate the rendering process, and assume the sandbox will be attacked.

## How Template Injection Arises

Template engines are designed to combine a fixed template with changing data. SSTI appears when that boundary is broken. [PortSwigger's Web Security Academy describes the root cause](https://portswigger.net/web-security/server-side-template-injection#how-do-server-side-template-injection-vulnerabilities-arise) as user input being concatenated into templates rather than passed in as data. Three patterns cover most cases.

### Untrusted input becomes template source

The application builds the template itself from request data, or passes untrusted input to an API that turns a string into a template, such as [Jinja2's `from_string`](https://jinja.palletsprojects.com/en/stable/api/#jinja2.Environment.from_string) or [Flask's `render_template_string`](https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string). If the string contains user input, the engine parses that input as template code, not as text to print.

### Untrusted input lands inside an expression

The application places user input inside a template expression, for example by putting a user-controlled variable or attribute name inside `{{ ... }}`. The engine then evaluates the input instead of printing it. This context is easy to miss in review because the surrounding template is fixed and only a fragment of the expression is attacker-controlled.

### User-controlled template names, paths, and includes

Template names, file paths, and include targets are code too. If a user can influence which template is loaded or what a template includes, they can steer the engine toward unintended files: [the FreeMarker FAQ illustrates this with a template that includes `../secret.txt`](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security) and requires the application to control what a template loader may load.

### Filtering template syntax from input is not a defense

Template syntax differs between engines ([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) notes that "the syntax varies depending on the language") and between rendering contexts within one engine, so no denylist of payload patterns covers every case. Keep untrusted input out of template source, expressions, and template names instead of trying to recognize and strip "template-looking" input.

## Prevention Guidelines

### Only use templates from trusted sources

Keep template files and template strings in version control, review them like application code, and never assemble them from request data. State the rule the way [the FreeMarker FAQ does](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security): treat templates as part of the source code. If a product requirement calls for user-authored templates (custom email bodies, CMS themes, report layouts), treat that feature as privileged and apply the guidance in the [sandboxing section](#sandboxing-user-supplied-templates).

### Pass untrusted input as data

Render a fixed template and pass user-supplied values as named render variables, so the engine treats them as data. This is the [central prevention rule for SSTI](https://portswigger.net/web-security/server-side-template-injection#how-to-prevent-server-side-template-injection-vulnerabilities), and it is the same discipline as using parameterized queries for [SQL injection](SQL_Injection_Prevention_Cheat_Sheet.md).

### Enable auto-escaping and encode for the output context

Auto-escaping encodes values as they are printed, which keeps untrusted data from changing the structure of the rendered HTML ([Cross-Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)):

- Jinja2's [base configuration does not auto-escape](https://jinja.palletsprojects.com/en/stable/templates/#html-escaping); enable it deliberately, for example with [`select_autoescape`](https://jinja.palletsprojects.com/en/stable/api/#jinja2.select_autoescape).
- Twig [auto-escaping is enabled by default](https://twig.symfony.com/doc/3.x/templates.html#html-escaping) with an `html` strategy; keep it on.
- FreeMarker escapes through an [output format associated with each template](https://freemarker.apache.org/docs/dgui_misc_autoescaping.html), which is the programmer's responsibility to set up.

For non-HTML output, use the engine's per-context escaping strategies (for example [Twig's `escape` filter strategies for HTML, JavaScript, CSS, and URL contexts](https://twig.symfony.com/doc/3.x/filters/escape.html)) or encode with a dedicated library. Never mark untrusted values as safe — that is what [Jinja2's `safe` filter](https://jinja.palletsprojects.com/en/stable/templates/#working-with-automatic-escaping) and Twig's `raw` filter do ([Symfony Cheat Sheet](Symfony_Cheat_Sheet.md)) — and never switch auto-escaping off around a block that prints untrusted data ([Jinja2 autoescape overrides](https://jinja.palletsprojects.com/en/stable/templates/#autoescape-overrides)).

### Expose only what each template needs

Anything in the render context is readable by the template, so pass only the values the template actually uses and avoid globals and objects whose methods have side effects. [The Jinja2 sandbox security considerations say to pass only the data relevant to the template](https://jinja.palletsprojects.com/en/stable/sandbox/#security-considerations), and [the FreeMarker FAQ](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security) explains that FreeMarker's default object wrapping exposes the public Java API of objects placed in the data model unless you restrict it. Keep secrets out of render contexts entirely.

### Return generic errors to users

Template errors routinely reveal the engine, its version, and internal structure — details attackers use to pick payloads. [PortSwigger's methodology relies on those error messages](https://portswigger.net/web-security/server-side-template-injection#identify) to identify the engine. Log the detail on the server and show users a generic message ([Error Handling Cheat Sheet](Error_Handling_Cheat_Sheet.md)).

### Prefer templates without logic where practical

Templates with expression languages give the template author program-like power over application objects. [PortSwigger recommends a logic-less engine such as Mustache](https://portswigger.net/web-security/server-side-template-injection#how-to-prevent-server-side-template-injection-vulnerabilities) unless the extra power is required. Choose the least expressive engine that meets the product's needs, and treat runtime evaluation of template strings as a privileged operation.

## Secure Template Engine Configuration

Engine defaults are not identical, and frameworks that wrap an engine may change them, so verify the effective settings in your own application rather than assuming them.

### Jinja2

- Turn auto-escaping on for HTML templates (`select_autoescape`), as shown above. Flask, for example, [decides per template file name whether auto-escaping is active](https://flask.palletsprojects.com/en/stable/api/#flask.Flask.select_jinja_autoescape).
- Keep [`|safe` marking and `{% autoescape false %}`](https://jinja.palletsprojects.com/en/stable/templates/#working-with-automatic-escaping) reserved for values your application produced or encoded itself.
- When you render templates you did not write, switch to the [sandboxed environment](#render-untrusted-templates-in-a-sandbox) described below.

### Twig

- Leave the [`autoescape` option at its default](https://twig.symfony.com/doc/3.x/templates.html#html-escaping) (`html`) for HTML output, and set explicit strategies such as `e('js')` or `e('url')` when a value is printed into [another context](https://twig.symfony.com/doc/3.x/filters/escape.html).
- For untrusted template authors, [configure a strict security policy through Twig's sandbox](https://twig.symfony.com/doc/3.x/sandbox.html) instead of exposing the normal environment to their templates.

### FreeMarker

- [Associate an output format with your templates](https://freemarker.apache.org/docs/dgui_misc_autoescaping.html) so `${...}` interpolations are escaped; the documentation recommends configuring templates with the `.ftlh` and `.ftlx` extensions to be associated with the HTML and XML output formats automatically.
- [Keep the `?api` built-in disabled](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security), which is its default, so templates cannot reach the full Java API of wrapped objects.
- If templates can call `?new`, [restrict which classes it may resolve](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security) with `Configuration.setNewBuiltinClassResolver`: the FAQ recommends a resolver such as `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER` for templates you do not fully trust, and warns that `SAFER_RESOLVER` is not restrictive enough for that purpose.
- Use a [template loader that double-checks the files a template may load](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security), including includes and imports.

## Sandboxing User-Supplied Templates

Some products genuinely require user-supplied templates: email builders, CMS themes, report designers, and tenant-customizable layouts. [PortSwigger notes that this is often intentional](https://portswigger.net/web-security/server-side-template-injection#how-do-server-side-template-injection-vulnerabilities-arise) — privileged users such as content editors are allowed to submit templates by design. If that is your requirement, sandboxing is the control to reach for, with several limits that apply to every engine.

### Apply the control in layers

- Restrict template editing to authenticated, authorized users and review template changes like code changes ([Access Control Cheat Sheet](Access_Control_Cheat_Sheet.md)). [CWE-1336 recommends choosing an engine with a sandbox or restricted mode](https://cwe.mitre.org/data/definitions/1336.html) precisely for this case.
- Pass sandboxed templates only the data they need: template authors can iterate everything in the render context, and [the Twig documentation warns that data is visible to them](https://twig.symfony.com/doc/3.x/sandbox.html#what-the-sandbox-does-not-protect-against).
- Enforce resource limits outside the engine. [Jinja2 asks you to cap CPU and memory](https://jinja.palletsprojects.com/en/stable/sandbox/#security-considerations), [Twig states that a sandbox does not limit resources](https://twig.symfony.com/doc/3.x/sandbox.html#what-the-sandbox-does-not-protect-against), and [FreeMarker states that it cannot enforce CPU or memory limits at all](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security). Run rendering in a dedicated process or container with time and memory limits.
- Assume a sandbox can be bypassed: [PortSwigger describes sandboxing untrusted code as inherently difficult and prone to bypasses](https://portswigger.net/web-security/server-side-template-injection#how-to-prevent-server-side-template-injection-vulnerabilities), and [the Jinja2 documentation states that the sandbox alone is not a solution for perfect security](https://jinja.palletsprojects.com/en/stable/sandbox/#security-considerations). Isolate the renderer with minimal privileges, no ambient secrets, and controlled network access, for example a locked-down container.

### Render untrusted templates in a sandbox

| Engine | Approach |
| --- | --- |
| Jinja2 | Use [`SandboxedEnvironment`](https://jinja.palletsprojects.com/en/stable/sandbox/) (or `ImmutableSandboxedEnvironment` to also block mutation of lists, dictionaries, and sets). It rejects unsafe attribute access and operations with `SecurityError`; you can further tighten [`is_safe_attribute()`](https://jinja.palletsprojects.com/en/stable/sandbox/) and mark dangerous methods with `unsafe()`. |
| Twig | Render through Twig's [sandbox with a strict `SecurityPolicy`](https://twig.symfony.com/doc/3.x/sandbox.html) that allow-lists the tags, filters, functions, tests, object methods, and properties templates may use. Twig treats templates as trusted code and states that the sandbox is the only security boundary for templates written by untrusted authors. |
| FreeMarker | Follow [the FAQ's guidance for allowing template uploads](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security): a restrictive class resolver for `?new`, a restricted object wrapper (for example a `SimpleObjectWrapper` or a whitelist `MemberAccessPolicy`), a checked template loader, and `?api` kept disabled. |

A sandbox limits what a template can reach, not what it can write: [Twig warns that a template's text is output as its author wrote it, HTML and JavaScript included, and that auto-escaping only applies to printed expressions](https://twig.symfony.com/doc/3.x/sandbox.html#what-the-sandbox-does-not-protect-against). Do not treat that output as trusted markup, keep secrets out of the render context, and keep the feature available only to the roles that need it.

## Reviewing the Template Attack Surface

Add template handling to your attack-surface review so that new sinks are found before they ship:

- **Inventory every rendering path.** Include server-rendered pages, email and notification bodies, PDF and report generation, and templates used to build prompts for large language model libraries — [CWE-1336 records a real-world case where Jinja2 template injection in a prompt led to code execution](https://cwe.mitre.org/data/definitions/1336.html).
- **Classify each path.** For every call site, confirm whether user input reaches template source, a template name or include target, or only render data. Only the last is acceptable.
- **Search for source-building code.** Look for string concatenation or formatting into template strings and for string-to-template APIs such as `from_string` and `render_template_string`. [CWE-1336 identifies automated static analysis](https://cwe.mitre.org/data/definitions/1336.html) as an effective way to find data flow into template engines; the same tooling used for [injection](Injection_Prevention_Cheat_Sheet.md) sinks applies here.
- **Flag privileged features.** Any screen or API that lets users create or edit templates is a design decision that needs authorization, sandboxing, and a code review of the template itself.
- **Review template changes.** Diff templates in pull requests and require review from someone who understands the engine's expression language, matching the ["templates are source code" rule](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security).
- **Verify with the testing guidance.** After remediation, confirm the fix using the [OWASP Web Security Testing Guide's SSTI testing page](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection/), which covers probing a live application — a task outside the scope of this cheat sheet.

## References

- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [PortSwigger Web Security Academy: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [PortSwigger Research: Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [OWASP Web Security Testing Guide: Testing for Server-side Template Injection (WSTG-INJT-18)](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection/)
- [Jinja2 documentation: Sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Twig documentation: Twig Sandbox](https://twig.symfony.com/doc/3.x/sandbox.html)
- [Apache FreeMarker FAQ: template uploading security](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security)
- [OWASP Injection Prevention Cheat Sheet](Injection_Prevention_Cheat_Sheet.md)
- [OWASP Cross-Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
