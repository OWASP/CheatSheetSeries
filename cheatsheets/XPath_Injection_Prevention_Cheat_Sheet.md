# XPath Injection Prevention Cheat Sheet

## Introduction

XPath selects data from XML documents. [XPath injection](https://cwe.mitre.org/data/definitions/643.html) occurs when external input becomes part of an expression's syntax, allowing it to change the query's meaning. Prevent it by keeping expressions under application control and passing external values through variable binding.

## Bind Values to Fixed Expressions

Use an XPath API that supports variables. Write the expression in application code and supply external values separately. Do not concatenate or interpolate input into the expression, even if you compile it afterward: [compilation alone does not separate data from query syntax](https://cwe.mitre.org/data/definitions/643.html).

For example, Python's [lxml `xpath()` method accepts variables as keyword arguments](https://lxml.de/xpathxslt.html#the-xpath-method). This illustrative lookup assumes `xml_document` is an already parsed lxml document and `requested_id` is an external string:

```python
books = xml_document.xpath(
    "/catalog/book[@id=$book_id]",
    book_id=requested_id,
)
```

The expression stays fixed; `requested_id` supplies only the value of `$book_id`. The application must separately authorize access to the selected books.

For Java, use the resolver pattern in the [Java Security Cheat Sheet](Java_Security_Cheat_Sheet.md#xml-xpath-injection). Check the documentation for your particular API: accepting an XPath string or compiling an expression does not by itself mean the API provides variable binding.

If the API cannot bind values, prefer one that can. Where practical, use a fixed expression to retrieve an authorized set of records and compare values in application code. Do not substitute ad hoc quote replacement for variable binding.

## Keep Query Structure Under Application Control

[XPath variables represent values](https://www.w3.org/TR/xpath-31/#id-variables); they do not substitute expression fragments. When a user chooses a query mode, map that choice to a complete, fixed expression defined by the application. Reject unknown choices and bind any external data values separately.

For example, a catalog application can map the choices `books` and `magazines` to the fixed paths `/catalog/book` and `/catalog/magazine`. Do not insert the selected choice directly into a path or accept user-supplied predicates, operators, or function calls.

Validate values against the application's expected types, lengths, and business rules, following the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md). Validation complements binding; it does not make dynamically constructed XPath safe by itself.

## Limit Exposure and Review Usage

Keep these controls separate from the binding mechanism:

- **Authorization:** Check the caller's permission to access each requested resource. A fixed query, narrow path, or bound identifier does not establish permission. Follow the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md#validate-the-permissions-on-every-request) and the [principle of least privilege](https://owasp.org/www-community/Access_Control#principle-of-least-privilege) to limit the data an operation can access and return.
- **Error handling:** Keep XPath expressions, XML contents, and stack traces out of client-facing error messages. Follow the [Error Handling Cheat Sheet](Error_Handling_Cheat_Sheet.md). Generic errors reduce disclosure; they do not prevent injection.
- **XML parsing:** Configure the parser according to the [XML External Entity Prevention Cheat Sheet](XML_External_Entity_Prevention_Cheat_Sheet.md). Parser hardening addresses XML parser risks, not unsafe XPath construction; binding values does not harden the parser.

During code review, locate calls that evaluate or compile XPath. Trace each expression back to application-controlled text and verify that external values reach it only through variable binding. For fixed query mappings, verify that unknown choices are rejected. Include correctness checks for ordinary valid values, absent records, and access to resources outside the caller's permissions.

For security assessment guidance, see the [Web Security Testing Guide's XPath injection chapter](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/09-XPath_Injection/).
