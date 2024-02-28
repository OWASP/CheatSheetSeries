# Django REST Framework (DRF) Cheat Sheet

## Introduction

This *Cheat sheet* intends to provide quick basic Django REST Framework security tips for developers.

The Django REST framework abstracts developers from quite a bit of tedious work and provides the means to build APIs quickly and with ease using Django. New developers, those unfamiliar with the inner workings of Django, likely need a basic set of guidelines to secure fundamental aspects of their application. The intended purpose of this doc is to be that guide.

## Settings

All the Django REST Framework (DRF) configuration is done under the
namespace REST_FRAMEWORK, usually in the settings.py file. From a security perspective, the most relevant ones are:

### DEFAULT_AUTHENTICATION_CLASSES

A list of authentication classes that determines the default set of authenticators used when accessing the request.user or request.auth properties. In other words, what classes should be used to identify which user is authenticated.

Defaults are 'rest_framework.authentication.SessionAuthentication', 'rest_framework.authentication.BasicAuthentication', that means that by default it checks the session and basic authentication for the user.

### DEFAULT_PERMISSION_CLASSES

A list of permission classes that determines the default set of permissions checked at the start of a view.

Permission must be granted by every class in the list. Default is 'rest_framework.permissions.AllowAny'18, that means that by **default every view allows access to everybody.**

### DEFAULT_THROTTLE_CLASSES

A list of throttle classes that determines the default set of throttles checked at the start of a view.
**Default is empty**, that means that by default there is no throttling in place.

### DEFAULT_PAGINATION_CLASS

The default class to use for queryset pagination. **Pagination is disabled by default.** Lack of proper pagination could lead to Denial of Service (DoS) in cases where there’s a lot of data.

## OWASP API Security Top 10

The [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) is a list of the most critical security risks for APIs, developed by the [Open Web Application Security Project (OWASP)](https://owasp.org/). It is intended to help organizations identify and prioritize the most significant risks to their APIs, so that they can implement appropriate controls to mitigate those risks.

This section is based on this. Your approach to securing your web API should be to start at the top threat A1 below and work down, this will ensure that any time spent on security will be spent most effectively spent and cover the top threats first and lesser threats afterwards. After covering the top 10 it is generally advisable to assess for other threats or get a professionally completed Penetration Test.

### API1:2019 Broken Object Level Authorization

When using object-level permissions:

DO: Validate that the object can be accessed by the user using the method `.check_object_permissions(request, obj)`. Example:

```python
def get_object(self):
    obj = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
    self.check_object_permissions(self.request, obj)
    return obj
```

DO NOT: Override the method `get_object()` without checking if the request should have access to that object.

### API2:2019 Broken User Authentication

DO: Use the setting value DEFAULT_AUTHENTICATION_CLASSES with the correct classes for your project.

DO: Have authentication on every non-public API endpoint.

DO NOT: Overwrite the authentication class on a class-based (variable `authentication_classes`) or function-based (decorator `authentication_classes`) view unless you are confident about the change and understand the impact.

### API3:2019 Excessive Data Exposure

DO: Review the serializer and the information you are displaying.

If the serializer is inheriting from ModelSerializer DO NOT use the exclude Meta property.

DO NOT: Display more information that the minimum required.

### API4:2019 Lack of Resources & Rate Limiting

DO: Configure the setting DEFAULT_THROTTLE_CLASSES.

DO NOT: Overwrite the throttle class on a class-based (variable `throttle_classes`) or function-based (decorator `throttle_classes`) view unless you are confident about the change and understand the impact.

EXTRA: If possible rate limiting should also be done with a WAF or similar. DRF should be the last layer of rate limiting.

### API5:2019 Broken Function Level Authorization

DO: Change the default value (`'rest_framework.permissions.AllowAny'`) of DEFAULT_PERMISSION_CLASSES.

DO NOT: Use `rest_framework.permissions.AllowAny` except for public API endpoints.

DO: Use the setting value DEFAULT_PERMISSION_CLASSES with the correct classes for your project.

DO NOT: Overwrite the authorization class on a class-based (variable `permission_classes`) or function-based (decorator `permission_classes`) view unless you are confident about the change and understand the impact.

### API6:2019 Mass Assignment

When using ModelForms:

DO: Use Meta.fields (allowlist approach).

DO NOT: Use Meta.exclude (denylist approach).

DO NOT: Use `ModelForms.Meta.fields = "__all__"`

### API7:2019 Security Misconfiguration

DO: Setup Django settings `DEBUG` and `DEBUG_PROPAGATE_EXCEPTIONS` to False.

DO: Setup Django setting `SECRET_KEY` to a random value. Never hardcode secrets.

DO: Have a repeatable hardening process leading to fast and easy deployment of a properly locked down environment.

DO: Have an automated process to continuously assess the effectiveness of the configuration and settings in all environments.

DO: Ensure API can only be accessed by the specified HTTP verbs. All other HTTP verbs should be disabled.

DO NOT: Use default passwords

### API8:2019 Injection

DO: Validate, filter, and sanitize all client-provided data, or other data coming from integrated systems.

#### SQLi

DO: Use parametrized queries.

TRY NOT TO: Use dangerous methods like `raw()`, `extra()` and custom SQL (via `cursor.execute()`).

DO NOT: Add user input to dangerous methods (`raw()`, `extra()`, `cursor.execute()`).

#### RCE

DO NOT: Add user input to dangerous methods (`eval()`, `exec()` and `execfile()`).

DO NOT: Load user-controlled pickle files. This includes the pandas method `pandas.read_pickle()`.

DO NOT: Load user-controlled YAML files using the method `load()`.

DO: Use the `Loader=yaml.SafeLoader` for YAML files.

### API9:2019 Improper Assets Management

DO: Have an inventory of all API hosts and document important aspects of each one of them, focusing on the API environment (e.g., production, staging, test, development), who should have network access to the host (e.g., public, internal, partners) and the API version.

DO: Document all aspects of your API such as authentication, errors, redirects, rate limiting, cross-origin resource sharing (CORS) policy and endpoints, including their parameters, requests, and responses.

### API10:2019 Insufficient Logging & Monitoring

DO: Log all failed authentication attempts, denied access, and input validation errors with sufficient user context to identify suspicious or malicious accounts.

DO: Create logs in a format suited to be consumed by a log management solution and should include enough detail to identify the malicious actor.

DO: Handle logs as sensitive data, and their integrity should be guaranteed at rest and transit.

DO: Configure a monitoring system to continuously monitor the infrastructure, network, and the API functioning.

DO: Use a Security Information and Event Management (SIEM) system to aggregate and manage logs from all components of the API stack and hosts.

DO: Configure custom dashboards and alerts, enabling suspicious activities to be detected and responded to earlier.

DO: Establish effective monitoring and alerting so suspicious activities are detected and responded to in a timely fashion.

DO NOT: Log generic error messages such as: Log.Error("Error was thrown"); rather log the stack trace, error message and user ID who caused the error.

DO NOT: Log sensitive data such as user's passwords, API Tokens or PII.

## Other security Risks

Below is a list of security risks for APIs not discussed in the OWASP API Security Top 10.

### Business Logic Bugs

Any application in any technology can contain business logic errors that result in security bugs. Business logic bugs are difficult to impossible to detect using automated tools. The best ways to prevent business logic security bugs are to do threat model, security design review, code review, pair program and write unit tests.

### Secret Management

Secrets should never be hardcoded. The best practice is to use a Secret Manager. For more information review OWASP [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

## Updating Django and DRF and Having a Process for Updating Dependencies

An concern with every application, including Python applications, is that dependencies can have vulnerabilities.

One good practice is to audit the dependencies your project is using.

In general, it is important to have a process for updating dependencies. An example process might define three mechanisms for triggering an update of response:

- Every month/quarter dependencies in general are updated.
- Every week important security vulnerabilities are considered and potentially trigger an update.
- In EXCEPTIONAL conditions, emergency updates may need to be applied.

The Django Security team has a information on [How Django discloses security issues](https://docs.djangoproject.com/en/4.1/internals/security/#how-django-discloses-security-issues).

Finally, an important aspect when considering if a new dependency should be added or not to the project is the "Security Health" of the library. How often it's updated? Does it have known vulnerabilities? Does it have an active community? etc. Some tools can help with this task (E.g. [Snyk Advisor](https://snyk.io/advisor/python))

## SAST Tools

There are several excellent open-source static analysis security tools for Python that are worth considering, including:

Bandit – [Bandit](https://bandit.readthedocs.io/en/latest/) is a tool designed to find common security issues in Python. To do this Bandit processes each file, builds an Abstract Syntax Tree (AST) from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files it generates a report. Bandit was originally developed within the OpenStack Security Project and later rehomed to PyCQA.

Semgrep – [Semgrep](https://semgrep.dev/) is a fast, open-source, static analysis engine for finding bugs, detecting vulnerabilities in third-party dependencies, and enforcing code standards. Developed by “Return To Corporation” (usually referred to as r2c) and open-source contributors. It works based on rules, which can focus on security, language best practices, or something else. Creating a rule is easy and semgrep is very powerful. For Django there are 29 rules.

PyCharm Security – [Pycharm-security](https://pycharm-security.readthedocs.io/en/latest/index.html) is a plugin for PyCharm, or JetBrains IDEs with the Python plugin. The plugin looks at Python code for common security vulnerabilities and suggests fixes. It can also be executed from a Docker container. It has about 40 checks and some are Django specific.

## Related Articles and References

- [Django REST Framework (DRF) Secure Code Guidelines](https://openaccess.uoc.edu/handle/10609/147246)
- [Django’s security policies](https://docs.djangoproject.com/en/4.1/internals/security/)
- [Security in Django](https://docs.djangoproject.com/en/4.1/topics/security/)
