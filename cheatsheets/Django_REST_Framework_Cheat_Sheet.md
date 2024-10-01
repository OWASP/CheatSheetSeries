# Django REST Framework (DRF) Cheat Sheet

## Introduction

This cheat sheet provides Django REST Framework security advice for developers. It is a basic set of guidelines for Django REST developers who need to secure fundamental aspects of an application.

## What is a view in Django?

A view in Django is a Python class or a function that returns a web response after it receives a web request. That response can be in simple HTTP, an HTML template, or an HTTP redirect request that redirects a user to another page.

## Settings

To configure the Django REST Framework (DRF), you will need to access the namespace REST_FRAMEWORK. Normally, you will find this namespace in the settings.py file. From a security perspective, the most relevant items are:

### DEFAULT_AUTHENTICATION_CLASSES

A list of authentication classes that are used by default to identify which user is authenticated by accessing the request.user or request.auth properties. These classes are 'rest_framework.authentication.SessionAuthentication' (session authentication) and 'rest_framework.authentication.BasicAuthentication' (basic authentication).

### DEFAULT_PERMISSION_CLASSES

A list of permission classes that defines the default set of permissions that Django checks before a view can be accessed. Since the default is 'rest_framework.permissions.AllowAny', that means **unless the default permission class is changed, everybody can access every view by default.**

### DEFAULT_THROTTLE_CLASSES

A list of throttle classes that determines the default set of throttles checked at the start of a view. **By default, there is no throttling in place since the default class is empty.**

### DEFAULT_PAGINATION_CLASS

The default class to use for queryset pagination. **In Django, pagination is disabled by default.** Without proper pagination, Denial of Service (DoS) problems or attacks could occur if there’s a lot of data.

## OWASP API Security Top 10 (2019)

The [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) is a list of the most critical security risks for APIs that was developed by the [Open Web Application Security Project (OWASP)](https://owasp.org/). It is designed to help organizations identify and prioritize the most significant risks to their APIs so that they can implement appropriate controls to mitigate those risks.

This section uses the 2019 version of the API Security Top 10. The best approach to securing your web API is to start at the top threat (A1 below) and work your way down. This will ensure that any time spent on security will be spent most effectively because you will cover the top threats first. After you look at the Top 10, it is generally advisable to assess for other threats or get a professional penetration test.

### API1:2019 Broken Object Level Authorization

When using object-level permissions, you should make sure that the object can be accessed by the user using the method `.check_object_permissions(request, obj)`.

Example:

```python
def get_object(self):
    obj = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
    self.check_object_permissions(self.request, obj)
    return obj
```

DO NOT override the method `get_object()` without checking if the request should have access to that object.

### API2:2019 Broken User Authentication

To prevent broken user authentication, use the setting value DEFAULT_AUTHENTICATION_CLASSES with the correct classes for your project and have authentication on every non-public API endpoint. Do not overwrite the authentication class on a class-based (variable `authentication_classes`) or function-based (decorator `authentication_classes`) view unless you are confident about the change and understand the impact.

### API3:2019 Excessive Data Exposure

To prevent this problem, only display the minimum amount of required information. Make sure you review the serializer and the information you are displaying. If the serializer is inheriting from ModelSerializer, DO NOT use the exclude Meta property.

### API4:2019 Lack of Resources & Rate Limiting

To prevent this problem, configure the setting DEFAULT_THROTTLE_CLASSES and DO NOT overwrite the throttle class on a class-based (variable `throttle_classes`) or function-based (decorator `throttle_classes`) view, unless you are confident about the change and understand the impact.

EXTRA: If possible, do rate limiting with a WAF or similar. DRF should be the last layer of rate limiting.

### API5:2019 Broken Function Level Authorization

To stop this problem, change the default value (`'rest_framework.permissions.AllowAny'`) of DEFAULT_PERMISSION_CLASSES. Use the setting value DEFAULT_PERMISSION_CLASSES with the correct classes for your project.

DO NOT use `rest_framework.permissions.AllowAny` except for public API endpoints and DO NOT overwrite the authorization class on a class-based (variable `permission_classes`) or function-based (decorator `permission_classes`) view unless you are confident about the change and understand the impact.

### API6:2019 Mass Assignment

To prevent this problem, use Meta.fields (allowlist approach) when using ModelForms. DO NOT use Meta.exclude (denylist approach) or `ModelForms.Meta.fields = "__all__"`

### API7:2019 Security Misconfiguration

To stop this problem, you must have a repeatable hardening process leading to fast and easy deployment of a properly locked down environment. Have an automated process to continuously assess the effectiveness of the configuration and settings in all environments.

**DO NOT use default passwords. Set the Django settings `DEBUG` and `DEBUG_PROPAGATE_EXCEPTIONS` to False. Ensure API can only be accessed by the specified HTTP verbs. All other HTTP verbs should be disabled. Set `SECRET_KEY` to a random value and NEVER hardcode secrets.**

**DO validate, filter, and sanitize all client-provided data, or other data coming from integrated systems.**

### API8:2019 Injection

#### SQLi

**To prevent this problem, use parametrized queries.** Be careful when using dangerous methods like `raw()`, `extra()` and custom SQL (via `cursor.execute()`). DO NOT add user input to dangerous methods (`raw()`, `extra()`, `cursor.execute()`).

#### RCE

To stop this problem, use the `Loader=yaml.SafeLoader` for YAML files. DO NOT load user-controlled YAML files using the method `load()`.

Also, DO NOT add user input to dangerous methods (`eval()`, `exec()` and `execfile()`) and DO NOT load user-controlled pickle files, which includes the pandas method `pandas.read_pickle()`.

### API9:2019 Improper Assets Management

To prevent this problem, create an inventory of all API hosts. In this inventory, document the important aspects of each host. Focus on the API version and the API environment (e.g., production, staging, test, development) and determine who should have network access to the host (e.g., public, internal, partners). Make sure you document all aspects of your API such as authentication, errors, redirects, rate limiting, cross-origin resource sharing (CORS) policy and endpoints, including their parameters, requests, and responses.

### API10:2019 Insufficient Logging & Monitoring

For proper logging and monitoring capabilities, do the following:

--Log all failed authentication attempts, denied access, and input validation errors with sufficient user context to identify suspicious or malicious accounts.

--Create logs in a format suited to be consumed by a log management solution and include enough detail to identify the malicious actor.

--Handle logs as sensitive data, and their integrity should be guaranteed at rest and transit.

--Configure a monitoring system to continuously monitor the infrastructure, network, and the API functioning.

--Use a Security Information and Event Management (SIEM) system to aggregate and manage logs from all components of the API stack and hosts.

--Configure custom dashboards and alerts, enabling suspicious activities to be detected and responded to earlier.

--Establish effective monitoring and alerting so suspicious activities are detected and responded to in a timely fashion.

DO NOT:

--Log generic error messages such as: Log.Error("Error was thrown"); rather log the stack trace, error message and user ID who caused the error.

--Log sensitive data such as user's passwords, API Tokens or PII.

## Other Security Risks

Below is a list of security risks for APIs not discussed in the OWASP API Security Top 10.

### Business Logic Bugs

Be aware of possible business logic errors that result in security bugs. Since business logic bugs are difficult to impossible to detect using automated tools, the best ways to prevent business logic security bugs are use threat models, do security design reviews, do code reviews, pair programs and write unit tests.

### Secret Management

**Secrets should never be hardcoded. The best practice is to use a Secret Manager.** For more information review OWASP [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

## Updating Django and DRF and Having a Process for Updating Dependencies

All applications have dependencies and those dependencies can have vulnerabilities. One good practice is to audit the dependencies your project is using. In general, it is important to have a process for updating dependencies. A sample process might define three mechanisms for triggering an update of response:

--Every month/quarter dependencies in general are updated.
--Every week important security vulnerabilities are considered and potentially trigger an update.
--In EXCEPTIONAL conditions, emergency updates may need to be applied.

The Django Security team has information on [How Django discloses security issues](https://docs.djangoproject.com/en/4.1/internals/security/#how-django-discloses-security-issues).

When a library is under consideration, consider the "Security Health" of the library. How often it's updated? Does it have known vulnerabilities? Does it have an active community? etc. Some tools can help with this task (E.g. [Snyk Advisor](https://snyk.io/advisor/python))

## SAST Tools

There are several excellent open-source static analysis security tools for Python that are worth considering, including:

Bandit – [Bandit](https://bandit.readthedocs.io/en/latest/) is a tool designed to find common security issues in Python. Bandit processes each file, builds an Abstract Syntax Tree (AST) from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files it generates a report. Bandit was originally developed within the OpenStack Security Project and later rehomed to PyCQA.

Semgrep – [Semgrep](https://semgrep.dev/) is a fast, open-source, static analysis engine for finding bugs, detecting vulnerabilities in third-party dependencies, and enforcing code standards. Developed by “Return To Corporation” (usually referred to as r2c) and open-source contributors. It works based on rules, which can focus on security, language best practices, or something else. Creating a rule is easy and semgrep is very powerful. For Django there are 29 rules.

PyCharm Security – [Pycharm-security](https://pycharm-security.readthedocs.io/en/latest/index.html) is a plugin for PyCharm, or JetBrains IDEs with the Python plugin. The plugin looks at Python code for common security vulnerabilities and suggests fixes. It can also be executed from a Docker container. It has about 40 checks and some are Django specific.

## Related Articles and References

- [Django REST Framework (DRF) Secure Code Guidelines](https://openaccess.uoc.edu/handle/10609/147246)
- [Django’s security policies](https://docs.djangoproject.com/en/4.1/internals/security/)
- [Security in Django](https://docs.djangoproject.com/en/4.1/topics/security/)
