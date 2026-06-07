# Authorization Regression Testing Cheat Sheet

## Introduction

Authorization implementation is rarely static. As applications evolve, new API endpoints are added, data layers are refactored, and microservices are decoupled. While initial security testing might validate access controls at launch, the "Day 2" problem emerges quickly: **How do engineering teams ensure that new features or structural changes do not break existing authorization logic?**

[Broken Access Control (BAC)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) was ranked the number-one risk in the OWASP Top Ten 2021, and [Insecure Direct Object Reference (IDOR)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) is one of its most frequently exploited sub-categories. This cheat sheet provides actionable, architectural guidance on implementing automated authorization regression testing within the Software Development Life Cycle (SDLC). By shifting from manual, point-in-time penetration testing to continuous, developer-centric regression suites, engineering teams can catch BAC, IDOR, and tenant isolation failures before they reach production.

Key topics covered in this cheat sheet include:

- Designing an automated authorization test matrix.
- Common regression testing patterns for horizontal, vertical, and tenant isolation tests.
- Validating authorization schemas using API contracts.
- Integrating authorization tests into CI/CD pipelines.

## Authorization Test Matrix Design

> **Relationship to the Authorization Testing Automation Cheat Sheet**
>
> The [Authorization Testing Automation Cheat Sheet](Authorization_Testing_Automation_Cheat_Sheet.md) provides a foundational, XML-driven approach to building and executing an authorization matrix against REST services — including a full Java/JUnit integration test harness. **This cheat sheet extends that foundation** by focusing on the *continuous regression* dimension: how to design matrices in formats (YAML/JSON) suited to modern test runners, which specific failure patterns to prioritize in a regression suite (IDOR, vertical escalation, tenant boundary), how to couple tests to OpenAPI contracts, and how to gate pull requests automatically in CI/CD. If you are new to authorization test matrices, start with the [Authorization Testing Automation Cheat Sheet](Authorization_Testing_Automation_Cheat_Sheet.md) first, then return here for SDLC-integration guidance.

The foundation of continuous authorization testing is a structured mapping of rules that can be consumed by automated frameworks. Rather than writing scattered, one-off test cases, design a central matrix.

### Define the Access Policy Model

Before writing tests, explicitly define the application's access model using the **Actor-Resource-Action** pattern described in [OWASP WSTG - Testing for Authorization](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/):

- **Actor (Who):** The logical role or specific user attempting the operation (e.g., `Tenant_Admin`, `Standard_User`, `Anonymous_User`).
- **Resource (What):** The object or data being accessed (e.g., `Invoice_123`, `/api/v2/users`, `System_Settings`).
- **Action (How):** The operation being performed (e.g., `READ`, `CREATE`, `DELETE`, `EXECUTE`).

### Machine-Readable Rules

Store this matrix in a machine-readable format (e.g., JSON, YAML, or structured test fixtures) rather than a spreadsheet. This allows testing frameworks to dynamically generate test cases, reducing manual maintenance as the authorization policy evolves.

```yaml
# Example Test Fixture Definition
policies:
  - resource: "/api/invoices/{id}"
    method: "GET"
    owner_role: "tenant_user"
    allowed_roles: ["tenant_admin", "system_auditor"]
    denied_roles: ["anonymous", "different_tenant_user"]
    expected_denial_code: 403
```

## Regression Testing Patterns

Automated tests should specifically target the ways authorization usually degrades over time. Implement the following test patterns in your regression suite.

### Horizontal Escalation (IDOR) Validation

[Horizontal privilege escalation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) occurs when a user accesses a resource belonging to another user with the same privilege level. The [OWASP IDOR Prevention Cheat Sheet](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md) describes the root cause: missing server-side ownership checks on object identifiers.

- **Pattern:** The "Multi-User Replay."
- **Implementation:** Authenticate as User A and create Resource X. Capture the resource identifier. Authenticate as User B (same role, different account) and attempt to read, update, and delete Resource X.
- **Assertion:** The system must return a [`403 Forbidden`](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4) or `404 Not Found` (to avoid information leakage about resource existence), never a `200 OK`.

### Vertical Escalation Validation

Vertical escalation occurs when a lower-privileged user accesses functions reserved for higher-privileged roles. This maps directly to [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html).

- **Pattern:** The "Role Demotion Check."
- **Implementation:** Build a suite of tests that target administrative endpoints (e.g., `/api/admin/users/delete`). Iterate through all non-administrative roles (including unauthenticated users) and attempt to execute the endpoints.
- **Assertion:** Ensure the endpoints explicitly reject the requests. Relying on UI hiding is insufficient; [the API layer must enforce the check](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls) — client-side controls are trivially bypassed.

### Tenant Isolation Breakage

In multi-tenant SaaS applications, logic changes (like caching or query modifications) can inadvertently leak data across tenant boundaries, a scenario covered by the [Multi-Tenant Security Cheat Sheet](Multi_Tenant_Security_Cheat_Sheet.md).

- **Pattern:** The "Cross-Tenant Boundary Test."
- **Implementation:** Provision two distinct tenants (Tenant Alpha and Tenant Beta) in the test environment. Seed data into Tenant Alpha. Execute broad read queries (e.g., `GET /api/all-records`) as a user from Tenant Beta.
- **Assertion:** Assert that the response payload contains absolutely no records belonging to Tenant Alpha. Even a single leaked record identifier constitutes a critical failure.

## Contract-Driven Authorization Validation

When building APIs, the authorization schema should be explicitly defined in the API contract. The [OpenAPI Specification](https://spec.openapis.org/oas/v3.1.0#security-scheme-object) provides `securitySchemes` and `security` fields to formally declare authorization requirements at both the global and per-operation level.

- **Schema-Aware Testing:** Use the OpenAPI definition as the source of truth for authorization requirements. If the specification states an endpoint requires an [OAuth2](https://www.rfc-editor.org/rfc/rfc6749) scope of `read:invoices`, the testing framework should automatically verify that tokens lacking this scope receive a [`401 Unauthorized`](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2) or `403 Forbidden` response. Tools such as [Schemathesis](https://schemathesis.readthedocs.io/en/stable/) can read the OpenAPI document and auto-generate these negative test cases.
- **Middleware Enforcement:** Configure API gateways or web frameworks to automatically enforce the security definitions present in the OpenAPI contract. Regression tests should validate that this middleware has not been bypassed or disabled following a refactor.

## Automated Testing Framework Integration

Authorization tests must live alongside functional tests in the developer's standard toolkit, following the guidance in [OWASP SAMM: Security Testing](https://owaspsamm.org/model/verification/security-testing/).

- **Test Frameworks:** Use standard test runners (e.g., [`pytest`](https://docs.pytest.org/) for Python, [`Jest`](https://jestjs.io/) for JavaScript, [`JUnit`](https://junit.org/junit5/) for Java) to build authorization suites. This keeps the barrier to entry low and ensures the tests run in the same CI pipeline as functional tests.
- **Property-Based Testing:** Tools like [Schemathesis](https://schemathesis.readthedocs.io/en/stable/) or [Dredd](https://dredd.org/en/latest/) can read an OpenAPI specification and automatically generate negative test cases (e.g., sending requests without tokens, with expired tokens, or with tokens missing required scopes) to ensure the API fails securely.
- **Session Switching:** Design the test suite to quickly and cheaply swap authentication context (e.g., swapping JWTs in the `Authorization` header as defined in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)) without requiring a full login flow for every test.

## CI/CD Gating and SDLC Integration

The value of an authorization regression suite is only realized if it prevents vulnerable code from merging. The [OWASP CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md) describes broader pipeline hardening; the recommendations below focus specifically on authorization gates.

- **Blocking PR Builds:** The authorization test suite must be a required check in the CI/CD pipeline (e.g., [GitHub Actions](https://docs.github.com/en/actions), GitLab CI). If an authorization test fails, the Pull Request cannot be merged.
- **Dedicated Test Suites:** Tag or group authorization tests distinctly (e.g., `@pytest.mark.authz` or a dedicated `authz-tests` npm script). This allows developers to run them quickly and independently during local development.
- **Monitoring in Lower Environments:** Configure CI environments to flag unusual volumes of [`401 Unauthorized`](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2) or [`403 Forbidden`](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4) responses during integration testing, which may indicate that a developer's functional changes are colliding with existing security controls.

## References

### OWASP Resources

- [OWASP Top Ten 2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Web Security Testing Guide v4.2 — Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [OWASP WSTG — Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP Proactive Controls C7: Enforce Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)
- [OWASP Software Assurance Maturity Model (SAMM): Security Testing](https://owaspsamm.org/model/verification/security-testing/)
- [OWASP Application Security Verification Standard (ASVS) 4.0 — V4: Access Control](https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.pdf)

### Related OWASP Cheat Sheets

- [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md)
- [Authorization Testing Automation Cheat Sheet](Authorization_Testing_Automation_Cheat_Sheet.md)
- [Insecure Direct Object Reference Prevention Cheat Sheet](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)
- [Multi-Tenant Security Cheat Sheet](Multi_Tenant_Security_Cheat_Sheet.md)
- [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md)

### Standards and Specifications

- [OpenAPI Specification 3.1.0 — Security Scheme Object](https://spec.openapis.org/oas/v3.1.0#security-scheme-object)
- [OAuth 2.0 Authorization Framework (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749)
- [OAuth 2.0 Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750)
- [HTTP Semantics (RFC 9110) — 401 Unauthorized](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2)
- [HTTP Semantics (RFC 9110) — 403 Forbidden](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

### Tools

- [Schemathesis — Property-based API testing](https://schemathesis.readthedocs.io/en/stable/)
- [Dredd — HTTP API Testing Framework](https://dredd.org/en/latest/)
- [pytest — Python test framework](https://docs.pytest.org/)
- [JUnit 5 — Java test framework](https://junit.org/junit5/)
- [Jest — JavaScript test framework](https://jestjs.io/)
