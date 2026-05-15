# Authorization Regression Testing Cheat Sheet

## Introduction

Authorization implementation is rarely static. As applications evolve, new API endpoints are added, data layers are refactored, and microservices are decoupled. While initial security testing might validate access controls at launch, the "Day 2" problem emerges quickly: **How do engineering teams ensure that new features or structural changes do not break existing authorization logic?**

This cheat sheet provides actionable, architectural guidance on implementing automated authorization regression testing within the Software Development Life Cycle (SDLC). By shifting from manual, point-in-time penetration testing to continuous, developer-centric regression suites, engineering teams can catch Broken Access Control (BAC), Insecure Direct Object Reference (IDOR), and tenant isolation failures before they reach production.

Key topics covered in this cheat sheet include:

- Designing an automated authorization test matrix.
- Common regression testing patterns for horizontal, vertical, and tenant isolation tests.
- Validating authorization schemas using API contracts.
- Integrating authorization tests into CI/CD pipelines.

## Authorization Test Matrix Design

The foundation of continuous authorization testing is a structured mapping of rules that can be consumed by automated frameworks. Rather than writing scattered, one-off test cases, design a central matrix.

### Define the Access Policy Model

Before writing tests, explicitly define the application's access model using the **Actor-Resource-Action** pattern:

- **Actor (Who):** The logical role or specific user attempting the operation (e.g., `Tenant_Admin`, `Standard_User`, `Anonymous_User`).
- **Resource (What):** The object or data being accessed (e.g., `Invoice_123`, `/api/v2/users`, `System_Settings`).
- **Action (How):** The operation being performed (e.g., `READ`, `CREATE`, `DELETE`, `EXECUTE`).

### Machine-Readable Rules

Store this matrix in a machine-readable format (e.g., JSON, YAML, or structured test fixtures) rather than a spreadsheet. This allows testing frameworks to dynamically generate test cases.

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

Horizontal escalation occurs when a user accesses a resource belonging to another user with the same privilege level.

- **Pattern:** The "Multi-User Replay."
- **Implementation:** Authenticate as User A and create Resource X. Capture the resource identifier. Authenticate as User B (same role, different account) and attempt to read, update, and delete Resource X.
- **Assertion:** The system must return a `403 Forbidden` or `404 Not Found` (to avoid information leakage), never a `200 OK`.

### Vertical Escalation Validation

Vertical escalation occurs when a lower-privileged user accesses functions reserved for higher-privileged roles.

- **Pattern:** The "Role Demotion Check."
- **Implementation:** Build a suite of tests that target administrative endpoints (e.g., `/api/admin/users/delete`). Iterate through all non-administrative roles (including unauthenticated users) and attempt to execute the endpoints.
- **Assertion:** Ensure the endpoints explicitly reject the requests. Relying on UI hiding is insufficient; the API layer must enforce the check.

### Tenant Isolation Breakage

In multi-tenant SaaS applications, logic changes (like caching or query modifications) can inadvertently leak data across tenant boundaries.

- **Pattern:** The "Cross-Tenant Boundary Test."
- **Implementation:** Provision two distinct tenants (Tenant Alpha and Tenant Beta) in the test environment. Seed data into Tenant Alpha. Execute broad read queries (e.g., `GET /api/all-records`) as a user from Tenant Beta.
- **Assertion:** Assert that the response payload contains absolutely no records belonging to Tenant Alpha.

## Contract-Driven Authorization Validation

When building APIs, the authorization schema should be explicitly defined in the API contract (e.g., OpenAPI/Swagger).

- **Schema-Aware Testing:** Use the OpenAPI definition as the source of truth for authorization requirements. If the specification states an endpoint requires an OAuth2 scope of `read:invoices`, the testing framework should automatically verify that tokens lacking this scope are rejected.
- **Middleware Enforcement:** Configure API gateways or web frameworks to automatically enforce the security definitions present in the OpenAPI contract. Regression tests should validate that this middleware has not been bypassed or disabled.

## Automated Testing Framework Integration

Authorization tests must live alongside functional tests in the developer's standard toolkit.

- **Test Frameworks:** Use standard test runners (e.g., `pytest` for Python, `Jest` for JavaScript, `JUnit` for Java) to build authorization suites.
- **Property-Based Testing:** Tools like Schemathesis or Dredd can read an OpenAPI specification and automatically generate negative test cases (e.g., sending requests without tokens, with expired tokens, or with tokens missing required scopes) to ensure the API fails securely.
- **Session Switching:** Design the test suite to quickly and cheaply swap authentication context (e.g., swapping JWTs in the `Authorization` header) without requiring a full login flow for every test.

## CI/CD Gating and SDLC Integration

The value of an authorization regression suite is only realized if it prevents vulnerable code from merging.

- **Blocking PR Builds:** The authorization test suite must be a required check in the CI/CD pipeline (e.g., GitHub Actions, GitLab CI). If an authorization test fails, the Pull Request cannot be merged.
- **Dedicated Test Suites:** Tag or group authorization tests distinctly (e.g., `@pytest.mark.authz` or a dedicated `authz-tests` npm script). This allows developers to run them quickly and independently during local development.
- **Monitoring in Lower Environments:** Configure CI environments to flag unusual volumes of `401 Unauthorized` or `403 Forbidden` responses during integration testing, which may indicate that a developer's functional changes are colliding with existing security controls.

## References

- [OWASP Access Control Cheat Sheet](../cheatsheets/Access_Control_Cheat_Sheet.md)
- [OWASP Authorization Cheat Sheet](../cheatsheets/Authorization_Cheat_Sheet.md)
- [OWASP Authorization Testing Automation Cheat Sheet](../cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)
- [OWASP Application Security Verification Standard (ASVS) V4 - V4 Access Control](https://github.com/OWASP/ASVS/tree/master/4.0/en/0x12-V4-Access-Control)
