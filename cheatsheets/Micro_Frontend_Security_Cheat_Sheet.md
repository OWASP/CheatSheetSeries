# Micro-Frontend Security Cheat Sheet

## Introduction

Micro-frontend architecture extends the principles of microservices to the frontend layer. It allows autonomous development teams to build, test, and deploy decoupled feature modules independently while integrating them into a unified user-facing shell application.

However, combining multiple independent web applications into a single browser runtime introduces complex multi-application trust boundaries. Traditional single-page application (SPA) security assumptions—such as a single trusted codebase, unified state containers, and centralized client routing—may no longer apply.

Micro-frontend security should therefore focus on clearly defining application boundaries, controlling communication between applications, isolating sensitive state, enforcing authorization independently, and securing dynamically loaded code.

This cheat sheet covers:

- Multi-application runtime boundaries
- Inter-application communication
- Dynamic module integration
- Cross-application state and storage
- Host-to-remote authorization
- Runtime isolation and sandboxing
- Software supply-chain security

The following topics are outside the primary scope and should be addressed using the corresponding OWASP Cheat Sheets:

- General web application vulnerabilities
- JavaScript and DOM-based XSS prevention
- OAuth2 token issuance and server-side authentication flows
- General session management

## Architectural Topologies and Threats

Micro-frontends can be implemented using different runtime topologies. Each topology changes the application's trust boundaries and introduces different security considerations.

### Webpack Module Federation

Webpack Module Federation allows remote JavaScript modules to be dynamically fetched and executed inside the host application's JavaScript runtime.

Because code from multiple repositories executes in the same JavaScript context, a compromised remote module can potentially:

- Execute arbitrary JavaScript in the host context.
- Access objects exposed by the host application.
- Manipulate the host DOM.
- Access client-side storage available to the origin.
- Interact with application state and APIs accessible to JavaScript.

Treat dynamically loaded remote modules as trusted code only when their source, deployment pipeline, integrity, and authorization boundaries are appropriately controlled.

### Web Components and Shadow DOM

Web Components can encapsulate custom elements and provide scoped DOM and styling through Shadow DOM.

Shadow DOM should **not** be treated as a security boundary. It provides encapsulation rather than cryptographic or process-level isolation.

Do not assume that:

```javascript
attachShadow({ mode: 'closed' })
```

prevents JavaScript executing in the host context from interacting with component internals.

Use Shadow DOM for modularity and encapsulation, not for isolating untrusted code.

### Iframe-Based Composition

Iframes provide browser-enforced origin boundaries and can provide stronger isolation between independently deployed applications.

When using iframes:

- Apply a restrictive `sandbox` policy.
- Restrict communication through `postMessage`.
- Validate message origins.
- Avoid unnecessarily permissive CORS policies.
- Prevent unauthorized frame navigation.

Example:

```html
<iframe
    src="https://trusted-remote.example.com/widget"
    sandbox="allow-scripts allow-same-origin">
</iframe>
```

Only grant sandbox permissions that are required by the micro-frontend.

### Server-Side and Edge Composition

Server-side or edge-side composition stitches micro-frontend fragments together before the response reaches the browser.

Security considerations include:

- Fragment injection.
- SSRF during server-side composition.
- Inconsistent security headers between fragments.
- Trust relationships between independently managed services.

## Runtime Isolation and Secure Communication

Micro-frontends frequently execute within shared browser environments. Explicit isolation and communication controls are therefore required.

### Protecting the Global Runtime

A vulnerable micro-frontend can potentially modify shared JavaScript objects and prototypes, such as:

```javascript
Object.prototype
Array.prototype
window
```

Avoid exposing mutable global objects between micro-frontends.

Where state or utilities must be shared:

- Prefer immutable data structures.
- Minimize global state.
- Define explicit APIs between applications.
- Validate data crossing application boundaries.
- Avoid allowing remote applications to modify host application internals.

For prototype manipulation risks, see the Prototype Pollution Prevention Cheat Sheet.

### Securing `window.postMessage`

When micro-frontends communicate across origins using `window.postMessage`, always validate the sender's origin and the structure of the received message.

Do not process arbitrary messages:

```javascript
window.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    eval(data.action);
});
```

Instead, validate the origin and message contents:

```javascript
window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted-micro-app.example.com') {
        return;
    }

    const { action, payload } = event.data;

    if (typeof action !== 'string' || !isValidAction(action)) {
        return;
    }

    processTrustedPayload(action, payload);
});
```

Use an explicit allowlist of trusted origins.

### Restricting Outbound Messages

Do not use a wildcard target origin when sending sensitive information:

```javascript
targetWindow.postMessage(
    { type: 'USER_UPDATED', userId: '12345' },
    '*'
);
```

Specify the expected target origin:

```javascript
targetWindow.postMessage(
    { type: 'USER_UPDATED', userId: '12345' },
    'https://trusted-micro-app.example.com'
);
```

### Pub/Sub Event Buses

Treat data received through shared event buses as untrusted input.

Avoid directly inserting event data into the DOM:

```javascript
element.innerHTML = event.data;
```

Apply appropriate validation and context-aware output encoding before using data in security-sensitive contexts.

## State, Storage, Authentication and Authorization

Sharing state between micro-frontends can create unintended access to credentials, tenant data, application state, and user information.

### `localStorage` and `sessionStorage`

`localStorage` is accessible to scripts running under the same origin. Therefore, a vulnerable micro-frontend may be able to access sensitive information stored there by another application.

Avoid storing sensitive authentication credentials or raw access tokens in shared client-side storage when untrusted or independently managed modules are loaded.

A Backend-for-Frontend (BFF) architecture can reduce this exposure by keeping authentication credentials on the server side and using appropriately configured cookies.

For example, authentication cookies should generally use appropriate security attributes such as:

```http
HttpOnly
Secure
SameSite=Strict
```

The exact `SameSite` configuration should match the application's legitimate cross-site requirements.

### Multi-Tenant State Isolation

Applications supporting multiple tenants must prevent data from one tenant from becoming accessible to another.

Shared stores such as Redux or Zustand should have clearly defined boundaries and must not unintentionally expose:

- Tenant-specific information.
- User information.
- Authorization state.
- Internal application state.
- Sensitive cached API responses.

### Defense-in-Depth Authorization

Do not assume that authorization performed by the host shell automatically protects remote micro-frontends.

For example, hiding a navigation element in the host application does not provide sufficient protection if the remote application can still invoke a privileged backend API.

Every backend API must independently enforce authorization.

A micro-frontend should therefore not rely solely on:

```text
Host UI permission
        ↓
Remote UI
        ↓
Backend
```

Instead, authorization should ultimately be enforced at the backend:

```text
Host UI ────────┐
                ├──> Remote Application ───> Backend Authorization
Remote UI ──────┘
```

Use the Authorization and Access Control Cheat Sheets for additional guidance.

## Dynamic Loading and Software Supply Chain Security

Dynamic remote loading significantly expands the software supply-chain attack surface.

### Securing Remote Modules

When loading remote modules:

- Pin exact versions where possible.
- Avoid uncontrolled floating versions.
- Require HTTPS.
- Verify the source of remote assets.
- Protect the repositories and deployment infrastructure that publish remote modules.
- Review dependencies used by independently deployed micro-frontends.

Where supported by the loading mechanism, use Subresource Integrity (SRI) to help detect unexpected changes to remotely loaded resources.

### Content Security Policy

Use Content Security Policy (CSP) to restrict where executable resources can be loaded from.

Example:

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self' https://trusted-host.example.com https://trusted-cdn.example.com;
    object-src 'none';
```

Keep the list of permitted script sources as narrow as practical.

For complete CSP guidance, see the Content Security Policy Cheat Sheet.

### CI/CD Pipeline Isolation

Treat each micro-frontend repository and CI/CD pipeline as an independent security perimeter.

A compromise of one team's repository or pipeline should not automatically provide write or deployment permissions to:

- The host shell.
- Other micro-frontends.
- Shared production infrastructure.

Use separate credentials, permissions, deployment controls, and repository access wherever practical.

## Security Checklist

Use the following checklist when reviewing a micro-frontend architecture:

| Verification Item                                                              | Status | Associated Control              |
| :----------------------------------------------------------------------------- | :----: | :------------------------------ |
| Are all cross-app `postMessage` listeners validating the exact `event.origin`? |   [ ]  | Inter-application communication |
| Are outbound `postMessage` calls avoiding wildcard (`*`) target origins?       |   [ ]  | Inter-application communication |
| Are remote modules loaded over HTTPS?                                          |   [ ]  | Remote module loading           |
| Is the integrity of dynamically loaded resources verified where supported?     |   [ ]  | Supply-chain security           |
| Is a restrictive Content Security Policy implemented?                          |   [ ]  | CSP                             |
| Are sensitive tokens kept out of shared client-side storage?                   |   [ ]  | Storage security                |
| Are tenant boundaries enforced in shared state?                                |   [ ]  | State isolation                 |
| Do remote micro-frontends have independent backend authorization checks?       |   [ ]  | Authorization                   |
| Are iframe sandbox permissions restricted to required capabilities?            |   [ ]  | Runtime isolation               |
| Are CI/CD pipelines isolated between micro-frontend teams?                     |   [ ]  | Supply-chain security           |
| Are shared global objects and mutable state minimized?                         |   [ ]  | Runtime isolation               |

## References

- [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [DOM-based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md)
- [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md)
- [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md)
- [Access Control Cheat Sheet](Access_Control_Cheat_Sheet.md)
- [Content Security Policy Cheat Sheet](Content_Security_Policy_Cheat_Sheet.md)
- [Prototype Pollution Prevention Cheat Sheet](Prototype_Pollution_Prevention_Cheat_Sheet.md)
- [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md)
- [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md)
- [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md)
- [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md)
- [GitHub Actions Security Cheat Sheet](GitHub_Actions_Security_Cheat_Sheet.md)
