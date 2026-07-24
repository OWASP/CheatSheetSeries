# React Security Cheat Sheet

## Introduction

React is a widely used JavaScript library for building user interfaces. While React provides some built-in protections against common vulnerabilities, it does not enforce secure coding practices by default, and several React patterns introduce security risks that are easy to overlook. As React architectures increasingly move toward the server through patterns such as Server-Side Rendering (SSR) and React Server Components (RSC), the attack surface has expanded beyond traditional client-side vulnerabilities. This cheat sheet provides practical guidance
for developers building React applications to avoid the most common security pitfalls across both client and server rendering contexts.

Key areas covered:

- Preventing Cross-Site Scripting (XSS) through safe rendering patterns
- Protecting sensitive data in client state and server-side rendering
- Securing authentication tokens and managing authorization in the UI
- Hardening server-side rendered (SSR) React applications
- Managing third-party dependency and supply chain risk
- Defending against AI-introduced vulnerabilities in developer tooling and the browser runtime

## Cross-Site Scripting (XSS) Prevention

Cross-Site Scripting (XSS) occurs when an attacker injects malicious scripts into a web page that are then executed in another user's browser. React escapes dynamic content rendered through JSX by default, converting special characters such as `<`, `>`, and `"` into their HTML-encoded equivalents so the browser treats them as text rather than executable code. This protection applies only to content rendered through JSX. Several React patterns bypass this protection entirely and must be handled with care.

Related CWE(Common Weakness Enumeration): [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

### Avoid Unsafe HTML Injection with dangerouslySetInnerHTML

React provides `dangerouslySetInnerHTML` as an escape hatch for rendering raw HTML — for example, content produced by a rich text editor or a Content Management System (CMS). When used without sanitization, it bypasses React's built-in escaping and allows injected scripts or malicious event handlers to execute in the browser.

Always sanitize HTML content before passing it to `dangerouslySetInnerHTML`. Use a dedicated HTML sanitization library such as [DOMPurify](https://github.com/cure53/DOMPurify), which parses the HTML in an isolated sandbox, removes dangerous tags and attributes, and returns a safe HTML string.

```jsx
// Illustrative example — not production-ready
import DOMPurify from "dompurify";

const clean = DOMPurify.sanitize(rawHTML);
return <div dangerouslySetInnerHTML={ { __html: clean } } />;
```

Sanitize content on the server before storing it, and again on the client before rendering. Client-side sanitization alone does not prevent malicious content from being stored in your database and served to other consumers such as mobile clients or third-party integrations.

HTML injection via unsanitized content can also enable DOM Clobbering — where injected elements with specific id or name attributes overwrite global JavaScript variables your application depends on. For guidance see [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)

Related CWE: [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

### Validate URLs Before Rendering

React does not sanitize the `href`, `src`, or `action` attributes. This creates two distinct risks. First, an attacker can supply a `javascript:` URL which the browser executes as code when the user interacts with the element — a form of DOM-based XSS delivered through an attribute. Second, an attacker can supply a valid `https://` URL pointing to a malicious external site, redirecting users to phishing pages that impersonate your application.

Validate both the URL scheme and the destination hostname before rendering any user-supplied URL into an attribute. Scheme validation alone prevents code execution via `javascript:`, `data:`, or `vbscript:` URLs but does
not prevent open redirect attacks where the attacker supplies a valid `https://` URL pointing to their own site.

```jsx
// ❌ Unsafe — user-supplied URL rendered without validation
<a href={userSuppliedUrl}>Click here</a>

// ❌ Insufficient — scheme check alone does not prevent open redirect
const isSafe = url.startsWith('https://');
<a href={isSafe ? url : '#'}>Click here</a>

// ✅ Safe — validate both scheme and hostname
const url = new URL(userSuppliedUrl);
const isSafe =
(url.protocol === 'https:' || url.protocol === 'http:') &&
url.hostname === 'yourdomain.com';
<a href={isSafe ? userSuppliedUrl : '#'}>Click here</a>
```

Where the destination cannot be controlled — such as in user-generated content or comment sections — intercept external navigation with a redirect warning page to inform users they are leaving your application rather than silently following the link.

High-impact URL sinks include `<iframe src>`, `<embed src>`, and `<object data>`. Unlike `<a href>`, these load their target automatically on page render without any user interaction, making them especially dangerous. The `<iframe srcdoc>` attribute renders an HTML string directly as a document inside the frame and must never receive user-supplied content without sanitization. Apply the same scheme and hostname validation to all of these attributes.

```jsx
// ❌ Unsafe — loads automatically on render without user interaction
<iframe src={userSuppliedUrl} />
<embed src={userSuppliedUrl} />

// ❌ Unsafe — srcdoc renders raw HTML directly inside the frame
<iframe srcdoc={userContent} />

// ✅ Safe — validate scheme and hostname before rendering any URL sink
const url = new URL(userSuppliedUrl);
const isSafe = (url.protocol === 'https:' || url.protocol === 'http:') && url.hostname === 'yourdomain.com';
<iframe src={isSafe ? userSuppliedUrl : 'about:blank'} />

// ✅ Safe — sanitize before passing to srcdoc
import DOMPurify from 'dompurify';
<iframe srcdoc={DOMPurify.sanitize(userContent)} />
```

Related CWEs: [CWE-79: Improper Neutralization of Input During Web Page Generation(XSS)](https://cwe.mitre.org/data/definitions/79.html),[CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html),[CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

### Avoid Direct DOM Manipulation

React's `useRef` hook provides direct access to underlying DOM nodes. Setting `.innerHTML` on a ref bypasses React's rendering pipeline entirely and injects content directly into the DOM without any escaping or sanitization, creating the same risk as `dangerouslySetInnerHTML` without any of the visibility.

Where raw HTML must be injected, use `dangerouslySetInnerHTML` with sanitization instead. This keeps the injection path explicit and reviewable.

```jsx
// ❌ Unsafe — bypasses React rendering entirely
const ref = useRef();
useEffect(() => {
  ref.current.innerHTML = userContent;
}, []);

// ✅ Safer — use dangerouslySetInnerHTML with sanitization
import DOMPurify from "dompurify";
const clean = DOMPurify.sanitize(userContent);
return <div dangerouslySetInnerHTML={ { __html: clean } } />;
```

The same risk applies to `.outerHTML` and `.insertAdjacentHTML()`. Avoid all three when handling dynamic content.

Component-level encapsulation and Shadow DOM do not prevent browser extensions from reading DOM content. Extensions can pierce closed Shadow DOM boundaries using the openOrClosedShadowRoot() API, meaning sensitive data rendered into the DOM remains accessible to any extension with sufficient permissions regardless of the encapsulation strategy used.

Related CWE: [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

### Avoid Prop Injection via the Spread Operator

The spread operator ({...object}) expands all key-value pairs of an object into component props. When applied to user-controlled or externally sourced objects, an attacker can inject props the component was never intended to receive — including dangerouslySetInnerHTML — causing unintended HTML injection.

Never spread user-controlled objects directly into components. Instead, destructure only the specific props your component expects and pass them explicitly.

```jsx
// ❌ Unsafe — attacker can inject dangerouslySetInnerHTML via userInput
<Component {...userInput} />

// ✅ Safe — extract only the props you expect
const { className, disabled } = userInput;
<Component className={className} disabled={disabled} />
```

Where genuinely dynamic props are required — such as in component libraries or CMS-driven layouts — filter the object against an allowlist of known safe prop names before spreading. This preserves dynamic behavior while preventing injection of dangerous props.

 ```jsx
// Illustrative example — not production-ready
const ALLOWED_PROPS = new Set([
  'className', 'style', 'id', 'placeholder',
  'disabled', 'aria-label', 'aria-describedby'
]);
 
function sanitizeProps(props) {
  return Object.fromEntries(
    Object.entries(props).filter(([key]) => ALLOWED_PROPS.has(key))
  );
}
 
// ✅ Safe — only allowlisted props reach the component
<Component {...sanitizeProps(userInput)} />
```

Never use a blocklist approach — blocking known dangerous props such as `dangerouslySetInnerHTML` by name is fragile because new dangerous props may be introduced in future React versions.

Related CWEs: [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html),[CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

### Avoid JSON Injection in Server-Side Rendered State

Server-side rendered React applications commonly embed initial state in a `<script>` tag for client hydration. Using JSON.stringify for this purpose is unsafe because it does not escape HTML special characters. If the serialized data contains a `</script>` sequence, the browser's HTML parser will terminate the script tag early and may execute attacker-controlled content that follows.

Use a library that explicitly escapes HTML-unsafe sequences such as `</script>` before embedding serialized data in a script tag.[serialize-javascript](https://github.com/yahoo/serialize-javascript) is a commonly used option that was designed for this purpose. Ensure any such library is kept up to date, as serialization libraries have historically been targets for injection vulnerabilities.

```jsx
// ❌ Unsafe — JSON.stringify does not escape HTML characters
<script dangerouslySetInnerHTML={ {
  __html: `window.__INITIAL_STATE__ = ${JSON.stringify(data)}`
} } />

// ✅ Safe — serialize-javascript escapes HTML-unsafe characters
import serialize from 'serialize-javascript';
<script dangerouslySetInnerHTML={ {
  __html: `window.__INITIAL_STATE__ = ${serialize(data)}`
} } />
```

Modern React frameworks such as Next.js App Router reduce this risk through React Server Components, which avoid client-side state serialization in script tags. The vulnerability remains present in applications using custom SSR implementations or the Next.js Pages Router with manual state serialization.

Related CWEs: [CWE-79: Improper Neutralization of Input During Web Page Generation(XSS)](https://cwe.mitre.org/data/definitions/79.html), [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

### Avoid Dynamic Code Execution

Functions such as `eval()`, `new Function()`, and `setTimeout()` or `setInterval()` called with a string argument execute arbitrary JavaScript at runtime. If user-controlled data reaches any of these functions, an attacker controls what code executes in the browser.

```jsx
// ❌ Unsafe — user input reaches eval()
eval(userInput);

// ❌ Unsafe — equivalent risk
new Function(userInput)();

// ❌ Unsafe — string argument behaves like eval()
setTimeout(userInput, 1000);

// ✅ Safe — use structured data and conditional logic instead
const actions = { greet: () => alert('Hello'), logout: () => signOut() };
if (actions[userInput]) actions[userInput]();

// ✅ Safe — always pass a function reference to setTimeout
setTimeout(() => doSomething(), 1000);
```

Avoid these patterns entirely. Data-driven logic should use structured data and conditional rendering rather than dynamic code generation.

Related CWEs: [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html),[CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)

## Sensitive Data Exposure

React applications handle sensitive data including authentication tokens, personally identifiable information (PII), API credentials, and server-side configuration. This data is frequently exposed through architectural decisions that appear harmless during development but create significant risk in production. The exposures in this section do not require an attacker to inject code — they result from how the application is designed to store, pass, and render data.

Related CWE: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### Store Authentication Tokens in httpOnly Cookies

Storing authentication tokens in localStorage or sessionStorage is a common pattern in React applications but creates significant risk. Both storage mechanisms are accessible to any JavaScript running on the page — including third-party scripts, browser extensions, and Cross-Site Scripting (XSS) payloads. A single XSS vulnerability anywhere in the application is sufficient for an attacker to read and exfiltrate all stored tokens.

httpOnly cookies cannot be read by JavaScript at all. The browser holds them internally and attaches them automatically to outgoing requests. This makes them inaccessible to scripts running on the page regardless of their origin.

```jsx
// ❌ Unsafe — accessible to any script on the page
localStorage.setItem('authToken', token);
sessionStorage.setItem('authToken', token);

// ✅ Safe — set by server, never accessible to JavaScript
// Server response header:
// Set-Cookie: authToken=...; HttpOnly; Secure; SameSite=Strict
```

In Single Page Applications (SPAs), the React client cannot set httpOnly cookies directly — only the server can. Use a Backend for Frontend (BFF) pattern — a server-side layer such as a Next.js API route or Edge Function — to exchange tokens with the authentication server and set cookies on behalf of the client. The React application never handles the raw token at any point.

Related CWEs: [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html), [CWE-284: Improper AccessControl](https://cwe.mitre.org/data/definitions/284.html)

### Minimize Sensitive Data in Component State and Props

Passing entire data objects through the component tree exposes sensitive fields to components that do not need them. Each component that receives a full object containing sensitive data is an additional location where
that data can be accidentally logged, rendered, or forwarded to a third-party service. Pass only the specific fields each component requires. Destructure data at the point where it is fetched and distribute only what is necessary.

```jsx
// ❌ Unsafe — entire user object passed to every component
// Avatar only needs name and photo, but receives SSN and token too
<Avatar user={fullUserObject} />

// ✅ Safe — pass only what each component needs
const { name, avatarUrl } = user;
<Avatar name={name} avatarUrl={avatarUrl} />
```

In 2026, React component state is subject to an additional exposure risk. Session recording tools and browser extensions can access React's internal Fiber tree — the data structure React uses to track component state — including state values that are never rendered into the DOM. Sensitive values should be held in component state only for as long as necessary and released immediately after use. Where possible, keep sensitive processing outside React's rendering cycle entirely.

Related CWEs: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html), [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### Remove Sensitive Data from Logs Before Production

Development logging frequently captures sensitive values for debugging purposes. These log statements are routinely deployed to production where the browser console is accessible to anyone with DevTools access, including users on shared devices, support engineers, and browser extensions that intercept console output. Configure your build tool to strip console statements from production output rather than relying on manual removal. Modern bundlers support this through build configuration without requiring code changes.

```jsx
// ❌ Unsafe — sensitive values written to console in production
console.log('User:', user);
console.log('Token:', authToken);

// ✅ Safe — removed at build time via bundler configuration
//vite.config.js (illustrative — not production-ready)
//esbuild: { drop: ['console'] }
```

Related CWE: [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

### Keep Sensitive Data Out of URLs

React Router and similar routing libraries make it easy to embed data in URLs as path parameters or query strings. URLs are an unsafe location for sensitive data because they are recorded in browser history, written to server access logs, transmitted in referrer headers when navigating to external sites, and readable by browser extensions monitoring the current URL.

```jsx
// ❌ Unsafe — token and identifier exposed in URL
navigate(`/reset?token=${passwordResetToken}`);
navigate(`/user/${user.ssn}/profile`);

// ✅ Safe — sensitive data passed in request body or headers
// Use POST requests with body payload for sensitive operations
// Store identifiers in server session, not URL parameters
```

Authentication tokens, session identifiers, personal identifiers, and any value that could be used to authenticate or identify a user must never appear in a URL.

Related CWEs: [CWE-598: Use of GET Request Method with Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html), [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### Do Not Expose Secrets Through Environment Variables

React applications built with modern bundlers such as Vite or Create React App use a prefix convention to distinguish client-side from server-side environment variables. Variables prefixed with 'VITE_' or 'REACT_APP_' are bundled into the client-side JavaScript output and become publicly readable by anyone who inspects the application bundle.

```bash
# ❌ Unsafe — bundled into client JavaScript, publicly readable
VITE_DATABASE_PASSWORD=secret
VITE_PRIVATE_API_KEY=sk_live_...

# ✅ Safe — accessed only by server-side processes
DATABASE_PASSWORD=secret
PRIVATE_API_KEY=sk_live_...
```

If a value is a secret, it belongs in a server-side environment variable accessed only by a server-side process such as a Node.js API route or Edge Function. The VITE_or REACT_APP_ prefix should be reserved exclusively for values that are intentionally public, such as a public-facing API base URL or a publishable key explicitly designed for client-side use.

Related CWEs: [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html), [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

### Limit Sensitive Data Rendered Into the DOM

AI browser assistants and side-panels, including those built into modern browsers read page content to provide context-aware help to users. When sensitive data is rendered into the DOM, these agents may include it in summaries or queries transmitted to third-party Large Language Model (LLM) providers. This applies equally to session recording tools such as FullStory and Hotjar, which capture DOM state for replay purposes. The data leaves the browser without the user understanding the full scope of what is being transmitted. The architectural mitigation is to keep sensitive values out of the DOM entirely.

Render masked representations at the display layer and process raw sensitive values in isolated execution contexts that do not expose their contents to the DOM. Existing Web Worker-based isolation patterns implement this boundary for form inputs by ensuring the raw value never enters the document tree. For content that must be rendered, scope it to the smallest possible DOM subtree and avoid placing sensitive values in attributes, data attributes, or element text content that is not immediately visible to the user.

Related CWEs: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html), [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

## Authentication and Authorization

Authentication is the process of verifying the identity of a user. Authorization is the process of determining what an authenticated user is permitted to do. React applications commonly implement both concerns at the UI layer — controlling what routes and components are visible based on the current user's identity and role. UI-layer controls improve user experience but provide no security guarantee. Every authentication and authorization decision that matters must be enforced on the server, independently of what the React client does or does not render.

Related CWE: [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

### Do Not Rely on UI-Only Route Protection

Protecting a route in React by redirecting unauthenticated users is a user experience pattern, not a security control. An attacker can bypass the React UI entirely and call the underlying API directly. The server must validate authentication on every request regardless of whether the client enforced a redirect.

```jsx
// ❌ Insufficient — redirects in the UI but the API remains unprotected
function ProtectedRoute({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/login" replace />;
}

// ✅ Correct — UI redirect paired with server-side validation on every
// API request. The UI redirect is for user experience only.
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <LoadingSpinner />;
  return user ? children : <Navigate to="/login" replace />;
}
// Every API endpoint independently validates the token server-side
```

The UI and the server must each enforce their own controls. The server must never trust that the React client has already performed a check.

Related CWEs: [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html),[CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/602.html)

### Do Not Enforce Authorization Through UI Role Checks

Checking a user's role in a React component to show or hide features is a display decision, not a security boundary. Role values stored in client-side state, localStorage, or token payloads are controlled by the browser and can be modified by an attacker. The server must validate the user's role independently on every request that requires elevated permission.

```jsx
// ❌ Unsafe — role check in the UI is not an authorization control
{ user.role === 'admin' && <AdminPanel /> }

// ✅ Safe — UI check controls display only
// The server enforces the role on every admin API request independently
{ user.role === 'admin' && <AdminPanel /> }
// Server: if (req.user.role !== 'admin') return res.status(403)
```

Never use client-side role data to gate API calls, determine data visibility, or make any decision with security consequences.

Related CWEs: [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html),[CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

### Do Not Store Sensitive Data in JWT Payloads

JSON Web Tokens (JWTs) consist of a header, a payload, and a signature. The payload is Base64-encoded, not encrypted. Any party that intercepts or reads the token can decode the payload without a key. Signing a JWT guarantees that its contents have not been tampered with — it does not make those contents private.

```jsx
// ❌ Unsafe — payload is readable by anyone who has the token
// { "userId": "123", "ssn": "123-45-6789", "salary": 95000 }

// ✅ Safe — store only non-sensitive identifiers in the payload
// { "userId": "123", "role": "user" }
// Fetch sensitive data from the server using the userId as a reference
```

Store only the minimum data required for the server to identify and authorize the user. Internal database identifiers in the payload expose your data model and may enable enumeration attacks — use opaque identifiers or purpose-specific claims rather than raw database primary keys. Retrieve sensitive user attributes from the server on demand rather than embedding them in the token.

Related CWE: [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

### Validate the OAuth State Parameter

OAuth 2.0 authorization flows require a state parameter to prevent Cross-Site Request Forgery (CSRF) attacks during authentication. The state value must be generated by the client before the authorization request, stored locally, and validated when the OAuth provider redirects back to the application. Omitting this validation allows an attacker to trick a user into completing an authorization flow initiated by the attacker.

```jsx
// ❌ Unsafe — no state parameter, vulnerable to CSRF
window.location.href =
  `https://provider.com/oauth/authorize?client_id=${id}`;

// ✅ Safe — generate, store, and validate state
const state = crypto.randomUUID();
sessionStorage.setItem('oauth_state', state);
window.location.href =
  `https://provider.com/oauth/authorize?client_id=${id}&state=${state}`;

// On callback — validate before processing
const params = new URLSearchParams(window.location.search);
if (params.get('state') !== sessionStorage.getItem('oauth_state')) {
  throw new Error('Invalid OAuth state — possible CSRF attack');
}
```

Related CWE: [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

### Invalidate Sessions on the Server at Logout

A logout implementation that only clears client-side state — removing tokens from localStorage or resetting React state — does not invalidate the session on the server. Any token captured before logout remains valid and can be used by an attacker until it expires naturally. Logout must notify the server to invalidate the session or revoke the token before clearing client-side state.

```jsx
// ❌ Unsafe — token remains valid on the server after logout
function logout() {
  localStorage.clear();
  setUser(null);
  navigate('/login');
}

// ✅ Safe — server invalidates the session before client clears state
async function logout() {
  await api.post('/auth/logout'); // server revokes token/session
  localStorage.clear();
  setUser(null);
  navigate('/login');
}
```

For httpOnly cookie-based sessions, the server logout endpoint must clear the cookie via a Set-Cookie response header with an expired date. The client cannot clear httpOnly cookies directly.

Related CWE: [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

## SSR Security

Server-Side Rendering (SSR) and React Server Components (RSC) execute React code in a server environment that has direct access to databases, secrets, and internal network resources. This execution context introduces a class of vulnerabilities that do not exist in client-side React applications. The most critical architectural concern in SSR is the server/client data boundary — the point at which data serialized on the server is transmitted to the browser. Data that crosses this boundary becomes accessible to the client regardless of how it was originally obtained or marked.

Related CWEs: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html),[CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

### Shape Data Explicitly at the Server/Client Boundary

React Server Components pass data to Client Components through props. Every value passed as a prop crosses the server/client boundary and is serialized into the payload transmitted to the browser. Passing a full database object to a Client Component exposes all of its fields — including fields that were never intended to leave the server — to anyone inspecting network traffic or the browser environment. Pass only the specific fields a Client Component requires. Shape the data explicitly at the point where it crosses the boundary rather than passing full objects.

```jsx
// Illustrative example — not production-ready

// ❌ Unsafe — full database object crosses boundary
// All fields including ssn, medicalRecord, internalKey reach the browser
async function UserProfile({ userId }) {
  const user = await db.getUser(userId);
  return <ClientProfile user={user} />;
}

// ✅ Safe — only required fields cross the boundary
async function UserProfile({ userId }) {
  const user = await db.getUser(userId);
  return <ClientProfile name={user.name} avatarUrl={user.avatarUrl} />;
}
```

This applies equally to environment variables and other server-side values. Never pass a secret or internal credential as a prop to a Client Component. In Next.js, import the server-only package in modules that contain sensitive server logic to enforce a build-time error if they are accidentally imported in a Client Component.

Related CWE: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### Validate User Input Before Server-Side Fetch Calls

SSR components frequently fetch data from internal APIs or services using values derived from user input such as URL parameters, query strings, or form data. Using unvalidated user input to construct server-side fetch URLs enables Server-Side Request Forgery (SSRF) — where an attacker manipulates the server into making requests to unintended internal targets. In cloud environments, internal metadata endpoints are a primary SSRF target. A successful SSRF attack can expose cloud credentials, internal service responses, or data from systems that are only accessible from within the server's network.

```jsx
// Illustrative example — not production-ready

// ❌ Unsafe — user-controlled value used directly in server fetch URL
async function ProductPage({ params }) {
  const data = await fetch(
    `http://internal-api.company.com/products/${params.id}`
  );
  return <Product data={await data.json()} />;
}

// ✅ Safe — validate input against an allowlist before use
async function ProductPage({ params }) {
  const id = params.id;
  if (!/^\d+$/.test(id)) throw new Error('Invalid product ID');
  const data = await fetch(
    `http://internal-api.company.com/products/${id}`
  );
  return <Product data={await data.json()} />;
}
```

Validate that user-supplied values conform to the expected format and character set before interpolating them into any server-side URL or query. Use allowlists rather than denylists.

Related CWE: [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

### Sanitize User Input Used in HTTP Response Headers

SSR applications sometimes set HTTP response headers using values derived from user input — for example, setting a Content-Language header from a locale parameter. If the input is not sanitized, an attacker can inject newline characters (\r\n) into the header value and append arbitrary HTTP headers to the server response. This is known as HTTP Response Splitting and can enable cache poisoning, cookie injection, and Cross-Site Scripting.

Validate that any user-supplied value used in a response header contains only permitted characters. Reject or strip any input containing carriage return or newline characters before it reaches a header assignment.

Related CWE: [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)

### Use a Server-Compatible Sanitization Library for SSR HTML

The HTML sanitization guidance in the XSS Prevention section applies equally to SSR. However, DOMPurify depends on browser DOM APIs and cannot run in a Node.js server environment. For server-side HTML sanitization use a server-compatible library such as sanitize-html, which provides equivalent sanitization without requiring a browser context. Unsanitized HTML injected during SSR is rendered before React hydrates and before any client-side protection runs, making server-side sanitization the more critical of the two layers.

Related CWE: [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

### JSON State Serialization

For guidance on the risk of using JSON.stringify to embed state in `<script>` tags during SSR hydration, see the Avoid JSON Injection in Server-Side Rendered State subsection in the XSS Prevention section.

### Authorize Inside Server Actions

Server Actions are async functions marked with the 'use server' directive. Next.js automatically exposes each Server Action as a publicly accessible HTTP POST endpoint. Developers often treat Server Actions as internal functions, but any authenticated or unauthenticated client can call them directly by crafting an HTTP request to the generated endpoint.

Every Server Action that accesses or modifies data must independently validate the current user's session and verify that the user is authorized to operate on the specific resource identified in the request. Failing to check resource ownership enables Insecure Direct Object Reference (IDOR) attacks where an attacker substitutes another
user's resource identifier to access or modify data they do not own.

```jsx
// Illustrative example — not production-ready

// ❌ Unsafe — no session check, no ownership validation
async function deleteDocument(documentId) {
  'use server';
  await db.documents.delete(documentId);
}

// ✅ Safe — validate session and ownership before operating on data
async function deleteDocument(documentId) {
  'use server';
  const session = await getSession();
  if (!session?.user) throw new Error('Unauthenticated');
  const doc = await db.documents.findById(documentId);
  if (doc.ownerId !== session.user.id) throw new Error('Forbidden');
  await db.documents.delete(documentId);
}
```

Apply the same authorization checks to every Server Action that reads, writes, or deletes data — regardless of whether the action is invoked from a protected route.

Related CWE: [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

### Keep React and RSC-Enabled Frameworks Updated

CVE-2025-55182 (React2Shell) is a critical unauthenticated Remote Code Execution (RCE) vulnerability affecting React 19.0.0 through 19.2.0. The vulnerability is caused by insecure deserialization in the RSC Flight protocol — the mechanism React uses to transfer server component output to the client. When the server deserializes an RSC payload, it failed to validate whether object properties were own properties or inherited prototype properties. An attacker can craft a malicious HTTP POST request containing __proto__ or constructor keys that pollute the JavaScript prototype chain on the server, which can be chained to execute arbitrary shell commands with full server privileges. The attack requires no authentication and affects any application that uses React Server Components — even those that do not explicitly implement Server Actions.

The vulnerability was assigned a CVSS score of 10.0 (maximum severity), added to CISA's Known Exploited Vulnerabilities (KEV) catalog, and observed being actively exploited in the wild within hours of disclosure.
Upgrade React to 19.3.0 or later and upgrade any RSC-enabled framework such as Next.js to its corresponding patched version. Do not manually parse, construct, or manipulate RSC Flight payloads in application code. Apply framework updates promptly — the RSC serialization layer is a security-critical component and its attack surface will evolve as the ecosystem matures.

Related CWEs: [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html),[CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)

### Do Not Rely on Middleware as the Sole Authorization Boundary

Next.js middleware.ts runs at the Edge layer before a request reaches the server. It is a useful layer for redirecting unauthenticated users and enforcing routing rules. It is not a complete security boundary. The Edge Runtime is a restricted JavaScript environment that executes separately from the main server process, and middleware bugs or misconfigurations can allow requests to bypass it. Authorization must be re-validated inside the Server Component or Page itself, immediately before any data fetching occurs. This creates a defense-in-depth posture where both the routing layer and the data layer independently enforce access controls.

```jsx
// Illustrative example — not production-ready

// ❌ Insufficient — relies on middleware redirect as sole auth check
// middleware.ts redirects unauthenticated users
// AdminPage fetches without re-validating
async function AdminPage() {
  const data = await db.getAdminData(); // assumes middleware already checked
  return <AdminDashboard data={data} />;
}

// ✅ Safe — defense in depth, auth validated before data fetch
async function AdminPage() {
  const session = await getSession();
  if (!session?.user?.isAdmin) redirect('/login');
  const data = await db.getAdminData(); // only reached after validation
  return <AdminDashboard data={data} />;
}
```

Related CWEs: [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

## Dependency and Supply Chain Security

React applications depend on large ecosystems of third-party packages. A typical production application has hundreds of transitive dependencies such as packages installed by packages. These include the ones that developer never explicitly chose. Each dependency is a potential attack surface. Supply chain attacks target this ecosystem rather than application code directly: an attacker compromises a package that many applications depend on, causing every downstream application to become vulnerable without any change to its own codebase.

Related CWEs: [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html),[CWE-1104: Use of Unmaintained Third-Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### Audit Dependencies Regularly

Run dependency audits as part of your development workflow to identify packages with known vulnerabilities. The npm CLI provides a built-in audit command. Automated tools such as GitHub Dependabot and Snyk monitor your dependency graph continuously and open pull requests when new security advisories affect your packages.

```bash
# Run audit manually
npm audit

# Apply safe automatic fixes
npm audit fix
```

Automated scanning identifies known vulnerabilities but cannot detect newly published malicious packages or compromised packages that have not yet been reported. Recent supply chain attacks have used invisible Unicode characters — variation selectors and Private Use Area characters that render as blank space in code editors and diff tools — to hide malicious payloads from visual code review. Automated scanning tools that operate on the parsed token stream rather than the visual representation are required to detect these techniques. Treat audit results as a floor, not a ceiling.

Related CWE: [CWE-1104: Use of Unmaintained Third-Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### Commit Lock Files and Use Deterministic Installs

The package-lock.json or yarn.lock file records the exact resolved version and cryptographic integrity hash of every installed package. Committing this file to version control and using npm ci instead of npm install in CI/CD pipelines ensures that every environment installs exactly the same dependency tree with verified hashes. Avoid loose semantic versioning ranges such as * wildcards or broad ^ caret ranges for critical dependencies — these allow automatic installation of newer versions published after your last install, including versions that may have been compromised.

```bash
# ❌ Non-deterministic — resolves latest compatible versions at install time
npm install

# ✅ Deterministic — installs exactly what is in the lock file
# Fails if lock file is inconsistent with package.json
npm ci
```

Without a committed lock file, a CI pipeline or a new developer machine may install a different version of a transitive dependency than what was tested — including a version published after the last install that may contain malicious code.

Related CWE: [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

### Verify Package Names Before Installing

Typosquatting attacks register package names that closely resemble popular packages — differing by a single character, a hyphen, or a word reversal. A developer who miskeys a package name or copies an install command from an untrusted source may install a malicious package that mimics the real one while exfiltrating environment variables, tokens, or user data.

Verify the exact spelling and registry URL of any package before installing it, particularly when following tutorials, copying commands from third-party documentation, or installing unfamiliar packages. Check the package's npm page for download counts, maintenance activity, and repository links before adding it to a production dependency.

Related CWE: [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html),[CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

### Disable Lifecycle Script Execution During Dependency Install

npm packages can define lifecycle hooks — preinstall, postinstall, and similar scripts — that execute automatically the moment a package is downloaded. Malicious packages exploit this mechanism to run code with the full privileges of the host machine before any application code imports them. These scripts routinely target environment variables, cloud credentials, CI/CD tokens, and private deployment keys, exfiltrating them before the developer has any opportunity to detect or prevent it.

Configure your environment and CI/CD pipelines to disable lifecycle script execution by default. Where a legitimate package requires a postinstall build step, explicitly allow only that package after reviewing its script contents.

```bash
# ❌ Unsafe — automatically runs lifecycle scripts on install
npm install

# ✅ Safe — disables lifecycle script execution during install
npm install --ignore-scripts

# Or enforce globally via npm configuration
npm config set ignore-scripts true
```

Note that some legitimate packages — particularly those that compile native Node.js modules or generate build artifacts at install time — require lifecycle scripts to function correctly. Evaluate each exception individually rather than applying a blanket allowance.

Related CWE: [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

### Minimize Your Dependency Footprint

Every package added to a project expands the supply chain attack surface. Prefer solving problems with the standard library or with well-established packages that have active maintenance, high download counts, and clear ownership. Avoid installing a package to solve a problem that can be solved in a few lines of code. Before adding a dependency, evaluate: the package's maintenance status, the number of maintainers, the history of ownership transfers, and whether the functionality is already available through an existing dependency. Unmaintained packages with a single maintainer are historically the most common vector for supply chain compromise.

Related CWE: [CWE-1104: Use of Unmaintained Third-Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### Apply Subresource Integrity to CDN-Hosted Scripts

React applications that load scripts from a Content Delivery Network (CDN) — such as third-party analytics, chat widgets, or UI libraries loaded via a `<script>` tag — are exposed to CDN compromise. If an attacker modifies the hosted file, every application loading it from that URL executes the malicious version. Subresource Integrity (SRI) allows a browser to verify that a CDN-hosted file matches a known cryptographic hash before executing it. If the file has been modified, the hash will not match and the browser will refuse to load it.

```html
<!-- Illustrative example — not production-ready -->
<script
  src="https://cdn.example.com/widget.js"
  integrity="sha384-[base64-encoded-hash]"
  crossorigin="anonymous">
</script>
```

Generate SRI hashes using the openssl command or an online SRI hash generator, and update the hash whenever the CDN-hosted file is intentionally upgraded. For scripts loaded dynamically via React, apply equivalent validation before injection.

Related CWE: [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## AI and Emerging Threats

The integration of Artificial Intelligence (AI) into both developer tooling and the user's browser has introduced a class of security risks that did not exist in earlier React development contexts. These risks operate at two distinct layers: the developer pipeline, where AI coding assistants generate code that is committed directly to production; and the browser runtime, where AI agents read page content on behalf of users and transmit it to third-party services. React applications are particularly exposed because they render dynamic data into the DOM and frequently integrate LLM APIs for user-facing features.

Related CWEs: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html),[CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### Sanitize Input Before Passing It to LLM APIs

React applications that integrate Large Language Model (LLM) APIs for features such as chatbots, smart search, or AI summarization create a direct pipeline from user-controlled form inputs to an AI model. Prompt injection attacks exploit this pipeline by embedding instructions inside user input that override the model's intended behavior. An attacker can craft input that causes the model to reveal system prompt contents, bypass content restrictions, or produce output that is rendered back to other users.

Treat every value passed to an LLM API as untrusted input subject to the same validation rules as any other user-supplied data. Never embed secrets, internal pricing, authorization tokens, or other sensitive
values in LLM system prompts — assume system prompt contents can be extracted. Use structured inputs and output schemas where the model produces machine-readable responses rather than free text, and validate
model output before rendering it to other users.

```jsx
// Illustrative example — not production-ready

// ❌ Unsafe — raw user input passed directly to LLM API
const response = await llm.chat({
  system: `You are a support agent. Internal discount code: SAVE50`,
  user: userInput // attacker can inject instructions here
});

// ✅ Safer — validate input and keep secrets out of the prompt
const sanitized = validateAndSanitize(userInput);
const response = await llm.chat({
  system: `You are a support agent. Answer only product questions.`,
  user: sanitized
});
// Validate response structure before rendering
```

For comprehensive LLM security guidance see the OWASP Top 10 for LLM Applications.

Related CWE: [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

### Limit Sensitive Data Rendered Into the DOM for AI Agent Contexts

AI browser assistants which are built-in side panels and extensions from major platform providers read DOM content to provide context-aware help to users. When these agents summarize a page or answer a question about it, they transmit DOM content to third-party LLM provider servers. For React applications that render personally identifiable information (PII), health data, or financial data, this creates an unintended data transmission path that operates outside the application's own data handling controls — even when the user has intentionally enabled the AI assistant.

AI-branded browser extensions present a compounded risk. Enterprise research indicates that AI extensions are significantly more likely than standard extensions to request broad DOM access permissions, and more likely to carry known security vulnerabilities. An extension that appears legitimate may transmit DOM content to unintended destinations.

The architectural mitigation is consistent with the guidance in the Sensitive Data Exposure section: keep sensitive values out of the DOM entirely. Data that is never rendered cannot be read by an AI agent regardless of its access level. Where sensitive data must be displayed, render only masked representations at the component layer and process raw values in isolated execution contexts that do not expose their contents to the document tree.

Related CWEs: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html),[CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### Review AI-Generated React Code Against Security Standards

AI coding assistants generate React code that developers commit to production at high velocity. Research and practical observation indicate that AI-generated React code frequently reproduces known security antipatterns — using dangerouslySetInnerHTML without sanitization, storing authentication tokens in localStorage, implementing authorization checks exclusively in the UI layer, and using eval() for dynamic logic. These are precisely the patterns documented in the preceding sections of this cheat sheet.

The speed of AI-assisted development does not reduce the requirement for security review. Treat AI-generated code with the same scrutiny applied to any untrusted contribution. Review generated code against the patterns in this cheat sheet before committing, and include AI-generated files in automated security scanning pipelines.

Where possible, provide explicit security constraints in prompts to coding assistants — specifying that generated code must follow OWASP guidelines, avoid known antipatterns, and use the specific safe patterns documented here. This reduces but does not eliminate the risk of insecure output.

Related CWE: [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

## References

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
- [OWASP Browser Extension Vulnerabilities Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [serialize-javascript](https://github.com/yahoo/serialize-javascript)
- [sanitize-html](https://github.com/apostrophecms/sanitize-html)
