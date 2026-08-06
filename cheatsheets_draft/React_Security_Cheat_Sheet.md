# React Security Cheat Sheet

## Introduction

React provides built-in protections against common vulnerabilites through JSX escaping, but several common patterns bypass these protections entirely. As React moves toward server-side rendering and React Server Components, the attack surface has expanded. This cheat sheet covers the most critical security pitfalls for React developers.

Key areas covered:

- Preventing Cross-Site Scripting (XSS) through safe rendering patterns
- Protecting sensitive data in client state and server-side rendering
- Securing authentication tokens and managing authorization in the UI
- Hardening server-side rendered (SSR) React applications
- Managing third-party dependency and supply chain risk

## Cross-Site Scripting (XSS) Prevention

For a comprehensive overview of XSS, see the [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html). The following guidance covers React-specific patterns that bypass JSX escaping.

### Avoid Unsafe HTML Injection with dangerouslySetInnerHTML

React provides `dangerouslySetInnerHTML` as an escape hatch for rendering raw HTML from rich text editors or a Content Management System(CMS). Without sanitization it allows injected scripts to execute in the browser.

Where possible, render untrusted content as text using JSX expressions. React escapes these automatically. Use `dangerouslySetInnerHTML` when raw HTML rendering is genuinely required, and sanitize untrusted input first using  library such as [DOMPurify](https://github.com/cure53/DOMPurify).

```jsx
// rawHTML is untrusted input e.g. from a CMS or rich text editor
import DOMPurify from "dompurify";

const clean = DOMPurify.sanitize(rawHTML);
return <div dangerouslySetInnerHTML={ { __html: clean } } />;
```

Unsanitized content can also enable DOM Clobbering. See the [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html).

### Validate URLs Before Rendering

Any attribute that renders a URL is a potential injection sink. React does not sanitize URL-bearing attributes. Common sinks include `href`, `src`, `action`, `formaction`, `data`, `srcset`, and `ping`, as well as `href` and `xlink:href` inside inline SVG elements.

Reject any untrusted URL whose scheme is not `https:` or `http:`.

```jsx
// ❌ Unsafe — untrusted URL rendered without validation
<a href={untrustedUrl}>Click here</a>

// ✅ Safe — reject dangerous schemes
let isSafe = false;
try {
  const url = new URL(untrustedUrl);
  isSafe = url.protocol === 'https:' || url.protocol === 'http:';
} catch {
  isSafe = false;
}
<a href={isSafe ? untrustedUrl : '#'}>Click here</a>
```

For links navigating users away from your application, show a confirmation prompt before following the URL. A valid `https://` URL can still point to a spoofing site and cannot be prevented through scheme validation alone.

### Avoid Direct DOM Manipulation

Setting `.innerHTML`, `.outerHTML`, or `.insertAdjacentHTML()` on a ref bypasses React's rendering pipeline without any sanitization. Use `dangerouslySetInnerHTML` with DOMPurify instead.

```jsx
// ❌ Unsafe — bypasses React rendering entirely
const ref = useRef();
useEffect(() => {
  ref.current.innerHTML = untrustedContent;
}, []);

// ✅ Safer — use dangerouslySetInnerHTML with sanitization
import DOMPurify from "dompurify";
const clean = DOMPurify.sanitize(untrustedContent);
return <div dangerouslySetInnerHTML={ { __html: clean } } />;
```

Component-level encapsulation and Shadow DOM do not prevent browser extensions from reading DOM content. Extensions can pierce closed Shadow DOM boundaries using the [`openOrClosedShadowRoot()`](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/dom/openOrClosedShadowRoot) API regardless of encapsulation strategy.

### Avoid Prop Injection via the Spread Operator

Spreading untrusted objects into components allows attackers to inject props the component was never intended to receive, including `dangerouslySetInnerHTML`. Filter against an allowlist of known safe prop names before spreading, or destructure only the props your component expects.

```jsx
// ❌ Unsafe
<Component {...userInput} />

// ✅ Safe — allowlist approach
const ALLOWED_PROPS = new Set([
  'placeholder',
  'disabled',
  'aria-label',
  'aria-describedby',
  'type'
]);

function sanitizeProps(props) {
  return Object.fromEntries(
    Object.entries(props).filter(([key]) => ALLOWED_PROPS.has(key))
  );
}
<Component {...sanitizeProps(userInput)} />
```

Avoid blocklists because new dangerous props may be introduced in future React versions.

### Avoid Dynamic Code Execution

For guidance on avoiding dynamic code execution patterns such as `eval()` and `new Function()`, see the [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html).

## Sensitive Data Exposure

Avoid storing sensitive values in React component state longer than necessary. Session recording tools and browser extensions can access React's internal Fiber tree, including state values that are never rendered into the DOM.

### Store Authentication Tokens in httpOnly Cookies

Storing authentication tokens in localStorage or sessionStorage is a common pattern in React applications but creates significant risk. Both storage mechanisms are accessible to any JavaScript running on the page including third-party scripts, browser extensions, and Cross-Site Scripting (XSS) payloads. A single XSS vulnerability anywhere in the application is sufficient for an attacker to read and exfiltrate all stored tokens.

httpOnly cookies cannot be read by JavaScript at all. The browser holds them internally and attaches them automatically to outgoing requests. This makes them inaccessible to scripts running on the page regardless of their origin.

```jsx
// ❌ Unsafe — accessible to any script on the page
localStorage.setItem('authToken', token);
sessionStorage.setItem('authToken', token);

// ✅ Safe — set by server, never accessible to JavaScript
// Server response header:
// Set-Cookie: authToken=...; HttpOnly; Secure; SameSite=Strict
```

In Single Page Applications (SPAs), the React client cannot set httpOnly cookies directly. Only the server can. Use a Backend for Frontend (BFF) pattern (a server-side layer such as a Next.js API route or Edge Function) to exchange tokens with the authentication server and set cookies on behalf of the client. The React application never handles the raw token at any point.

### Minimize Sensitive Data in Component State and Props

Passing entire data objects through the component tree exposes sensitive fields to components that do not need them. Each component that receives a full object containing sensitive data is an additional location where that data can be accidentally logged, rendered, or forwarded to a third-party service. Pass only the specific fields each component requires. Destructure data at the point where it is fetched and distribute only what is necessary.

```jsx
// ❌ Unsafe — entire user object passed to every component
// Avatar only needs name and photo, but receives SSN and token too
<Avatar user={fullUserObject} />

// ✅ Safe — pass only what each component needs
const { name, avatarUrl } = user;
<Avatar name={name} avatarUrl={avatarUrl} />
```

Session recording tools and browser extensions can access React's internal Fiber tree, the data structure React uses to track component state, including state values that are never rendered into the DOM. Hold sensitive values in component state only for as long as necessary and release them immediately after use.

### Keep Sensitive Data Out of URLs

Avoid passing sensitive values through React Router navigation or URL parameters. URLs are stored in browser history, server logs, and referrer headers.

```jsx
// ❌ Unsafe — token exposed in URL
navigate(`/reset?token=${passwordResetToken}`);

// ✅ Safe — pass sensitive data in request body instead
await api.post('/reset', { token: passwordResetToken });
```

### Do Not Expose Secrets Through Environment Variables

React applications built with modern bundlers such as Vite use a prefix convention to distinguish client-side from server-side environment variables. Variables prefixed with `VITE_` are bundled into the client-side JavaScript output and become publicly readable by anyone who inspects the application bundle ([Vite docs](https://vite.dev/guide/env-and-mode)). Next.js uses the `NEXT_PUBLIC_` prefix for the same purpose.

```bash
# ❌ Unsafe — bundled into client JavaScript, publicly readable
VITE_DATABASE_PASSWORD=secret
VITE_PRIVATE_API_KEY=sk_live_...

# ✅ Safe — accessed only by server-side processes
DATABASE_PASSWORD=secret
PRIVATE_API_KEY=sk_live_...
```

If a value is a secret, it belongs in a server-side environment variable accessed only by a server-side process such as a Node.js API route or Edge Function. The `VITE_` prefix should be reserved exclusively for values that are intentionally public, such as a public-facing API base URL or a publishable key explicitly designed for client-side use.

## Authentication and Authorization

Client-side authentication checks such as hiding routes, disabling buttons, checking roles in components are user experience patterns that can be bypassed entirely by calling your API directly. Every authorization decision must be enforced on the server, independently of what the React client renders.

### Do Not Rely on UI-Only Route Protection

Protecting a route in React by redirecting unauthenticated users is a user experience pattern, not a security control. An attacker can bypass the React UI entirely and call the underlying API directly. The server must validate authentication on every request regardless of whether the client enforced a redirect.

```jsx
// ❌ Insufficient — client-side redirect only, API unprotected
function ProtectedRoute({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/login" replace />;
}
// An attacker can call /api/data directly without touching this component

// ✅ Client layer — redirects unauthenticated users (UX only)
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <LoadingSpinner />;
  return user ? children : <Navigate to="/login" replace />;
}

// ✅ Server layer — enforces auth on every request (actual security)
async function handler(req, res) {
  const user = await verifyToken(req.headers.authorization);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  // proceed with request
}
```

The UI and the server must each enforce their own controls. The server must never trust that the React client has already performed a check.

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

## SSR Security

Server-Side Rendering (SSR) and React Server Components (RSC) execute React code in a server environment that has direct access to databases, secrets, and internal network resources. This execution context introduces a class of vulnerabilities that do not exist in client-side React applications. The most critical architectural concern in SSR is the server/client data boundary which is the point at which data serialized on the server is transmitted to the browser. Data that crosses this boundary becomes accessible to the client regardless of how it was originally obtained or marked.

### Shape Data Explicitly at the Server/Client Boundary

React Server Components pass data to Client Components through props. Every value passed as a prop crosses the server/client boundary and is serialized into the payload transmitted to the browser. Passing a full database object to a Client Component exposes all of its fields including fields that were never intended to leave the server to anyone inspecting network traffic or the browser environment. Pass only the specific fields a Client Component requires. Shape the data explicitly at the point where it crosses the boundary rather than passing full objects.

```jsx
// Server Component — async data fetching is idiomatic in RSC
// Runs only on the server, never ships JS to the browser
async function UserProfile({ userId }) {
  const user = await db.getUser(userId);

  // ❌ Unsafe — full object serialized and sent over network to browser
  return <ClientProfile user={user} />;
}

// ✅ Safe — only required fields cross the network
async function UserProfile({ userId }) {
  const user = await db.getUser(userId);
  return <ClientProfile name={user.name} avatarUrl={user.avatarUrl} />;
}
```

This applies equally to environment variables and other server-side values. Never pass a secret or internal credential as a prop to a Client Component. In Next.js, import the server-only package in modules that contain sensitive server logic to enforce a build-time error if they are accidentally imported in a Client Component.

### Validate User Input Before Server-Side Fetch Calls

SSR components frequently fetch data from internal APIs or services using values derived from user input such as URL parameters, query strings, or form data. Using unvalidated user input to construct server-side fetch URLs enables Server-Side Request Forgery (SSRF) where an attacker manipulates the server into making requests to unintended internal targets. In cloud environments, internal metadata endpoints are a primary SSRF target. A successful SSRF attack can expose cloud credentials, internal service responses, or data from systems that are only accessible from within the server's network.

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

### Sanitize User Input Used in HTTP Response Headers

SSR applications sometimes set HTTP response headers using values derived from untrusted input. For example, setting a Content-Language header from a locale parameter. If the input is not sanitized, an attacker can inject newline characters (\r\n) into the header value and append arbitrary HTTP headers to the server response. This is known as HTTP Response Splitting and can enable cache poisoning, cookie injection, and Cross-Site Scripting.

Validate that any untrusted value used in a response header contains only permitted characters. Reject or strip any input containing carriage return or newline characters before it reaches a header assignment.

### Use a Server-Compatible Sanitization Library for SSR HTML

The HTML sanitization guidance in the XSS Prevention section applies equally to SSR. However, DOMPurify depends on browser DOM APIs and cannot run in a Node.js server environment. For server-side HTML sanitization use a server-compatible library such as sanitize-html, which provides equivalent sanitization without requiring a browser context. Unsanitized HTML injected during SSR is rendered before React hydrates and before any client-side protection runs, making server-side sanitization the more critical of the two layers.

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

Apply the same authorization checks to every Server Action that reads, writes, or deletes data regardless of whether the action is invoked from a protected route.

### Do Not Rely on Middleware as the Sole Authorization Boundary

Server-side frameworks such as Next.js support middleware that runs before a request reaches your application, useful for redirecting unauthenticated users. This layer is not a complete security boundary.
Bugs or misconfigurations can allow requests to bypass it. Authorization must be re-validated inside the Server Component or page itself before any data fetching occurs.

```jsx
// ❌ Insufficient — no auth check before data fetch
async function AdminPage() {
  const data = await db.getAdminData();
  return <AdminDashboard data={data} />;
}

// ✅ Safe — validate before fetching
async function AdminPage() {
  const session = await getSession();
  if (!session?.user?.isAdmin) redirect('/login');
  const data = await db.getAdminData();
  return <AdminDashboard data={data} />;
}
```

## Dependency and Supply Chain Security

React applications share the same npm supply chain risks as any JavaScript project. See the [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/) for comprehensive guidance.

## References

- [DOMPurify](https://github.com/cure53/DOMPurify)
- [serialize-javascript](https://github.com/yahoo/serialize-javascript)
- [sanitize-html](https://github.com/apostrophecms/sanitize-html)
