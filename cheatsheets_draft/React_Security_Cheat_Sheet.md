# React Security Cheat Sheet

## Introduction

React encodes values rendered through JSX by default, which prevents injection through rendered values ([OWASP XSS Prevention Cheat Sheet, Framework Security](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#framework-security)), but several common patterns bypass this protection entirely. As React moves toward server-side rendering and React Server Components, the attack surface has expanded. This cheat sheet covers the most critical security pitfalls for React developers.

## Cross-Site Scripting (XSS) Prevention

For a comprehensive overview of XSS, see the [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html). The following guidance covers React-specific patterns that bypass JSX escaping.

### Avoid Unsafe HTML Injection with dangerouslySetInnerHTML

React provides `dangerouslySetInnerHTML` as an escape hatch for rendering raw HTML from rich text editors or a Content Management System (CMS). Without sanitization, it allows injected scripts to execute in the browser.

Where possible, render untrusted content as text using JSX expressions. React escapes these automatically. Use `dangerouslySetInnerHTML` when raw HTML rendering is genuinely required, and sanitize untrusted input first using a library such as [DOMPurify](https://github.com/cure53/DOMPurify).

```jsx
import DOMPurify from "dompurify";

// rawHTML is untrusted input, e.g. from a CMS or rich text editor
function Bio({ rawHTML }) {
  const clean = DOMPurify.sanitize(rawHTML, { SANITIZE_NAMED_PROPS: true });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

Unsanitized content can also enable DOM Clobbering. DOMPurify's default configuration removes only clobbering collisions with built-in DOM APIs; `SANITIZE_NAMED_PROPS: true` extends protection to custom variables and properties by prefixing `id` and `name` values. See the [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html).

### Validate URLs Before Rendering

Any attribute that renders a URL is a potential injection sink. React 19 blocks `javascript:` URLs in `href`, `src`, `action`, `formAction`, `data`, and `xlinkHref`, replacing them with functions that throw ([react/react#29808](https://github.com/react/react/pull/29808)); React 16.9 through 18 only warn in development. This is not a URL sanitizer: it does not cover `data:` URLs, `srcSet`, `ping`, `poster`, `<iframe srcdoc>`, or `style` `url()`, so validate the scheme yourself.

For navigation targets such as `href`, validate untrusted URLs against an allow-list of expected schemes, defaulting to `https:` and `http:` and adding schemes such as `mailto:` or `tel:` only where the application requires them. Never allow `javascript:` or `data:` in navigable attributes. Scheme validation addresses script execution, not transport security; drop `http:` from the list where the application links only to its own HTTPS origins. Scheme validation is not enough for props that load or submit to a resource, such as `script src`, `iframe src`, `object data`, and `form action`: an arbitrary `https:` URL can still load attacker-controlled code or content, or send form data to an attacker, so those props need an allow-list of expected origins. `srcdoc` takes HTML and needs the sanitization described above, and `style` `url()` values need CSS-context validation.

```jsx
const ALLOWED_SCHEMES = ["https:", "http:"]; // add "mailto:" or "tel:" only if required

// Returns a normalized absolute URL for navigation targets (href), or null if the scheme is not allowed.
// During SSR, pass an explicit base instead of document.baseURI.
function safeHref(untrustedUrl, base = document.baseURI) {
  try {
    const url = new URL(untrustedUrl, base);
    return ALLOWED_SCHEMES.includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

// ❌ Unsafe: untrusted URL rendered without validation
function UnsafeLink({ untrustedUrl, label }) {
  return <a href={untrustedUrl}>{label}</a>;
}

// ✅ Safe: validate, render the normalized URL, and fall back to plain text
function SafeLink({ untrustedUrl, label }) {
  const href = safeHref(untrustedUrl);
  return href ? <a href={href}>{label}</a> : <span>{label}</span>;
}
```

Render the normalized `url.href` rather than the original string so that the value checked is the value rendered. Scheme validation alone is not sufficient for navigation or redirect targets: once a base is supplied, a protocol-relative URL such as `//evil.com/x` resolves to an allowed scheme on an attacker-controlled host. Validate those targets against a host allow-list, and where the destination is legitimately arbitrary, such as user-supplied external links, show an interstitial confirming that the user is leaving the application, since a well-formed `https://` URL can still point to a phishing site.

### Avoid Direct DOM Manipulation

React does not sanitize HTML on any path. Writing to `.innerHTML`, `.outerHTML`, or `.insertAdjacentHTML()` through a ref is exactly as safe or unsafe as `dangerouslySetInnerHTML` with the same input; the control is sanitization, not the choice of API. When raw HTML is not actually needed, render the value as JSX text or assign `textContent`, which never parses markup. When HTML is required, sanitize first, then render it through React.

Avoid imperative DOM writes to React-managed nodes for a second, React-specific reason: React does not know about the change, so the real DOM diverges from what React believes it rendered, and the content is overwritten whenever a re-render touches that element's children or the element remounts. Rendering through `dangerouslySetInnerHTML` keeps the content inside React's model.

```jsx
import DOMPurify from "dompurify";

// Preferred when HTML is not needed: rendered as text, never parsed as markup
function PlainContent({ untrusted }) {
  return <div>{untrusted}</div>;
}

// When HTML is required: sanitize, then render through React
function HtmlContent({ untrustedHtml }) {
  const clean = DOMPurify.sanitize(untrustedHtml, { SANITIZE_NAMED_PROPS: true });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

### Avoid Prop Injection via Spread Syntax

Spreading an untrusted object into a JSX element passes every key in that object to the element as a prop. If the object came from user input, a URL query string, or an API response, an attacker controls which props are set: `dangerouslySetInnerHTML`, `href`, event handlers, or anything else the element accepts. The risk lands where the bag reaches a DOM element, whether directly or forwarded through a wrapper component, so never spread untrusted objects into elements and never pass them onward unfiltered.

When a component's props are known, destructure them explicitly. This is the simplest defense and needs no helper: only the named props reach the element, and everything else is dropped.

```jsx
// ❌ Unsafe: every key in the untrusted object becomes a prop
function UnsafeField(props) {
  return <input {...props} />;
}

// ✅ Safe: only the named props reach the element
function Field({ placeholder, disabled, value, onChange }) {
  return <input placeholder={placeholder} disabled={disabled} value={value} onChange={onChange} />;
}
```

Use an allow-list only for genuinely dynamic prop bags, where the set of props is not known at authoring time. Define the allow-list per component rather than sharing one across components, since each element accepts different props. Allow-lists fail closed: an unexpected key is dropped. Block-lists fail open: an unexpected key passes through. Avoid `type` in allow-lists for inputs unless the permitted values are also constrained, because `type="image"` inputs accept `src` and `formAction`.

```jsx
const FIELD_ALLOWED_PROPS = ["placeholder", "disabled", "value", "onChange"];

function DynamicField(untrustedProps) {
  const safeProps = Object.fromEntries(
    Object.entries(untrustedProps).filter(([key]) => FIELD_ALLOWED_PROPS.includes(key))
  );
  return <input {...safeProps} />;
}
```

### Avoid Dynamic Code Execution

For guidance on avoiding dynamic code execution patterns such as `eval()` and `new Function()`, see the [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html).

## Sensitive Data Exposure

Avoid storing sensitive values in React component state longer than necessary. Component state is not private at runtime: React attaches its internal fiber and props objects to DOM nodes as expando properties (`__reactFiber$<key>` and `__reactProps$<key>`, set by [`precacheFiberNode` in `ReactDOMComponentTree.js`](https://github.com/react/react/blob/v19.2.0/packages/react-dom-bindings/src/client/ReactDOMComponentTree.js)), so any script running in the same page, including third-party analytics and session-replay scripts the application deliberately loads, can traverse from a DOM node to the component tree and read props and state, including values that are never rendered into the DOM. TThis is an implementation detail rather than a guarantee: React has introduced a feature flag (`enableInternalInstanceMap`) that moves these properties into internal maps, currently disabled in stable releases, so the exact mechanism may change; React provides no isolation of component state from other code running in the page. Separately, measurement research has [documented session-replay scripts collecting rendered page content and form input](https://freedom-to-tinker.com/2017/11/15/no-boundaries-exfiltration-of-personal-data-by-session-replay-scripts/) before submission, which is the DOM-level exposure path rather than fiber access.

The guidance in this sheet addresses exposure to scripts the application itself includes. Compromise of a same-origin script, and browser extensions with content-script access, can read the DOM directly and sit outside the threat model that the countermeasures here address; protecting against those requires controls beyond the application layer.

### Store Authentication Tokens in httpOnly Cookies

Do not store authentication tokens in `localStorage` or `sessionStorage`; both are readable by JavaScript running in the same browser context. A React client cannot set an `httpOnly` cookie, so when the browser must authenticate through an `httpOnly` session cookie, use a server-side layer, often a Backend for Frontend (BFF), to set it. `httpOnly` keeps the token from being read, but an XSS payload can still make authenticated requests from the victim's browser, so it does not remove the need to fix XSS. Follow the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for token storage, the BFF pattern, and cookie attributes including `SameSite`, and the [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for CSRF controls.

### Minimize Sensitive Data in Component State and Props

Passing entire data objects through the component tree exposes sensitive fields to components that do not need them. Each component that receives a full object containing sensitive data is an additional location where that data can be accidentally logged, rendered, or forwarded to a third-party service. Pass only the specific fields each component requires. Destructure data at the point where it is fetched and distribute only what is necessary.

```jsx
// ❌ Unsafe: the entire user object reaches a component that needs two fields
function UnsafeProfileHeader({ user }) {
  return <Avatar user={user} />;
}

// ✅ Safe: pass only what each component needs
function ProfileHeader({ user }) {
  const { name, avatarUrl } = user;
  return <Avatar name={name} avatarUrl={avatarUrl} />;
}
```

Do not hold long-lived credentials in client state at all; keep sessions in `httpOnly` cookies through a server-side layer as described above. Component state is readable by any script in the page for as long as the value exists, and JavaScript offers no way to erase a value on demand: strings are immutable, there is no zeroization primitive, and garbage collection timing is not controllable, so clearing state does not remove the value from memory. If a secret must be handled in the browser, hold it inside a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers), whose global scope is separate from the page and not reachable from main-thread scripts. This protects values while they are held in the Worker; a value that enters through user input still passes through the main thread before it reaches the Worker.

### Keep Sensitive Data Out of URLs

React Router's `navigate()` and `<Link>` perform ordinary URL navigation, so a query string assembled in JSX is exposed like any other URL: it persists in browser history, reaches server logs on page loads and through the same-origin referrer on API requests, and is readable by any third-party script through `window.location`. Router location state is not a hiding place either: React Router documents the `state` option as [`history.state`](https://api.reactrouter.com/v8/functions/react-router.useNavigate), so it persists in session history across reloads and is readable by any script on the page. Keep session identifiers in `httpOnly` cookies and never in routes. The [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) covers session ID exposure through URLs in full, and the [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) covers the one legitimate URL-token flow, password reset, and its controls.

```jsx
// ❌ Unsafe: session token exposed in the URL
navigate(`/dashboard?sessionToken=${sessionToken}`);

// ✅ Safe: the session lives in an httpOnly cookie; navigate without it
navigate("/dashboard");
```

### Do Not Expose Secrets Through Environment Variables

React applications built with modern bundlers such as Vite use a prefix convention to distinguish client-side from server-side environment variables. Variables prefixed with `VITE_` are bundled into the client-side JavaScript output and become publicly readable by anyone who inspects the application bundle ([Vite docs](https://vite.dev/guide/env-and-mode)). Next.js uses the `NEXT_PUBLIC_` prefix for the same purpose ([Next.js docs](https://nextjs.org/docs/pages/building-your-application/configuring/environment-variables)).

```bash
# ❌ Unsafe: bundled into client JavaScript, publicly readable
VITE_DATABASE_PASSWORD=secret
VITE_PRIVATE_API_KEY=sk_live_...

# Not exposed by Vite, but also not safe: a Vite SPA has no server-side
# process to read these, so the secret is simply an unused plaintext value
# in the frontend project tree.
DATABASE_PASSWORD=secret
PRIVATE_API_KEY=sk_live_...
```

Unprefixed variables are not exposed by Vite, but that does not make them a safe place for secrets. A secret must live only where a server-side process or a secret manager can read it, such as the environment of a Node.js API route or Edge Function, and never in the frontend project at all. Reserve the `VITE_` prefix for values that are intentionally public, such as a public-facing API base URL or a publishable key explicitly designed for client-side use. Note that the [`envPrefix`](https://vite.dev/config/shared-options.html#envprefix) and [`define`](https://vite.dev/config/shared-options.html#define) options change what reaches the bundle, so review both when auditing what a build exposes.

## Authentication and Authorization

Client-side authentication checks such as hiding routes, disabling buttons, or checking roles in components are user-experience patterns that can be bypassed entirely by calling your API directly. Every authorization decision must be enforced on the server, independently of what the React client renders; the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) states the principle and its ASVS basis.

### Do Not Rely on UI-Only Route Protection or Role Checks

A route guard that redirects unauthenticated users, or a component that renders an admin panel only for `user.role === 'admin'`, is a display decision, not a security boundary. Role values in client state, `localStorage`, or a token payload are under the browser's control and can be altered, and an attacker can skip the React UI entirely and call the underlying API. The React layer keeps the interface coherent; the server must verify the session and the role on every request that requires them, regardless of what the client rendered.

```jsx
// ❌ Unsafe: the client decides whether a privileged call happens
async function deleteUser(user, id) {
  if (user.role === "admin") {
    await api.post("/admin/users/delete", { id });
  }
}

// Client layer: route guards and role checks keep the UI coherent, provide no security
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <LoadingSpinner />;
  return user ? children : <Navigate to="/login" replace />;
}

function AdminArea({ user }) {
  return user.role === "admin" ? <AdminPanel /> : null;
}

// Server layer: the actual authorization boundary, enforced on every request
async function adminHandler(req, res) {
  const session = await getSession(req); // read from the httpOnly session cookie
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  if (session.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  // proceed with the request
}
```

Never use client-side role data to gate API calls, determine data visibility, or make any decision with security consequences. A route guard or role check that is the only control is a vulnerability, not a control.

## Server-Side Rendering Security

SSR and React Server Components (RSC) execute React code in a server environment that has direct access to databases, secrets, and internal network resources. This execution context introduces a class of vulnerabilities that do not exist in client-side React applications. The most critical architectural concern is the server/client data boundary, the point at which data serialized on the server is transmitted to the browser. Props passed from a Server Component to a Client Component cross this boundary automatically through the React Server Components protocol ([Next.js: How to Think About Security](https://nextjs.org/blog/security-nextjs-server-components-actions)), and any data that crosses it becomes accessible to the client regardless of how it was originally obtained or marked. Framework-specific guards for this boundary, including Server Actions and the `server-only` package, are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html); this section covers what applies to any React SSR or RSC setup.

Two controls apply at this boundary. First, filter data in an isolated data access layer before it reaches React's render context; the [Next.js data security guide](https://nextjs.org/docs/app/guides/data-security) describes this structure and recommends keeping database packages and environment variables out of every other module. The subsection below shows the pattern at the component level. Second, React's experimental taint APIs (`experimental_taintObjectReference` and `experimental_taintUniqueValue`) mark an object or value so that React throws an error if it is passed across the server-client boundary ([Next.js taint reference](https://nextjs.org/docs/app/api-reference/next-config-js/taint)). Tainting is a safety net rather than a substitute for filtering: it tracks objects by reference, so a copy of a tainted object loses the protection, and it cannot follow values derived from a tainted value.

### Shape Data Explicitly at the Server/Client Boundary

Every prop passed from a Server Component to a Client Component is serialized into the payload sent to the browser. Pass only the specific fields a Client Component requires, and shape the data explicitly at the point where it crosses the boundary rather than passing full objects; a full database record exposes all of its fields to anyone inspecting network traffic or the browser environment, including fields that were never intended to leave the server.

```jsx
// Server Component: async data fetching is idiomatic in RSC and runs only on the server

// ❌ Unsafe: the full object is serialized and sent to the browser
async function UnsafeUserProfile({ userId }) {
  const user = await db.getUser(userId);
  return <ClientProfile user={user} />;
}

// ✅ Safe: only the required fields cross the boundary
async function UserProfile({ userId }) {
  const user = await db.getUser(userId);
  return <ClientProfile name={user.name} avatarUrl={user.avatarUrl} />;
}
```

This applies equally to environment variables and other server-side values: never pass a secret or internal credential as a prop to a Client Component. Framework-level guards such as the `server-only` package and the `NEXT_PUBLIC_` prefix convention are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html), including the limitation that `server-only` prevents a module from being imported into a Client Component but does not stop server code from explicitly returning sensitive data.

### Validate User Input Before Server-Side Fetch Calls

A Server Component that fetches using values derived from user input introduces a Server-Side Request Forgery sink that has no client-side equivalent: the request originates from the server, inside the network perimeter, with access to internal services and cloud metadata endpoints. The [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) covers the controls, including destination host and port allow-lists, validating resolved IP addresses against private and link-local ranges, and disabling redirect following. Apply them to every fetch a Server Component makes with user-derived input, and never let user input supply the host or the full URL.

```jsx
// Path-segment validation: necessary, and not sufficient on its own.
// The host is fixed here; see the SSRF Cheat Sheet when the destination is variable.
async function ProductPage({ params }) {
  const { id } = await params;
  if (!/^\d+$/.test(id)) throw new Error("Invalid product ID");
  const response = await fetch(`https://internal-api.example.com/products/${id}`);
  return <Product data={await response.json()} />;
}
```

### Validate Untrusted Values Used in Response Headers

Node's `res.setHeader` and the `Headers` API reject CR and LF in header values, so classic [HTTP response splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) is not reachable through these APIs; validate anyway as defense in depth for raw socket writes, upstream proxies, and runtimes with different header implementations. The header risk that remains exploitable is a redirect destination built from user input: validate it against an allow-list as described in the [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html). Framework-specific redirect and cache guidance is covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html).

### Use a Server-Compatible Sanitization Library for SSR HTML

The HTML sanitization guidance in the XSS Prevention section applies equally to SSR. However, DOMPurify depends on a DOM implementation and requires [jsdom to run in a Node.js server environment](https://github.com/cure53/DOMPurify#running-dompurify-on-the-server). For server-side HTML sanitization without that dependency, use a server-compatible library such as [sanitize-html](https://www.npmjs.com/package/sanitize-html), which provides equivalent sanitization without requiring a browser context. Unsanitized HTML injected during SSR is rendered before React hydrates and before any client-side protection runs, making server-side sanitization the more critical of the two layers.

### JSON State Serialization

Embedding state into `<script>` tags with `JSON.stringify` during SSR hydration allows attacker-controlled strings such as `</script>` to break out of the script context and inject markup. Escape HTML-significant characters before embedding state, using a library such as [serialize-javascript](https://github.com/yahoo/serialize-javascript), whenever you write the serialization yourself rather than relying on a framework's. See the [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) for output encoding in script contexts.

### Authorize Inside Server Functions

A Server Function is client-callable, so enforce authentication and authorization inside the function and validate every argument as untrusted input; [react.dev](https://react.dev/reference/rsc/use-server) states this requirement. Framework-specific Server Action and routing-layer controls are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html).

## Content Security Policy

A Content Security Policy limits the damage of several threats described in this sheet: it constrains which scripts may execute, which origins a page may connect to, and whether inline script is permitted at all. It does not prevent an allowed script from reading the DOM, so it complements the controls above rather than replacing them. A restrictive policy also interacts with React tooling: `worker-src` governs Web Worker creation, and bundlers that rely on inline script or `eval` in development need policies that differ between development and production builds. See the [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).

## Related Cheat Sheets

- [Cross-Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOM Clobbering Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
- [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Next.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html)
- [NPM Security](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)
- [Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
- [Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Server-Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
