# React Security Cheat Sheet

## Introduction

React escapes text values rendered through JSX by default, but raw HTML and URL-bearing props require additional controls ([OWASP XSS Prevention Cheat Sheet, Framework Security](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#framework-security)). This cheat sheet covers React-specific rendering, component data exposure, and the server/client boundary in server-side rendering (SSR) and React Server Components (RSC). Examples illustrate individual controls and require application-specific validation and testing.

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

URL-bearing props need validation appropriate to their use. React 19 blocks `javascript:` URLs in several URL-bearing props; its [URL sanitizer](https://github.com/react/react/blob/v19.2.0/packages/react-dom-bindings/src/shared/sanitizeURL.js) replaces them with a URL string that throws if visited. This does not validate other schemes or the destination host, and does not sanitize HTML or CSS.

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

// Unvalidated navigation target
function UnsafeLink({ untrustedUrl, label }) {
  return <a href={untrustedUrl}>{label}</a>;
}

// Scheme validation only; this does not establish that the destination is trustworthy
function SafeLink({ untrustedUrl, label }) {
  const href = safeHref(untrustedUrl);
  return href ? <a href={href}>{label}</a> : <span>{label}</span>;
}
```

Render the normalized `url.href` rather than the original string so that the value checked is the value rendered. For navigation intended to remain within trusted sites, validate the destination against an origin allow-list as well. Scheme validation alone permits external hosts, including protocol-relative URLs. For arbitrary external links and user-controlled redirects, follow the [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html); an allowed scheme does not establish that a site is trustworthy.

### Avoid Direct DOM Manipulation

React does not sanitize HTML on any path. Writing to `.innerHTML`, `.outerHTML`, or `.insertAdjacentHTML()` through a ref is exactly as safe or unsafe as `dangerouslySetInnerHTML` with the same input; the control is sanitization, not the choice of API. When raw HTML is not actually needed, render the value as JSX text or assign `textContent`, which never parses markup. When HTML is required, sanitize first, then render it through React.

### Avoid Prop Injection via Spread Syntax

Spreading an untrusted object into a JSX element passes every key in that object to the element as a prop. If the object came from user input, a URL query string, or an API response, an attacker controls which props are set. If one of those props reaches a DOM element, whether directly or through a wrapper component that forwards its props, it can lead to XSS: a `dangerouslySetInnerHTML` key injects HTML, and URL props such as `href` or `formAction` can point anywhere (see Validate URLs Before Rendering). Never spread untrusted objects into elements, and never pass them onward unfiltered.

When a component's props are known, destructure them explicitly. This is the simplest defense and needs no helper: only the named props reach the element, and everything else is dropped.

```jsx
// Every key in the untrusted object becomes a prop
function UnsafeField(props) {
  return <input {...props} />;
}

// Only the named props reach the element; onChange is an application-provided handler
function Field({ placeholder, disabled, value, onChange }) {
  return <input placeholder={placeholder} disabled={disabled} value={value} onChange={onChange} />;
}
```

Use an allow-list only for genuinely dynamic props, where the set of props is not known at authoring time. Define the allow-list per component rather than sharing one across components, since each element accepts different props. Allow-lists fail closed: an unexpected key is dropped. Block-lists fail open: an unexpected key passes through. Avoid `type` in allow-lists for inputs unless the permitted values are also constrained, because `type="image"` inputs accept `src` and `formAction`.

### Avoid Dynamic Code Execution

For guidance on avoiding dynamic code execution patterns such as `eval()` and `new Function()`, see the [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html).

## Sensitive Data Exposure

Do not treat component state or props as a confidentiality boundary within the page. React has exposed component internals through DOM node properties, as shown in [React 19.2's DOM integration](https://github.com/react/react/blob/v19.2.0/packages/react-dom-bindings/src/client/ReactDOMComponentTree.js). Although implementation details can change, omitting a value from rendered HTML does not make it private from scripts running in the same page. Minimize the sensitive data delivered to the browser and shared with components.

### Store Authentication Tokens in HttpOnly Cookies

A React client cannot set an `HttpOnly` cookie; use a server-side layer to set session cookies. `HttpOnly` prevents scripts from reading the cookie, but does not stop injected scripts from making authenticated requests. Follow the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for token storage and cookie attributes, and the [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for protection against cross-site requests.

### Minimize Sensitive Data in Component State and Props

Passing entire data objects through the component tree exposes sensitive fields to components that do not need them. Each component that receives a full object containing sensitive data is an additional location where that data can be accidentally logged, rendered, or forwarded to a third-party service. Pass only the specific fields each component requires. Destructure data at the point where it is fetched and distribute only what is necessary.

### Keep Sensitive Data Out of URLs

React Router's `navigate()` and `<Link>` perform ordinary URL navigation, so a query string assembled in JSX is exposed like any other URL: it persists in browser history, reaches server logs on page loads and through the same-origin referrer on API requests, and is readable by any third-party script through `window.location`. Router location state is not a hiding place either: React Router documents the `state` option as [`history.state`](https://api.reactrouter.com/v8/functions/react-router.useNavigate), so it persists in session history across reloads and is readable by any script on the page. Keep session identifiers in `HttpOnly` cookies and never in routes. The [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) covers session ID exposure through URLs in full, and the [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) covers password-reset URL tokens and their controls.

### Do Not Expose Secrets Through Environment Variables

React applications built with Vite expose referenced `VITE_` environment variables in client JavaScript. Reserve these variables for intentionally public values; see the [Vite environment variable guide](https://vite.dev/guide/env-and-mode). Keep secrets in server-side configuration and out of browser-delivered code, public assets, and version control. Review Vite's [`envPrefix`](https://vite.dev/config/shared-options.html#envprefix) and [`define`](https://vite.dev/config/shared-options.html#define) options because they can change which values reach the bundle. Next.js environment variable controls are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html).

## Authentication and Authorization

React route guards, hidden buttons, and role checks in components control the user interface. They do not authorize API requests. Enforce authorization on the server for each protected operation, independently of what the React client renders; follow the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). Never rely on client-provided roles as proof of permission.

## Server-Side Rendering Security

SSR and RSC execute React code in a server environment that has direct access to databases, secrets, and internal network resources. This execution context introduces a class of vulnerabilities that do not exist in client-side React applications. The most critical architectural concern is the server/client data boundary, the point at which data serialized on the server is transmitted to the browser. Props passed from a Server Component to a Client Component cross this boundary automatically through the React Server Components protocol ([Next.js: How to Think About Security](https://nextjs.org/blog/security-nextjs-server-components-actions)), and any data that crosses it becomes accessible to the client regardless of how it was originally obtained or marked. Framework-specific guards for this boundary, including Server Actions and the `server-only` package, are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html); this section covers what applies to any React SSR or RSC setup.

Filter and authorize data in a server-side data access layer before it reaches React's render context; the [Next.js data security guide](https://nextjs.org/docs/app/guides/data-security#data-access-layer) describes this pattern. React's experimental taint APIs provide an additional check for accidental disclosure, with limitations covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html#control-data-crossing-into-the-browser). Tainting does not replace filtering and authorization.

### Shape Data Explicitly at the Server/Client Boundary

Every prop passed from a Server Component to a Client Component is serialized into the payload sent to the browser. Pass only the specific fields a Client Component requires, and shape the data explicitly at the point where it crosses the boundary rather than passing full objects; a full database record exposes all of its fields to anyone inspecting network traffic or the browser environment, including fields that were never intended to leave the server.

```jsx
// Illustrative Server Component output; user has already been authorized for this viewer.
// Avoid passing the complete record to the Client Component:
<ClientProfile user={user} />

// Pass only the fields the viewer is authorized to receive and the component needs:
<ClientProfile name={user.name} avatarUrl={user.avatarUrl} />
```

This applies equally to environment variables and other server-side values: never pass a secret or internal credential as a prop to a Client Component. Framework-level guards such as the `server-only` package and the `NEXT_PUBLIC_` prefix convention are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html), including the limitation that `server-only` prevents a module from being imported into a Client Component but does not stop server code from explicitly returning sensitive data.

### Validate User Input Before Server-Side Fetch Calls

When a Server Component fetches a user-selected resource, apply the [OWASP Server-Side Request Forgery (SSRF) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html). The request originates from the server and may reach internal services unavailable to the browser. Prefer a server-controlled destination and validate user input used in its path or query. If destinations must vary, apply the sheet's destination validation and redirect controls; validating a path segment alone does not prevent SSRF.

### Use a Server-Compatible Sanitization Library for SSR HTML

Sanitize untrusted HTML on the server before including it in an SSR response; client-side sanitization cannot protect HTML the browser has already parsed. To use DOMPurify in Node.js, follow its [server-side setup](https://github.com/cure53/DOMPurify#running-dompurify-on-the-server) with a current, supported DOM implementation such as jsdom. Keep both dependencies updated: DOMPurify warns that vulnerabilities in older jsdom versions can undermine sanitization.

### JSON State Serialization

Embedding state into `<script>` tags with `JSON.stringify` during SSR hydration allows attacker-controlled strings such as `</script>` to break out of the script context and inject markup. Escape HTML-significant characters before embedding state, using a library such as [serialize-javascript](https://github.com/yahoo/serialize-javascript), with HTML escaping enabled, whenever you serialize JSON-compatible state yourself rather than using the framework's serializer. See the [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) for output encoding in script contexts.

### Authorize Inside Server Functions

Server Functions are client-callable. For protected operations, enforce authentication and authorization inside the function. Validate every argument as untrusted input; [react.dev](https://react.dev/reference/rsc/use-server) states this requirement. Framework-specific Server Action and routing-layer controls are covered in the [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html).

## Other Considerations

Use a Content Security Policy to limit the damage of several threats described in this sheet. See the [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).

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

## References

- [DOMPurify: HTML Sanitization](https://github.com/cure53/DOMPurify#what-does-it-do)
- [React: use server Security Considerations](https://react.dev/reference/rsc/use-server)
- [Vite: Environment Variables and Modes](https://vite.dev/guide/env-and-mode)
