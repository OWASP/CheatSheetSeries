# HTTP Headers Cheat Sheet

## Introduction

HTTP Headers are a great booster for web security with easy implementation. Proper HTTP headers can prevent security vulnerabilities like Cross-Site Scripting, Click-jacking, Packet sniffing and, information disclosure.

In this cheat sheet, we will review all security-related HTTP headers and the recommended configurations for them.

## Security Headers

### X-Frame-Options

The `X-Frame-Options` HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`. Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.

#### Recommendation

Do not allow displaying of the page in a frame.
> `X-Frame-Options: DENY`

### X-XSS-Protection

The HTTP `X-XSS-Protection` response header is a feature of Internet Explorer, Chrome, and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks.

#### Recommendation

Enable XSS filtering and prevent browsers from rendering pages if an attack is detected.
> `X-XSS-Protection: 1; mode=block`

### X-Content-Type-Options

The `X-Content-Type-Options` response HTTP header is used by the server to prevent browsers from guessing the media type ( MIME type).
This is known as **MIME sniffing** in which the browser guesses the correct MIME type by looking at the contents of the resource.
The absence of this header might cause browsers to transform non-executable content into executable content.

#### Recommendation

> `X-Content-Type-Options: nosniff`

### Referrer-Policy

The `Referrer-Policy` HTTP header controls how much referrer information (sent via the Referer header) should be included with requests.

#### Recommendation

Send everything to the same site but only the origin for other sites.
> `Referrer-Policy: strict-origin-when-cross-origin`

- *NOTE:* This is the default in modern browsers

### Content-Type

The `Content-Type` representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending).

#### Recommendation

> `Content-Type: text/html; charset=UTF-8`

- *NOTE:* the `charset` attribute is necessary to prevent XSS in **HTML** pages
- *NOTE*: the `text/html` can be any of the possible [MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types)

### Set-Cookie

The `Set-Cookie` HTTP response header is used to send a cookie from the server to the user agent, so the user agent can send it back to the server later. To send multiple cookies, multiple Set-Cookie headers should be sent in the same response.

#### Recommendation

> `Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict`

- *NOTE:* The `Domain` attribute has been removed intentionally

### Strict-Transport-Security

The HTTP `Strict-Transport-Security` response header (often abbreviated as HSTS) lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP.

#### Recommendation

Enable HTTPS-only access for the site and sub domains.
> `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

Please checkout [HTTP Strict Transport Security Cheat Sheet](HTTP_Strict_Transport_Security_Cheat_Sheet.md) for more information.

### Expect-CT

The `Expect-CT` header lets sites opt-in to reporting and/or enforcement of Certificate Transparency requirements, to prevent the use of misissued certificates for that site from going unnoticed.

#### Recommendation

Enforce Certificate Transparency for 24 hours.
> `Expect-CT: max-age=86400`

### Content-Security-Policy

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement to distribution of malware.

#### Recommendation

Restrict most of the resource types to the same site and subdomains of `yourdoamin.com`
> `Content-Security-Policy: default-src 'self' *.yourdomain.com; block-all-mixed-content; font-src 'self' https: data:; img-src 'self' data: blob:; object-src 'none'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests;`

- *WARNING*: Inline `script` elements and inline script event handlers like `onload` will stop working with the above header. But this is required to neutralize XSS attacks.

### Access-Control-Allow-Origin

The `Access-Control-Allow-Origin` response header indicates whether the response can be shared with requesting code from the given origin.

#### Recommendation

Use `*` or specific domain names.
> `Access-Control-Allow-Origin: *`

### Cross-Origin-Opener-Policy

The HTTP `Cross-Origin-Opener-Policy` (COOP) response header allows you to ensure a top-level document does not share a browsing context group with cross-origin documents.

#### Recommendation

Isolates the browsing context exclusively to same-origin documents.
> `HTTP Cross-Origin-Opener-Policy: same-origin`

### Cross-Origin-Resource-Policy

The `Cross-Origin-Resource-Policy` (CORP) header allows you to control the set of origins that are empowered to include a resource. It is a robust defense against attacks like [Spectre](https://meltdownattack.com/), as it allows browsers to block a given response before it enters an attacker's process.

#### Recommendation

Limit current resource loading to the site and sub-domains only.
> `Cross-Origin-Resource-Policy: same-site`

### Cross-Origin-Embedder-Policy

The HTTP `Cross-Origin-Embedder-Policy` (COEP) response header prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using [CORP](#cross-origin-resource-policy) or CORS).

#### Recommendation

A document can only load resources from the same origin, or resources explicitly marked as loadable from another origin.
> `Cross-Origin-Embedder-Policy: require-corp`

- *NOTE*: you can bypass it by adding the `crossorigin` attribute like below:
- `<img src="https://thirdparty.com/img.png" crossorigin>`

### Server

The `Server` header describes the software used by the origin server that handled the request — that is, the server that generated the response.

#### Recommendation

Remove this header or set non-informative values.
> `Server: webserver`

### X-Powered-By

The `X-Powered-By` header describes the technologies used by the webserver. This information exposes the server to attackers. Using the information in this header, attackers can find vulnerabilities easier.

#### Recommendation

Remove all `X-Powered-By` headers.

### X-AspNet-Version

Provides information about the .NET version.

#### Recommendation

Disable sending this header. Add the following line in your `web.config` in the `<system.web>` section to remove it.

```xml
<httpRuntime enableVersionHeader="false" />
```

### X-AspNetMvc-Version

Provides information about the .NET version.

#### Recommendation

Disable sending this header. To remove the `X-AspNetMvc-Version` header, add the below line in `Global.asax` file.

```lang-none
MvcHandler.DisableMvcResponseHeader = true;
```

### X-DNS-Prefetch-Control

The `X-DNS-Prefetch-Control` HTTP response header controls DNS prefetching, a feature by which browsers proactively perform domain name resolution on both links that the user may choose to follow as well as URLs for items referenced by the document, including images, CSS, JavaScript, and so forth.

#### Recommendation

The default behavior of browsers is to perform DNS caching which is good for most websites.
If you do not control links on your website, you might want to set `off` as a value to disable DNS prefetch to avoid leaking information to those domains.

### Public-Key-Pins ❌

The HTTP `Public-Key-Pins` response header is used to associate a specific cryptographic public key with a certain web server to decrease the risk of MITM attacks with forged certificates.

#### Recommendation

This header is deprecated. Use `Expect-CT` instead.

## Adding Http Headers in Different Technologies

### PHP

Below sample code sets the `X-XSS-Protection` header in PHP.

```php
header("X-XSS-Protection: 1; mode=block");
```

### Apache

Below `.htaccess` sample configuration sets the `X-XSS-Protection` header in Apache.

```lang-bsh
<IfModule mod_headers.c>
Header set X-XSS-Protection "1; mode=block"
</IfModule>
```

### IIS

Add below configurations to your `Web.config` in ISS to send the `X-XSS-Protection` header

```xml
<system.webServer>
...
 <httpProtocol>
   <customHeaders>
     <add name="X-XSS-Protection" value="1; mode=block" />
   </customHeaders>
 </httpProtocol>
...
</system.webServer>
```

### HAProxy

Add the below line to your font-end, listen, or backend configurations to send the `X-XSS-Protection` header

```lang-none
http-response set-header X-XSS-Protection 1; mode=block
```

### Nginx

Below sample configuration, sets the `X-XSS-Protection` header in Nginx.

```lang-none
add_header "X-XSS-Protection" "1; mode=block";
```

### Express

You can use [helmet](https://www.npmjs.com/package/helmet) to setup HTTP headers in Express. Below code is sample for adding the `X-Frame-Options` header.

```javascript
const helmet = require('helmet');
const app = express();
// Sets "X-Frame-Options: SAMEORIGIN"
app.use(
 helmet.frameguard({
   action: "sameorigin",
 })
);
```

## Testing Proper Implementation of Security Headers

### Mozilla Observatory

The [Mozilla Observatory](https://observatory.mozilla.org/) is an online tool that you can check your website's header status.

### SmartScanner

[SmartScanner](https://www.thesmartscanner.com/) has a dedicated [test profile](https://www.thesmartscanner.com/docs/security-tests) for testing security of HTTP headers.
Online tools usually test the homepage of the given address. But SmartScanner scans the whole website. So, you can make sure all of your web pages have the right HTTP Headers in place.

## References

- [Mozilla: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [Mozilla: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
- [hstspreload.org](https://hstspreload.org/)
- [Mozilla: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [Mozilla: Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
- [Mozilla: Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT)
- [Mozilla: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
- [Mozilla: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [content-security-policy.com](https://content-security-policy.com/)
- [Mozilla: Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin)
- [Mozilla: Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
- [resourcepolicy.fyi](https://resourcepolicy.fyi/)
- [Mozilla: Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
- [Mozilla: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
- [Mozilla: Server Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server)
