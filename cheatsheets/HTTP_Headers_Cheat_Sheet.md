# HTTP Security Response Headers Cheat Sheet

## Introduction

HTTP Headers are a great booster for web security with easy implementation. Proper HTTP response headers can help prevent security vulnerabilities like Cross-Site Scripting, Clickjacking, Information disclosure and more.

In this cheat sheet, we will review all security-related HTTP headers, recommended configurations, and reference other sources for complicated headers.

## Security Headers

### X-Frame-Options

The `X-Frame-Options` HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`. Sites can use this to avoid clickjacking attacks, by ensuring that their content is not embedded into other sites.

#### Recommendation

Do not allow displaying of the page in a frame.
> `X-Frame-Options: DENY`

### X-XSS-Protection

The HTTP `X-XSS-Protection` response header is a feature of Internet Explorer, Chrome, and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks.

#### Recommendation

Do not set this header or explicitly turn it off.
> `X-XSS-Protection: 0`

Please see [Mozilla X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection) for details.

### X-Content-Type-Options

The `X-Content-Type-Options` response HTTP header is used by the server to prevent browsers from guessing the media type ( MIME type).
This is known as **MIME sniffing** in which the browser guesses the correct MIME type by looking at the contents of the resource.
The absence of this header might cause browsers to transform non-executable content into executable content.

#### Recommendation

> `X-Content-Type-Options: nosniff`

### Referrer-Policy

The `Referrer-Policy` HTTP header controls how much referrer information (sent via the Referer header) should be included with requests.

#### Recommendation

Referrer policy has been supported by browsers since 2014. Today, the default behavior in modern browsers is to no longer send all referrer information (origin, path, and query string) to the same site but to only send the origin to other sites. However, since not all users may be using the latest browsers we suggest forcing this behavior by sending this header on all requests.

> `Referrer-Policy: strict-origin-when-cross-origin`

- *NOTE:* For more information on configuring this header please see [Mozilla Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy).

### Content-Type

The `Content-Type` representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending).

#### Recommendation

> `Content-Type: text/html; charset=UTF-8`

- *NOTE:* the `charset` attribute is necessary to prevent XSS in **HTML** pages
- *NOTE*: the `text/html` can be any of the possible [MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types)

### Set-Cookie

The `Set-Cookie` HTTP response header is used to send a cookie from the server to the user agent, so the user agent can send it back to the server later. To send multiple cookies, multiple Set-Cookie headers should be sent in the same response.

#### Recommendation

- Please read [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies) for a detailed explanation on cookie configuration options.

### Strict-Transport-Security

The HTTP `Strict-Transport-Security` response header (often abbreviated as HSTS) lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP.

#### Recommendation

Enable HTTPS-only access for the site and sub domains.
> `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

Please checkout [HTTP Strict Transport Security Cheat Sheet](HTTP_Strict_Transport_Security_Cheat_Sheet.md) for more information.

### Expect-CT

The `Expect-CT` header lets sites opt-in to reporting of Certificate Transparency (CT) requirements. Given that mainstream clients now require CT qualification, the only remaining value is reporting such occurrences to the nominated report-uri value in the header. The header is now less about enforcement and more about detection/reporting.

Please note Mozilla states that [this header will be obsolete](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT) in June 2021.

#### Recommendation

Set Certificate Transparency so user agents report Expect-CT failures.
> `Expect-CT: max-age=604800, report-uri="https://foo.example/report"`

### Content-Security-Policy

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement to distribution of malware.

#### Recommendation

Content Security Policy is very complex to configure and maintain. For an explanation on customization options, please read [Content Security Policy Cheat Sheet](Content_Security_Policy_Cheat_Sheet.md)

### Access-Control-Allow-Origin

The `Access-Control-Allow-Origin` response header indicates whether the response can be shared with requesting code from the given origin.

#### Recommendation

Prefer using specific [origin](https://developer.mozilla.org/en-US/docs/Glossary/Origin) instead of `*`. Checkout [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) for details.
> `Access-Control-Allow-Origin: https://yoursite.com`

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

### FLoC (Federated Learning of Cohorts)

FLoC is a method proposed by Google in 2021 to deliver interest-based advertisements to groups of users ("cohorts"). The [Electronic Frontier Foundation](https://www.eff.org/deeplinks/2021/03/googles-floc-terrible-idea), [Mozilla](https://blog.mozilla.org/en/privacy-security/privacy-analysis-of-floc/), and others believe FLoC does not do enough to protect users' privacy.

#### Recommendation

A site can declare that it does not want to be included in the user's list of sites for cohort calculation by sending this HTTP header.
> Permissions-Policy: interest-cohort=()

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

## Adding HTTP Headers in Different Technologies

### PHP

The sample code below sets the `X-Frame-Options` header in PHP.

```php
header("X-Frame-Options: DENY");
```

### Apache

Below is an `.htaccess` sample configuration which sets the `X-Frame-Options` header in Apache.

```lang-bsh
<IfModule mod_headers.c>
Header set X-Frame-Options "DENY"
</IfModule>
```

### IIS

Add configurations below to your `Web.config` in ISS to send the `X-Frame-Options` header.

```xml
<system.webServer>
...
 <httpProtocol>
   <customHeaders>
     <add name="X-Frame-Options" value="DENY" />
   </customHeaders>
 </httpProtocol>
...
</system.webServer>
```

### HAProxy

Add the line below to your font-end, listen, or backend configurations to send the `X-Frame-Options` header.

```lang-none
http-response set-header X-Frame-Options DENY
```

### Nginx

Below is a sample configuration, it sets the `X-Frame-Options` header in Nginx.

```lang-none
add_header "X-Frame-Options" "DENY";
```

### Express

You can use [helmet](https://www.npmjs.com/package/helmet) to setup HTTP headers in Express. The code below is sample for adding the `X-Frame-Options` header.

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

[SmartScanner](https://www.thesmartscanner.com/) has a dedicated [test profile](https://www.thesmartscanner.com/docs/configuring-security-tests) for testing security of HTTP headers.
Online tools usually test the homepage of the given address. But SmartScanner scans the whole website. So, you can make sure all of your web pages have the right HTTP Headers in place.

## References

- [Mozilla: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [Mozilla: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
- [hstspreload.org](https://hstspreload.org/)
- [Mozilla: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [Mozilla: Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
- [Mozilla: Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT)
- [Mozilla: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [content-security-policy.com](https://content-security-policy.com/)
- [Mozilla: Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
- [resourcepolicy.fyi](https://resourcepolicy.fyi/)
- [Mozilla: Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
- [Mozilla: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
- [Mozilla: Server Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server)
- [Linked OWASP project: Secure Headers Project](https://owasp.org/www-project-secure-headers/)
