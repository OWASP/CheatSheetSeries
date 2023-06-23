# Cross-Site Request Forgery Prevention Cheat Sheet

## Introduction

[Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. A CSRF attack works because browser requests automatically include all cookies including session cookies. Therefore, if the user is authenticated to the site, the site cannot distinguish between legitimate authorized requests and forged authenticated requests. This attack is thwarted when proper Authorization is used, which implies that a challenge-response mechanism is required that verifies the identity and authority of the requester.

The impact of a successful CSRF attack is limited to the capabilities exposed by the vulnerable application and privileges of the user. For example, this attack could result in a transfer of funds, changing a password, or making a purchase with the user's credentials. In effect, CSRF attacks are used by an attacker to make a target system perform a function via the victim's browser, without the victim's knowledge, at least until the unauthorized transaction has been committed.

In short, the following principles should be followed to defend against CSRF:

- **Check if your framework has [built-in CSRF protection](#use-built-in-or-existing-csrf-implementations-for-csrf-protection) and use it**
    - **If framework does not have built-in CSRF protection, add [CSRF tokens](#token-based-mitigation) to all state changing requests (requests that cause actions on the site) and validate them on the backend**
- **For stateful software use the [synchronizer token pattern](#synchronizer-token-pattern)**
- **For stateless software use [double submit cookies](#double-submit-cookie)**
- **For API-driven sites that don't use `<form>` tags, consider [using custom request headers](#custom-request-headers)**
- **Implement at least one mitigation from [Defense in Depth Mitigations](#defense-in-depth-techniques) section**
    - **Consider [SameSite Cookie Attribute](#samesite-cookie-attribute) for session cookies** but be careful to NOT set a cookie specifically for a domain as that would introduce a security vulnerability that all subdomains of that domain share the cookie. This is particularly an issue when a subdomain has a CNAME to domains not in your control.
    - **Consider implementing [user interaction based protection](#user-interaction-based-csrf-defense) for highly sensitive operations**
    - **Consider [verifying the origin with standard headers](#verifying-origin-with-standard-headers)**
- **Remember that any Cross-Site Scripting (XSS) can be used to defeat all CSRF mitigation techniques!**
    - **See the OWASP [XSS Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) for detailed guidance on how to prevent XSS flaws.**
- **Do not use GET requests for state changing operations.**
    - **If for any reason you do it, protect those resources against CSRF**

## Token Based Mitigation

The [synchronizer token pattern](#synchronizer-token-pattern) is one of the most popular and recommended methods to mitigate CSRF.

### Use Built-In Or Existing CSRF Implementations for CSRF Protection

Synchronizer token defenses have been built into many frameworks. It is strongly recommended to research if the framework you are using has an option to achieve CSRF protection by default before trying to build your custom token generating system. For example, .NET has [built-in protection](https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-2.1) that adds a token to CSRF vulnerable resources. You are responsible for proper configuration (such as key management and token management) before using these built-in CSRF protections that generate tokens to guard CSRF vulnerable resources.

### Synchronizer Token Pattern

CSRF tokens should be generated on the server-side. They can be generated once per user session or for each request. Per-request tokens are more secure than per-session tokens as the time range for an attacker to exploit the stolen tokens is minimal. However, this may result in usability concerns. For example, the "Back" button browser capability is often hindered as the previous page may contain a token that is no longer valid. Interaction with this previous page will result in a CSRF false positive security event on the server. In per-session token implementations after the initial generation of a token, the value is stored in the session and is used for each subsequent request until the session expires.

When a request is issued by the client, the server-side component must verify the existence and validity of the token in the request compared to the token found in the user session. If the token was not found within the request, or the value provided does not match the value within the user session, then the request should be rejected. Additional actions such as logging the event as a potential CSRF attack in progress should also be considered.

CSRF tokens should be:

- Unique per user session.
- Secret
- Unpredictable (large random value generated by a [secure method](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#rule---use-cryptographically-secure-pseudo-random-number-generators-csprng)).

CSRF tokens prevent CSRF because without a token, an attacker cannot create valid requests to the backend server.

**For the Synchronised Token Pattern, CSRF tokens should not be transmitted using cookies.**

The CSRF token can be transmitted to the client as part of a response payload, such as a HTML or JSON response. It can then be transmitted back to the server as a hidden field on a form submission, or via an AJAX request as a custom header value or part of a JSON payload. Make sure that the token is not leaked in the server logs, or in the URL. CSRF tokens in GET requests are potentially leaked at several locations, such as the browser history, log files, network utilities that log the first line of a HTTP request, and Referer headers if the protected site links to an external site.

For example:

``` html
<form action="/transfer.do" method="post">
<input type="hidden" name="CSRFToken" value="OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==">
[...]
</form>
```

Inserting the CSRF token in a custom HTTP request header via JavaScript is considered more secure than adding the token in the hidden field form parameter because requests with custom headers are automatically subject to the same-origin policy.

### Double Submit Cookie

If maintaining the state for CSRF token on the server is problematic, you can use an alternative technique known as the Double Submit Cookie pattern. This technique is easy to implement and is stateless. There are different ways to implement this technique, where the _naive_ pattern is the most commonly used variation.

#### Naive Double Submit Cookie

The _Naive Double Submit Cookie_ is a scalable and easy-to-implement technique where we send a random value in both a cookie and as a request parameter, with the server verifying if the cookie value and request value match. When a user visits (even before authenticating to prevent login CSRF), the site should generate a (ideally cryptographically strong) random value and set it as a cookie on the user's machine separate from the session identifier. The site then requires that every transaction request includes this random value as a hidden form value, or in the request header. If both of them match at server side, the server accepts it as legitimate request and if they don't, it would reject the request.

In a nutshell, an attacker is unable to access the cookie value during a cross-site request. This prevents them from including a matching value in the hidden form value or as a request parameter/header.

The Naive Double Submit Cookie method is a good initial step to counter CSRF attacks, but it remains vulnerable to certain attacks. [This resource](https://owasp.org/www-chapter-london/assets/slides/David_Johansson-Double_Defeat_of_Double-Submit_Cookie.pdf) provides more information on some vulnerabilities. It is therefore recommended to use a more secure implementation, the _Signed Double Submit Cookie_ pattern.

#### Signed Double Submit Cookie

The _Signed Double Submit Cookie_ involves a secret key known only to the server. This ensures that an attacker cannot create and inject their own, known, CSRF token into the victim's authenticated session. Tokens can be secured by hashing or encrypting them, with HMAC algorithm being a popular choice due to its fast speed and easy implementation.

In both cases, it is recommended to bind the CSRF token with the users current session to even further enhance security.

##### HMAC CSRF Token

A simpler alternative to an encrypted CSRF cookie is to use HMAC (Hash-based Message Authentication Code) to hash the random value with a secret key known only by the server and place this value in a cookie. This is similar to an encrypted cookie (both require knowledge only the server holds), but is less computationally intensive than encrypting and decrypting the cookie.

We recommend generating the HMAC CSRF Token, with a session-dependent user value, using the following steps:

- **A session-dependent value that changes with each login session**. This value should only be valid for the entirety of the users authenticated session. Avoid using static values like the user's email or ID, as they are not secure ([1](https://stackoverflow.com/a/8656417) | [2](https://stackoverflow.com/a/30539335) | [3](https://security.stackexchange.com/a/22936)). It's worth noting that updating the CSRF token too frequently, such as for each request, is a misconception that assumes it adds substantial security while actually harming the user experience ([1](https://security.stackexchange.com/a/22936)). For example, you could choose one of the following session-dependent values:
    - The server-side session ID (e.g. [PHP](https://www.php.net/manual/en/function.session-start.php) or [ASP.NET](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms178581(v=vs.100)))
    - A random value (e.g. UUID) within a JWT that changes every time a JWT is created
- **A secret cryptographic key** Not to confuse with the random value from the naive implementation. This value is used to generate the HMAC hash. Ideally, store this key as an environment variable.
- **A random value for anti-collision purposes**. Generate a random value (preferably cryptographically random) to ensure that consecutive calls within the same second do not produce the same hash ([1](https://github.com/data-govt-nz/ckanext-security/issues/23#issuecomment-479752531)).

Below is an example in pseudo-code that demonstrates the implementation steps described above:

```code
// Gather the values
secret = readEnvironmentVariable("CSRF_SECRET") // HMAC secret key
sessionID = session.sessionID // Current authenticated user session
randomValue = cryptographic.randomValue() // Cryptographic random value

// Create the CSRF Token
message = sessionID + "!" + randomValue // HMAC message payload
hmac = hmac("SHA256", secret, message) // Generate the HMAC hash
csrfToken = hmac + "." + message // Combine HMAC hash with message to generate the token. The plain message is required to later authenticate it against its HMAC hash

// Store the CSRF Token in a cookie
response.setCookie("csrf_token=" + csrfToken + "; Secure) // Set Cookie without HttpOnly flag
```

> **Should Timestamps be Included in CSRF Tokens for Expiration?**  
> It's a common misconception to include timestamps as a value to specify the CSRF token expiration time. A CSRF Token is not an access token. They are used to verify the authenticity of requests throughout a session, using session information. A new session should generate a new token ([1](https://stackoverflow.com/a/30539335)).

### Custom Request Headers

Both the synchronizer token and the double submit cookie are used to prevent forgery of form data, but they can be tricky to implement and degrade usability. Many modern web applications do not use `<form>` tags. A user-friendly defense that is particularly well suited for AJAX or API endpoints is the use of a **custom request header**. No token is needed for this approach.

In this pattern, the client appends a custom header to requests that require CSRF protection. The header can be any arbitrary key-value pair, as long as it does not conflict with existing headers.

```
X-YOURSITE-CSRF-PROTECTION=1
```

When handling the request, the API checks for the existence of this header. If the header does not exist, the backend rejects the request as potential forgery. This approach has several advantages:

- UI changes are not required
- no server state is introduced to track tokens

If you use `<form>` tags anywhere in your client, you will still need to protect them with alternate approaches described in this document such as tokens.

This defense relies on the browser's [same-origin policy (SOP)](https://en.wikipedia.org/wiki/Same-origin_policy) restriction that only JavaScript can be used to add a custom header, and only within its origin. By default, browsers do not allow JavaScript to make cross origin requests with custom headers. Only JavaScript that you serve from your origin can add these headers.

#### Custom Headers and CORS

Cookies are not set on cross-origin requests (CORS) by default. To enable cookies on an API, you will set `Access-Control-Allow-Credentials=true`. The browser will reject any response that includes `Access-Control-Allow-Origin=*` if credentials are allowed. To allow CORS requests, but protect against CSRF, you need to make sure the server only whitelists a few select origins that you definitively control via the `Access-Control-Allow-Origin` header. Any cross-origin request from an allowed domain will be able to set custom headers.

As an example, you might configure your backend to allow CORS with cookies from `http://www.yoursite.com` and `http://mobile.yoursite.com`, so that the only possible preflight responses are:

```
Access-Control-Allow-Origin=http://mobile.yoursite.com
Access-Control-Allow-Credentials=true
```

or

```
Access-Control-Allow-Origin=http://www.yoursite.com
Access-Control-Allow-Credentials=true
```

A less secure configuration would be to configure your backend server to allow CORS from all subdomains of your site using a regular expression. If an attacker is able to [take over a subdomain](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover) (not uncommon with cloud services) your CORS configuration would allow them to bypass the same origin policy and forge a request with your custom header.

## Defense In Depth Techniques

### SameSite Cookie Attribute

SameSite is a cookie attribute (similar to HTTPOnly, Secure etc.) which aims to mitigate CSRF attacks. It is defined in [RFC6265bis](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7). This attribute helps the browser decide whether to send cookies along with cross-site requests. Possible values for this attribute are `Lax`, `Strict`, or `None`.

The Strict value will prevent the cookie from being sent by the browser to the target site in all cross-site browsing context, even when following a regular link. For example, for a GitHub-like website this would mean that if a logged-in user follows a link to a private GitHub project posted on a corporate discussion forum or email, GitHub will not receive the session cookie and the user will not be able to access the project. A bank website however doesn't want to allow any transactional pages to be linked from external sites, so the Strict flag would be most appropriate.

The default Lax value provides a reasonable balance between security and usability for websites that want to maintain user's logged-in session after the user arrives from an external link. In the above GitHub scenario, the session cookie would be allowed when following a regular link from an external website while blocking it in CSRF-prone request methods such as POST. Only cross-site-requests that are allowed in Lax mode are the ones that have top-level navigations and are also [safe](https://tools.ietf.org/html/rfc7231#section-4.2.1) HTTP methods.

For more details on the `SameSite` values, check the following [section](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1) from the [rfc](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02).

Example of cookies using this attribute:

```text
Set-Cookie: JSESSIONID=xxxxx; SameSite=Strict
Set-Cookie: JSESSIONID=xxxxx; SameSite=Lax
```

All desktop browsers and almost all mobile browsers now support the `SameSite` attribute. To keep track of the browsers implementing it and the usage of the attribute, refer to the following [service](https://caniuse.com/#feat=same-site-cookie-attribute). Note that Chrome has [announced](https://blog.chromium.org/2019/10/developers-get-ready-for-new.html) that they will mark cookies as `SameSite=Lax` by default from Chrome 80 (due in February 2020), and Firefox and Edge are both planning to follow suit. Additionally, the `Secure` flag will be required for cookies that are marked as `SameSite=None`.

It is important to note that this attribute should be implemented as an additional layer *defense in depth* concept. This attribute protects the user through the browsers supporting it, and it contains as well 2 ways to bypass it as mentioned in the following [section](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1). This attribute should not replace having a CSRF Token. Instead, it should co-exist with that token in order to protect the user in a more robust way.

### Verifying Origin With Standard Headers

There are two steps to this mitigation, both of which rely on examining an HTTP request header value.

1. Determining the origin the request is coming from (source origin). Can be done via Origin or Referer headers.
2. Determining the origin the request is going to (target origin).

At server side we verify if both of them match. If they do, we accept the request as legitimate (meaning it's the same origin request) and if they don't, we discard the request (meaning that the request originated from cross-domain). Reliability on these headers comes from the fact that they cannot be altered programmatically as they fall under [forbidden headers](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name) list, meaning that only the browser can set them.

#### Identifying Source Origin (via Origin/Referer header)

##### Checking the Origin Header

If the Origin header is present, verify that its value matches the target origin. Unlike the Referer, the Origin header will be present in HTTP requests that originate from an HTTPS URL.

##### Checking the Referer Header

If the Origin header is not present, verify the hostname in the Referer header matches the target origin. This method of CSRF mitigation is also commonly used with unauthenticated requests, such as requests made prior to establishing a session state, which is required to keep track of a synchronization token.

In both cases, make sure the target origin check is strong. For example, if your site is `example.org` make sure `example.org.attacker.com` does not pass your origin check (i.e, match through the trailing / after the origin to make sure you are matching against the entire origin).

If neither of these headers are present, you can either accept or block the request. We recommend **blocking**. Alternatively, you might want to log all such instances, monitor their use cases/behavior, and then start blocking requests only after you get enough confidence.

#### Identifying the Target Origin

You might think it's easy to determine the target origin, but it's frequently not. The first thought is to simply grab the target origin (i.e., its hostname and port `#`) from the URL in the request. However, the application server is frequently sitting behind one or more proxies and the original URL is different from the URL the app server actually receives. If your application server is directly accessed by its users, then using the origin in the URL is fine and you're all set.

If you are behind a proxy, there are a number of options to consider.

- **Configure your application to simply know its target origin:** It's your application, so you can find its target origin and set that value in some server configuration entry. This would be the most secure approach as it's defined server side, so it is a trusted value. However, this might be problematic to maintain if your application is deployed in many places, e.g., dev, test, QA, production, and possibly multiple production instances. Setting the correct value for each of these situations might be difficult, but if you can do it via some central configuration and providing your instances to grab value from it, that's great! (**Note:** Make sure the centralized configuration store is maintained securely because major part of your CSRF defense depends on it.)

- **Use the Host header value:** If you prefer that the application find its own target so it doesn't have to be configured for each deployed instance, we recommend using the Host family of headers. The Host header's purpose is to contain the target origin of the request. But, if your app server is sitting behind a proxy, the Host header value is most likely changed by the proxy to the target origin of the URL behind the proxy, which is different than the original URL. This modified Host header origin won't match the source origin in the original Origin or Referer headers.

- **Use the X-Forwarded-Host header value:** To avoid the issue of proxy altering the host header, there is another header called X-Forwarded-Host, whose purpose is to contain the original Host header value the proxy received. Most proxies will pass along the original Host header value in the X-Forwarded-Host header. So that header value is likely to be the target origin value you need to compare to the source origin in the Origin or Referer header.

This mitigation is working properly when origin or referrer headers are present in the requests. Though these headers are included **majority** of the time, there are few use cases where they are not included (most of them are for legitimate reasons to safeguard users privacy/to tune to browsers ecosystem). The following lists some use cases:

- Internet Explorer 11 does not add the Origin header on a CORS request across sites of a trusted zone. The Referer header will remain the only indication of the UI origin. See the following references in Stack Overflow [here](https://stackoverflow.com/questions/20784209/internet-explorer-11-does-not-add-the-origin-header-on-a-cors-request) and [here](https://github.com/silverstripe/silverstripe-graphql/issues/118).
- In an instance following a [302 redirect cross-origin](https://stackoverflow.com/questions/22397072/are-there-any-browsers-that-set-the-origin-header-to-null-for-privacy-sensitiv), Origin is not included in the redirected request because that may be considered sensitive information that should not be sent to the other origin.
- There are some [privacy contexts](https://wiki.mozilla.org/Security/Origin#Privacy-Sensitive_Contexts) where Origin is set to "null" For example, see the following [here](https://www.google.com/search?q=origin+header+sent+null+value+site%3Astackoverflow.com&oq=origin+header+sent+null+value+site%3Astackoverflow.com).
- Origin header is included for all cross origin requests but for same origin requests, in most browsers it is only included in POST/DELETE/PUT **Note:** Although it is not ideal, many developers use GET requests to do state changing operations.
- Referer header is no exception. There are multiple use cases where referrer header is omitted as well ([1](https://stackoverflow.com/questions/6880659/in-what-cases-will-http-referer-be-empty), [2](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer), [3](https://en.wikipedia.org/wiki/HTTP_referer#Referer_hiding), [4](https://seclab.stanford.edu/websec/csrf/csrf.pdf) and [5](https://www.google.com/search?q=referrer+header+sent+null+value+site:stackoverflow.com)). Load balancers, proxies and embedded network devices are also well known to strip the referrer header due to privacy reasons in logging them.

Usually, a minor percentage of traffic does fall under above categories ([1-2%](http://homakov.blogspot.com/2012/04/playing-with-referer-origin-disquscom.html)) and no enterprise would want to lose this traffic. One of the popular technique used across the Internet to make this technique more usable is to accept the request if the Origin/referrer matches your configured list of domains "OR" a null value (Examples [here](http://homakov.blogspot.com/2012/04/playing-with-referer-origin-disquscom.html). The null value is to cover the edge cases mentioned above where these headers are not sent). Please note that, attackers can exploit this but people prefer to use this technique as a defense in depth measure because of the minor effort involved in deploying it.

#### Cookie with __Host- prefix

Another solution for this problem is use of `Cookie Prefixes` for cookie with CSRF token. If cookie has `__Host-` prefix e.g. `Set-Cookie: __Host-token=RANDOM; path=/; Secure` then the cookie:

- Cannot be (over)written from another subdomain.
- Must have the path of `/`.
- Must be marked as Secure (i.e, cannot be sent over unencrypted HTTP).

As of July 2020 cookie prefixes [are supported by all major browsers except Internet Explorer](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Browser_compatibility).

See the [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) and [IETF Draft](https://tools.ietf.org/html/draft-west-cookie-prefixes-05) for further information about cookie prefixes.

### User Interaction Based CSRF Defense

While all the techniques referenced here do not require any user interaction, sometimes it's easier or more appropriate to involve the user in the transaction to prevent unauthorized operations (forged via CSRF or otherwise). The following are some examples of techniques that can act as strong CSRF defense when implemented correctly.

- ~~Re-Authentication~~ Authorization mechanism (password or stronger)
- One-time Token
- CAPTCHA (prefer newer CAPTCHA versions without user interaction or visual pattern matching)

While these are a very strong CSRF defense, it can create a significant impact on the user experience. As such, they would generally only be used for security critical operations (such as password change, money transfers, etc.), alongside the other defences discussed in this cheat sheet.

## Login CSRF

Most developers tend to ignore CSRF vulnerability on login forms as they assume that CSRF would not be applicable on login forms because user is not authenticated at that stage, however this assumption is not always true. CSRF vulnerabilities can still occur on login forms where the user is not authenticated, but the impact and risk is different.

For example, if an attacker uses CSRF to assume an authenticated identity of a target victim on a shopping website using the attacker's account, and the victim then enters their credit card information, an attacker may be able to purchase items using the victim's stored card details. For more information about login CSRF and other risks, see section 3 of [this](https://seclab.stanford.edu/websec/csrf/csrf.pdf) paper.

Login CSRF can be mitigated by creating pre-sessions (sessions before a user is authenticated) and including tokens in login form. You can use any of the techniques mentioned above to generate tokens. Remember that pre-sessions cannot be transitioned to real sessions once the user is authenticated - the session should be destroyed and a new one should be made to avoid [session fixation attacks](http://www.acrossecurity.com/papers/session_fixation.pdf). This technique is described in [Robust Defenses for Cross-Site Request Forgery section 4.1](https://seclab.stanford.edu/websec/csrf/csrf.pdf).

## Client-side CSRF

[Client-side CSRF](https://soheilkhodayari.github.io/same-site-wiki/docs/attacks/csrf.html#client-side-csrf) is a new variant of CSRF attacks where the attacker tricks the client-side JavaScript code to send a forged HTTP request to a vulnerable target site by manipulating the program’s input parameters. Client-side CSRF originates when the JavaScript program uses attacker-controlled inputs, such as the URL, for the generation of asynchronous HTTP requests.

**Note:** These variants of CSRF are particularly important as they can bypass some of the common anti-CSRF countermeasures like [token-based mitigations](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#token-based-mitigation) and [SameSite cookies](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute). For example, when [synchronizer tokens](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern) or [custom HTTP request headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers) are used, the JavaScript program will include them in the asynchronous requests. Also, web browsers will include cookies in same-site request contexts initiated by JavaScript programs, circumventing the [SameSite cookie policies](https://soheilkhodayari.github.io/same-site-wiki/docs/policies/overview.html).

**Client-side vs. Classical CSRF:** In the classical CSRF, the vulnerable component is the server-side program, which cannot distinguish whether the incoming authenticated request was performed **intentionally**, also known as the confused deputy problem. In the client-side CSRF, the vulnerable component is the client-side JavaScript program instead, which allows an attacker to generate arbitrary asynchronous requests, e.g., by manipulating the request endpoint and/or its parameters. Client-side CSRF is an input validation problem, that when exploited, reintroduces the confused deputy flaw, that is, the server-side won't, again, be able to distinguish if the request was performed intentionally or not.

For more information about client-side CSRF vulnerabilities, see Sections 2 and 5 of this [paper](https://www.usenix.org/system/files/sec21-khodayari.pdf), the [CSRF chapter](https://soheilkhodayari.github.io/same-site-wiki/docs/attacks/csrf.html) of the [SameSite wiki](https://soheilkhodayari.github.io/same-site-wiki), and [this post](https://www.facebook.com/notes/facebook-bug-bounty/client-side-csrf/2056804174333798/) by the [Facebook Whitehat program](https://www.facebook.com/whitehat).

### Client-side CSRF Example

The following code snippet demonstrates a simple example of a client-side CSRF vulnerability.

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");
    function ajaxLoad(){
        // process the URL hash fragment
        let hash_fragment = window.location.hash.slice(1);  

        // hash fragment should be of the format: /^(get|post);(.*)$/
        // e.g., https://site.com/index/#post;/profile
        if(hash_fragment.length > 0 && hash_fragment.indexOf(';') > 0 ){

            let params = hash_fragment.match(/^(get|post);(.*)$/);
            if(params && params.length){
                let request_method = params[1];   
                let request_endpoint = params[3];

                fetch(request_endpoint, {
                    method: request_method,
                    headers: {
                        'XSRF-TOKEN': csrf_token,
                        // [...]
                    },
                    // [...]
                }).then(response => { /* [...] */ }); 
            }
        }
    }
    // trigger the async request on page load
    window.onload = ajaxLoad();
 </script>
```

**Vulnerability:** In this snippet, the program invokes a function `ajaxLoad()` upon the page load, which is responsible for loading various webpage elements. The function reads the value of the [URL hash fragment](https://developer.mozilla.org/en-US/docs/Web/API/Location/hash) (line 4), and extracts two pieces of information from it (i.e., request method and endpoint) to generate an asynchronous HTTP request (lines 11-13). The vulnerability occurs in lines 15-22, when the JavaScript program uses URL fragments to obtain the server-side endpoint for the asynchronous HTTP request (line 15) and the request method. However, both inputs can be controlled by web attackers, who can pick the value of their choosing, and craft a malicious URL containing the attack payload.

**Attack:** For exploitation, attackers can share the malicious URL with the victim (e.g.,  spear-phishing emails) and convince them to click on it, because such URL belongs to the origin of an honest, reputable but vulnerable website. Alternatively, they can use it as a part of an attack page they control and abuse browser APIs (e.g., the [`window.open()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/open) API) to trick the vulnerable JavaScript of the target page to send the HTTP request, which closely resemles the attack model of the classical CSRF attacks.

For more examples of client-side CSRF, see [this post](https://www.facebook.com/notes/facebook-bug-bounty/client-side-csrf/2056804174333798/) by the [Facebook Whitehat program](https://www.facebook.com/whitehat) and this USENIX Security [paper](https://www.usenix.org/system/files/sec21-khodayari.pdf).

### Client-side CSRF Mitigation Techniques

**Independent Requests:** Client-side CSRF can be prevented if asynchronous requests are not generated via attacker controllable inputs, such as the [URL](https://developer.mozilla.org/en-US/docs/Web/API/Window/location), [window name](https://developer.mozilla.org/en-US/docs/Web/API/Window/name), [document referrer](https://developer.mozilla.org/en-US/docs/Web/API/Document/referrer), and [postMessages](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage), to name only a few examples.

**Input Validation:** Achieving complete isolaion between inputs and request parameters may not always be possible depending on the context and functionality. In these cases, input validation checks has to be implemented. These checks should strictly assess the format and choice of the values of the request parameters and decide whether they can only be used in non-state-changing operations (e.g., only allow GET requests and endpoints starting with a predefined prefix).

**Predefined Request Data:** Another mitigation technique is to store a list of predefined, safe request data in the JavaScript code (e.g., combinations of endpoints, request methods and other parameters that are safe to be replayed). The program can then use a switch parameter in the URL fragment to decide which entry of the list should each JavaScript function use.

## Java Reference Example

The following [JEE web filter](https://github.com/righettod/poc-csrf/blob/master/src/main/java/eu/righettod/poccsrf/filter/CSRFValidationFilter.java) provides an example reference for some of the concepts described in this cheatsheet. It implements the following stateless mitigations ([OWASP CSRFGuard](https://github.com/aramrami/OWASP-CSRFGuard), cover a stateful approach).

- Verifying same origin with standard headers
- Double submit cookie
- SameSite cookie attribute

**Please note** that it only acts a reference sample and is not complete (for example: it doesn't have a block to direct the control flow when origin and referrer header check succeeds nor it has a port/host/protocol level validation for referrer header). Developers are recommended to build their complete mitigation on top of this reference sample. Developers should also implement authentication and authorization mechanisms before checking for CSRF is considered effective.

Full source is located [here](https://github.com/righettod/poc-csrf) and provides a runnable POC.

## JavaScript Guidance for Auto-inclusion of CSRF tokens as an AJAX Request header

The following guidance considers **GET**, **HEAD** and **OPTIONS** methods are safe operations. Therefore **GET**, **HEAD**, and **OPTIONS** method AJAX calls need not be appended with a CSRF token header. However, if the verbs are used to perform state changing operations, they will also require a CSRF token header (although this is bad practice, and should be avoided).

The **POST**, **PUT**, **PATCH**, and **DELETE** methods, being state changing verbs, should have a CSRF token attached to the request. The following guidance will demonstrate how to create overrides in JavaScript libraries to have CSRF tokens included automatically with every AJAX request for the state changing methods mentioned above.

### Storing the CSRF Token Value in the DOM

A CSRF token can be included in the `<meta>` tag as shown below. All subsequent calls in the page can extract the CSRF token from this `<meta>` tag. It can also be stored in a JavaScript variable or anywhere on the DOM. However, it is not recommended to store it in cookies or browser local storage.

The following code snippet can be used to include a CSRF token as a `<meta>` tag:

```html
<meta name="csrf-token" content="{{ csrf_token() }}">
```

The exact syntax of populating the content attribute would depend on your web application's backend programming language.

### Overriding Defaults to Set Custom Header

Several JavaScript libraries allow for overriding default settings to have a header added automatically to all AJAX requests.

#### XMLHttpRequest (Native JavaScript)

XMLHttpRequest's open() method can be overridden to set the `anti-csrf-token` header whenever the `open()` method is invoked next. The function `csrfSafeMethod()` defined below will filter out the safe HTTP methods and only add the header to unsafe HTTP methods.

This can be done as demonstrated in the following code snippet:

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");
    function csrfSafeMethod(method) {
        // these HTTP methods do not require CSRF protection
        return (/^(GET|HEAD|OPTIONS)$/.test(method));
    }
    var o = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(){
        var res = o.apply(this, arguments);
        var err = new Error();
        if (!csrfSafeMethod(arguments[0])) {
            this.setRequestHeader('anti-csrf-token', csrf_token);
        }
        return res;
    };
 </script>
```

#### AngularJS

AngularJS allows for setting default headers for HTTP operations. Further documentation can be found at AngularJS's documentation for [$httpProvider](https://docs.angularjs.org/api/ng/provider/$httpProvider#defaults).

```html
<script>
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    var app = angular.module("app", []);

    app.config(['$httpProvider', function ($httpProvider) {
        $httpProvider.defaults.headers.post["anti-csrf-token"] = csrf_token;
        $httpProvider.defaults.headers.put["anti-csrf-token"] = csrf_token;
        $httpProvider.defaults.headers.patch["anti-csrf-token"] = csrf_token;
        // AngularJS does not create an object for DELETE and TRACE methods by default, and has to be manually created.
        $httpProvider.defaults.headers.delete = {
            "Content-Type" : "application/json;charset=utf-8",
            "anti-csrf-token" : csrf_token
        };
        $httpProvider.defaults.headers.trace = {
            "Content-Type" : "application/json;charset=utf-8",
            "anti-csrf-token" : csrf_token
        };
      }]);
 </script>
```

This code snippet has been tested with AngularJS version 1.7.7.

#### Axios

[Axios](https://github.com/axios/axios) allows us to set default headers for the POST, PUT, DELETE and PATCH actions.

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    axios.defaults.headers.post['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.put['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.delete['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.patch['anti-csrf-token'] = csrf_token;

    // Axios does not create an object for TRACE method by default, and has to be created manually.
    axios.defaults.headers.trace = {}
    axios.defaults.headers.trace['anti-csrf-token'] = csrf_token
</script>
```

This code snippet has been tested with Axios version 0.18.0.

#### JQuery

JQuery exposes an API called `$.ajaxSetup()` which can be used to add the `anti-csrf-token` header to the AJAX request. API documentation for `$.ajaxSetup()` can be found here. The function `csrfSafeMethod()` defined below will filter out the safe HTTP methods and only add the header to unsafe HTTP methods.

You can configure jQuery to automatically add the token to all request headers by adopting the following code snippet. This provides a simple and convenient CSRF protection for your AJAX based applications:

```html
<script type="text/javascript">
    var csrf_token = $('meta[name="csrf-token"]').attr('content');

    function csrfSafeMethod(method) {
        // these HTTP methods do not require CSRF protection
        return (/^(GET|HEAD|OPTIONS)$/.test(method));
    }

    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("anti-csrf-token", csrf_token);
            }
        }
    });
</script>
```

This code snippet has been tested with jQuery version 3.3.1.

## References

### CSRF

- [OWASP Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/csrf)
- [Mozilla Web Security Cheat Sheet](https://infosec.mozilla.org/guidelines/web_security#csrf-prevention)
- [Common CSRF Prevention Misconceptions](https://medium.com/keylogged/common-csrf-prevention-misconceptions-67fd026d94a8)
- [Robust Defenses for Cross-Site Request Forgery](https://seclab.stanford.edu/websec/csrf/csrf.pdf)
- For Java: OWASP [CSRF Guard](https://owasp.org/www-project-csrfguard/) or [Spring Security](https://docs.spring.io/spring-security/site/docs/5.5.x-SNAPSHOT/reference/html5/#csrf)
- For PHP and Apache: [CSRFProtector Project](https://owasp.org/www-project-csrfprotector/)
- For AngularJS: [Cross-Site Request Forgery (XSRF) Protection](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection)
