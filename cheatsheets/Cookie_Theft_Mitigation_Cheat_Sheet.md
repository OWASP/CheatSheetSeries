# Cookie Theft Mitigation Cheat Sheet

## Introduction

With the spread of 2FA and Passkey, the login process has become more robust, and even if an attacker steals only the password, it has become difficult to do a spoofing attack.

However, if attacker can steal a valid session cookie instead, it is possible to hijack the user session for the duration of the session lifetime period. In other words, stealing a session cookie has the same impact as stealing authentication credentials until it expires. No matter how robust your authentication process is, it will not be a sufficient countermeasure for Cookie Theft.

Cookie theft can occur through malware, phishing, or application vulnerabilities. Apply the preventive controls in the [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md), and monitor for misuse of stolen cookies. Detection complements these controls; it does not replace them.

## Cookie Theft Mitigation

Session Cookies are given to users when they log in. If these are stolen by an attacker and used to hijack the session from the attacker's device, certain environment information used in the connection for session will change.

For example, if stolen cookies are used by an attacker from another country, you can detect this by detecting a significant change in the IP address.

In this way, there are multiple vectors that can be used to detect that the user environments has changed.

- Access from different region (IP Address)
- Access from different device (User-Agent)
- Access from different language setting (Accept-Language)
- Access at different time of day (Date)

If you save this information when establishing a session and compare it in each request, you can detect if the user environment has changed.

Of course, it is difficult to make a judgment based on simple comparison alone. For example, if the user changes the Wi-Fi network they are connected to, their IP address will change. If the user updates their browser, User-Agent will change. So it is necessary not only to compare the values, but also to check whether the meaning of the values has not changed significantly.

### False negatives/positives

Suppose that a session cookie that has been granted access in a certain country is used from another country. This could be an attack, or it could simply be that the user has traveled.

In other words, it is not possible to say with certainty that it is an attack just because the IP-Geo has changed. This means that there are **False Positives** (it seems to be an attack, but it is not) in this detection method.

At the same time, even if the IP-Geo does not change, there is also the possibility that the attacker is attacking from within the same country. This means that this detection method has **False Negatives** (it seems not to be an attack, but it is).

### Cookie Theft Detection

For an implementation case study, see [Slack's compromised-cookie detection design](https://slack.engineering/catching-compromised-cookies/).

By storing session information on the server side when a session is established, it is possible to detect session hijacking when that information is significantly changed.

The following are the core information that should be saved.

- IP Address
- User-Agent
- Accept-Language
- Date

In addition, the following headers, which can be change depending on the Device and OS, are also effective as monitoring targets.

- Accept
- Accept-Encoding

The following [`Sec-CH-*` Client Hint headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Client_hints#hint_types) provide information about the browser, device, or user preferences. These differ from [`Sec-Fetch-*` Fetch Metadata headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site), which describe request context. Client Hints may be omitted depending on browser support, server requests, and client permissions, so treat them as optional signals.

- sec-ch-prefers-color-scheme
- sec-ch-ua
- sec-ch-ua-arch
- sec-ch-ua-bitness
- sec-ch-ua-form-factors
- sec-ch-ua-full-version
- sec-ch-ua-full-version-list
- sec-ch-ua-mobile
- sec-ch-ua-model
- sec-ch-ua-platform
- sec-ch-ua-platform-version
- sec-ch-ua-wow64

The following illustrative Express sketch assumes a server-side session store and trusted middleware that populates `req.clientIP` and `req.session`. Read request headers with [Express's `req.get()`](https://expressjs.com/en/5x/api/request/#reqget), and use a server timestamp when establishing the session:

```js
const session = SessionStorage.create()
session.save({
  ip: req.clientIP,
  user_agent: req.get("User-Agent"),
  date: Date.now(),
  accept_language: req.get("Accept-Language"),
  // ...
})
```

If a large change is detected when comparing this information each time a request is received, it is possible that the session has been hijacked.

### Session Validation

If there is a possibility that a session has been hijacked, the most reliable verification method is to re-authenticate. If you temporarily invalidate the user's session, ask them to authenticate again, and then give them a new session cookie, the attacker will no longer be able to do anything with the stolen cookie.

However, as mentioned earlier, monitoring sessions has the potential for false positives, so if you have to re-authenticate too often, it will be a poor experience for the user.

A CAPTCHA may help limit automated abuse, but it does not establish that the requester controls an authenticator bound to the account, which is the basis of [authentication](https://pages.nist.gov/800-63-4/sp800-63b/introduction/). Do not treat a solved CAPTCHA as validation of a suspected stolen session. Use [reauthentication with an account-bound authenticator](Authentication_Cheat_Sheet.md#re-authentication-after-risk-events) before restoring access that depends on trusting the session.

In this sketch, comparison helpers return `false` when a signal requires reauthentication. They must account for missing headers and legitimate changes. [Express middleware must end the response or call `next()`](https://expressjs.com/en/guide/using-middleware/). The error response below blocks this request; the application must also restrict or invalidate the suspect session and complete account-bound reauthentication before restoring access. This sketch does not implement session storage, authorization, or CSRF protection.

```js
function cookieTheftDetectionMiddleware(req, res, next) {
  const currentIP = req.clientIP
  const expectedIP = req.session.ip
  if (checkGeoIPRange(currentIP, expectedIP) === false) {
    return res.status(403).send("Reauthentication required")
  }
  const currentUA = req.get("User-Agent")
  const expectedUA = req.session.user_agent
  if (checkUserAgent(currentUA, expectedUA) === false) {
    return res.status(403).send("Reauthentication required")
  }

  next()
}

app.post("/users/delete", cookieTheftDetectionMiddleware, (req, res) => {
 // ...
})
```

Usually, such functions are provided as middleware, or they are provided by WAF (Web Application Firewall) installed in front of the web server.

If this comparison has a significant impact on performance, it may be possible to tune it so that the priority is set for each path and only the endpoints that view or modify important information are checked intensively.

## Device Bound Session Credentials

Ordinary session cookies are bearer credentials: anyone possessing a valid cookie can use it until it expires or the server invalidates it.

Device Bound Session Credentials (DBSC) uses a device-bound signing key to prove possession when refreshing short-lived cookies, as described in the [DBSC refresh design](https://github.com/w3c/webappsec-dbsc/blob/main/README.md#browser-initiated-refreshes). Ordinary application requests still use those cookies as bearer credentials; DBSC does not bind every request to the key.

An attacker can replay a stolen cookie during its remaining lifetime. Protecting the key limits the attacker's ability to refresh the session from another device; it does not make a stolen cookie immediately unusable.

DBSC also does not prevent abuse while an attacker retains access to the compromised browser or device. Such an attacker may obtain fresh cookies or use the protected key through the compromised environment. Account for these [documented threat-model limits](https://github.com/w3c/webappsec-dbsc/blob/main/README.md#non-goals) when choosing session lifetimes and incident-response controls.

## References

- [NIST SP 800-63B-4: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Device Bound Session Credentials explainer](https://github.com/w3c/webappsec-dbsc/blob/main/README.md)
