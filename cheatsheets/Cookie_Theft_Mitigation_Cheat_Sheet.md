# Cookie Theft Mitigation Cheat Sheet

## Introduction

With the spread of 2FA and Passkey, the login process has become more robust, and even if an attacker steals only the password, it has become difficult to do a spoofing attack.

However, if attacker can steal a valid session cookie instead, it is possible to hijack the user session for the duration of the session lifetime period. In other words, stealing a session cookie has the same impact as stealing authentication credentials until it expires. No matter how robust your authentication process is, it will not be a sufficient countermeasure for Cookie Theft.

Generally, cookie theft is carried out directly against users through malware or phishing attacks. Therefore, the only thing a service can do is to _detect as quickly as possible when a stolen cookie is used_.

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

By storing session information on the server side when a session is established, it is possible to detect session hijacking when that information is significantly changed.

The following are the core information that should be saved.

- IP Address
- User-Agent
- Accept-Language
- Date

In addition, the following headers, which can be change depending on the Device and OS, are also effective as monitoring targets.

- Accept
- Accept-Encoding

Also, recent browsers sends request headers called `Sec-Fetch-*` that provides information about the browsing contexts, so these values can also be used as a reference. It's not sent by every browser, and it's not always sent even if browser supported, so it should not be relied upon.

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

When a session is established on the server, this information is collected and saved in association with the session like below.

```js
const session = SessionStorage.create()
session.save({
  ip: req.clientIP,
  user_agent: req.headers.userAgent,
  date: req.headers.date,
  accept_language: req.headers.acceptLanguage,
  // ...
})
```

If a large change is detected when comparing this information each time a request is received, it is possible that the session has been hijacked.

### Session Validation

If there is a possibility that a session has been hijacked, the most reliable verification method is to re-authenticate. If you temporarily invalidate the user's session, ask them to authenticate again, and then give them a new session cookie, the attacker will no longer be able to do anything with the stolen cookie.

However, as mentioned earlier, monitoring sessions has the potential for false positives, so if you have to re-authenticate too often, it will be a poor experience for the user.

An alternative would be to use a CAPTCHA or similar to make a decision. This is particularly useful when a stolen session cookie is being used by a bot or other malicious program.

As a compromise, if there is a suspicion of session hijacking, it could be good practice to display a CAPTCHA for normal browsing, and to use re-authentication to provide reliable protection before accessing confidential information or performing actions with side effects.

```js
function cookieTheftDetectionMiddleware(req, res) {
  const currentIP = req.clientIP
  const expectedIP = req.session.ip
  if (checkGeoIPRange(currentIP, expected) === false) {
     // Validation
  }
  const currentUA = req.userAgent
  const expectedUA = req.session.ua
  if (checkUserAgent(currentUA, expectedUA)) {
    // Validation
  }

  // ...
}

app.post("/users/delete", cookieTheftDetectionMiddleware, (req, res) => {
 // ...
})
```

Usually, such functions are provided as middleware, or they are provided by WAF (Web Application Firewall) installed in front of the web server.

If this comparison has a significant impact on performance, it may be possible to tune it so that the priority is set for each path and only the endpoints that view or modify important information are checked intensively.

## Device Bound Session Credentials

The fundamental problem that leads to Cookie Theft attack is that the session cookies are accepted without checking who sent them. Servers only check whether the values are valid. Such values are generally referred to as "Bearer Token".

To solve this problem, it is effective to make the Session Cookie itself as "Sender Constrained Token". The Device Bound Session Credentials API was proposed for this purpose.

[Device Bound Session Credentials explainer](https://github.com/WICG/dbsc/blob/main/README.md)

This API combines the Public Key Encryption with the owner verification of Session Cookies. By verifying the owner using the private key generated internally by the browser, even if an attacker succeeded to steal the session cookie, they will not be able to impersonate the user unless they also steal the private key that the browser keeping secret internally.

This specification is still in the drafting stages, but it's considered that it will be possible to solve the Cookie Theft Attack in the future.

## References

- [Catching Compromised Cookies - Engineering at Slack](https://slack.engineering/catching-compromised-cookies/)
- [Device Bound Session Credentials explainer](https://github.com/WICG/dbsc/blob/main/README.md)
