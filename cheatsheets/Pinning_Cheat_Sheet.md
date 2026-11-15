# Pinning Cheat Sheet

## Introduction

The Pinning Cheat Sheet is a technical guide to implementing public key pinning. It provides clear, simple, actionable guidance for securing the communication channel in a hostile environment where actors could be malicious and granting trust is a liability.

**Note:** Pin the hash of the certificate's public key, not the whole certificate. A certificate changes on every renewal, so a certificate pin forces a client or app update each time. A public key pin survives renewals as long as the server keeps the same key pair, and a pin on the issuing CA's public key survives even leaf key changes. See [What Should Be Pinned](#what-should-be-pinned) for how to choose.

## What's the problem

For baseline TLS configuration, see the [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md).

Users expect security on their communication channels, but some channels may not meet this expectation. Channels built using well known protocols like TLS can be vulnerable to Machine-in-the-Middle (MITM) attacks if certificate-based trusts are misused. Malicious attacks come in two forms:

1. An attacker is able to obtain a fraudulently issued or forged digital certificate that chains to a trusted certificate authority (CA) in the name of the victim site;
2. The attacker is able to place a CA controlled by the attacker into the client’s trust store.

In the case of the latter issue, an attacker with the access to update a trust store will have the access to change the workings of the mobile application, potentially defeating pinning.

The certificate authority and browser communities have significantly reduced this risk over the years through [Certificate Transparency, CAA records, and the CA/Browser Forum baseline requirements](https://community.owasp.org/controls/Certificate_and_Public_Key_Pinning). A fraudulently issued or forged certificate is therefore unlikely, but when such an attack happens, every TLS connection to the victim site can be intercepted. Pinning protects against this residual risk for the hosts your application pins.

## What Is Pinning

Pinning is the process of associating a host with its *expected* X.509 public key. Once a public key is known or seen for a host, the public key is associated or 'pinned' to the host. If more than one public key is acceptable, the set of acceptable keys is called a *pinset*, and the server's public key must match one of them.

**Note:** Pinning also introduces a risk, because the pinned public keys must be maintained in the app. [Changing to another CA renders apps with pinned certificates unable to connect to the server without receiving a client software update.](https://developer.android.com/privacy-and-security/security-ssl#Pinning) A pin mismatch is a denial of service against your own user base. Pinning therefore requires mature key management and a release process that can ship a new pinset before the old one stops working. If there is no significant threat that pinning addresses, you are adding an availability risk without a security benefit.

### When to Add a Pin

Ship the pins with the application at development time. Both Android's Network Security Configuration and iOS App Transport Security work this way, and *preloading* the public key *out-of-band* means an attacker on the network cannot taint the pin.

Two alternatives exist but are discouraged: Trust On First Use (TOFU), which pins whatever key is seen on the first connection and therefore offers no protection if that connection is already intercepted, and updating pins at runtime over an unpinned channel, which reintroduces the attack that pinning is meant to prevent. Both also require custom validation code instead of the platform mechanisms recommended below.

### When Do You Not Pin?

- If you do not control both the client and the server side of the connection, do not pin.
- If you cannot update the pinset securely, do not pin. For mobile apps the secure path is an app store release.
- If you cannot ship an update to your users before the current pins stop working, do not pin. Backup pins buy you time, but they do not remove the need for a working release process.
- If you cannot know the public keys in advance, both the leaf key and the issuing CA key, before they are put into service, do not pin.
- Do not pin in web applications. Browsers have removed HTTP Public Key Pinning, so there is no supported mechanism. Pinning is for native clients that you build and update yourself.

### When to Apply Exceptions

If you are working for an organization which practices "egress filtering" as part of a Data Loss Prevention (DLP) strategy, you will likely encounter *Interception Proxies*. We like to refer to these things as **"good" bad actors** (as opposed to **"bad" bad actors**) since both break end-to-end security and we can't tell them apart. In this case, **do not** offer to allow-list the interception proxy since it defeats your security goals. Add the interception proxy's public key to your pinset after being **instructed** to do so by the folks in Risk Acceptance.

### How Do You Pin

Declare the pinset in the platform's network security configuration rather than in application code. On Android this is the Network Security Configuration file, on iOS the App Transport Security settings in `Info.plist`. For traffic that goes through the platform's standard networking stack, the system then checks the server's certificate chain against the pinset on every handshake and fails the connection on a mismatch, with no callback or custom trust code in the app. Traffic that bypasses that stack, such as lower-level networking APIs or a bundled third-party TLS library, is not covered and needs explicit validation code. See the [examples](#examples-of-pinning) below.

### What Should Be Pinned

Decide whether to pin the root CA, an intermediate CA, or the leaf public key.

- Pinning the **root CA** narrows trust from every CA in the device trust store down to one and is the most rotation-tolerant option, because the root key outlives every intermediate and leaf. The cost is that the app still trusts every certificate that root and its intermediates ever issue. For a private CA that you operate, this is usually the right pin.
- Pinning a specific **issuing or intermediate CA** narrows trust further, but the application still trusts any other certificate issued by that CA or its sub-CAs, not only the ones meant for your application. Apple's [Identity Pinning](https://developer.apple.com/news/?id=g9ejcf8y) guidance recommends pinning CA public keys, in an intermediate or root certificate, rather than server keys so that the server can rotate its certificate under the same CA without an app update, and pinning more than one key for redundancy.
- Pinning a **leaf public key** gives the strongest guarantee that the app talks only to the hosts it was designed for, but it breaks on every renewal that changes the key pair. Treat it as breakage-on-renewal unless you control key rotation, and always pair it with a backup CA pin.

Check your CA's published chain policy before relying on an intermediate pin. Public CAs rotate intermediates, and [Let's Encrypt](https://letsencrypt.org/certificates/) states that it may start issuing from its backup intermediates at any time without warning, so include every active and backup intermediate in the pinset or pin the root instead.

**Recommendation:** pin a CA public key, intermediate or root, as the primary identity, with at least one backup CA pin. CA pins survive certificate renewal, which is why Apple recommends them; the cost is that you still trust everything that CA issues. Add a leaf pin only when you control key rotation and need to narrow trust further. Never ship a single pin.

With at least two CA pins, the app keeps working when one intermediate is retired or a leaf key changes, until you ship an update with the new pin. The backup widens trust slightly, which is the price of not bricking your app.

To pin the public key, pin the SHA-256 hash of the `SubjectPublicKeyInfo`. This is the format expected by [Android's Network Security Configuration](https://developer.android.com/privacy-and-security/security-config#CertificatePinning), [Apple's `NSPinnedDomains`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains), and third-party networking libraries, and it matches the pin format defined in [RFC 7469](https://datatracker.ietf.org/doc/html/rfc7469).

## Examples of Pinning

This section covers public key pinning on Android, iOS, .NET, OpenSSL, and Electron. Code is omitted for brevity; the key points for each platform are highlighted.

Implementing pinning validation from scratch should be avoided, as implementation mistakes are extremely likely and usually lead to severe vulnerabilities. Android and iOS provide declarative mechanisms, so no validation code is needed for traffic through their standard networking stacks. Everything else requires a small amount of code; keep it minimal and let the platform's default chain validation run first.

### Android

Since Android 7.0 (API level 24), the preferred way to implement pinning is the [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config), a declarative XML file that applies to all framework-managed traffic without app code.

Declare the pins in a [`<pin-set>` element](https://developer.android.com/privacy-and-security/security-config#CertificatePinning). Android's guidance is to [include multiple backup pins, at least one key fully under your control, and a sufficiently short expiration period](https://developer.android.com/privacy-and-security/security-ssl#Pinning). After the `expiration` date, pins are no longer enforced, which keeps apps that were never updated working but also removes the protection, so treat that date as a release deadline.

Programmatic alternatives such as a custom `TrustManager` or OkHttp's `CertificatePinner` are described in [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/). Prefer the Network Security Configuration which the MASTG names it the preferred and recommended approach.

To verify that pinning is enforced, attempt to bypass it as described in [MASTG-TECH-0012: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/). [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) lists the related test cases for Android.

### iOS

On iOS 14 and later, declare pins with [`NSPinnedDomains`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains) in the [App Transport Security (ATS)](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) settings of `Info.plist`. Each domain takes `NSPinnedCAIdentities`, `NSPinnedLeafIdentities`, or both, each holding SPKI SHA-256 hashes; if you specify both, ATS requires a match in each category. Apple advises against pinning unless you have a specific regulatory or threat-model reason, and recommends pinning CA public keys with backups rather than a single leaf key. See the article ["Identity Pinning: How to configure server certificates for your app"](https://developer.apple.com/news/?id=g9ejcf8y).

Prefer ATS pinning for all connections made through the URL Loading System (`URLSession` and `WKWebView`): it is declarative, auditable, and enforced by the system. Do not add custom server trust evaluation in a `URLSessionDelegate` on top of it; it is error-prone and offers no additional protection over a correctly configured `NSPinnedDomains` entry. Two limitations apply. `NSPinnedDomains` has no expiration date, so rotation must be managed by app updates, and [ATS pinning applies only to the URL Loading System](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/); it does not cover the Network framework, `CFNetwork`, BSD sockets, bundled third-party TLS libraries, or SDKs that cannot edit the host app's `Info.plist`. For those cases use a maintained library such as [TrustKit](https://github.com/datatheorem/TrustKit) rather than hand-rolled `SecTrust` evaluation, and confine the custom validation to the code that needs it.

To verify that pinning is enforced, attempt to bypass it as described in [MASTG-TECH-0064: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/). [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) lists the related test cases for iOS.

### .NET

.NET has no declarative pinning mechanism. [`ServicePointManager`](https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager) is obsolete and its settings no longer affect `HttpClient` or `SslStream`, so do not use it. Instead, set [`HttpClientHandler.ServerCertificateCustomValidationCallback`](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.servercertificatecustomvalidationcallback). In the callback, accept the connection only when the default validation reported no policy errors **and** the SPKI hash of a certificate in the presented chain matches your pinset. Never use the callback to suppress policy errors.

### OpenSSL

OpenSSL has no declarative pinning mechanism. Pin either in the user-supplied `verify_callback` or after the handshake by retrieving the peer certificate with [`SSL_get1_peer_certificate`](https://docs.openssl.org/master/man3/SSL_get_peer_certificate/). `SSL_get_peer_certificate` is deprecated. In both cases, extract the `SubjectPublicKeyInfo`, hash it, and compare it against the pinset.

OpenSSL performs the X.509 chain checks, but you must fail the connection and tear down the socket on error. A server that presents no certificate can still produce `X509_V_OK`, and [`SSL_get_verify_result`](https://docs.openssl.org/master/man3/SSL_get_verify_result/) alone does not establish that the peer was authenticated. After the handshake:

1. Call `SSL_get_verify_result` and verify the return code is `X509_V_OK`;
2. Call `SSL_get1_peer_certificate` and verify the certificate is **non-NULL** before comparing its public key against the pinset.

### Electron

Electron has no declarative pinning mechanism. Validate server certificates with [`ses.setCertificateVerifyProc(proc)`](https://www.electronjs.org/docs/latest/api/session#sessetcertificateverifyprocproc), which Electron calls for every server certificate verification in that session. In the callback, accept the certificate only when Chromium's own verification succeeded **and** the SPKI hash of the presented certificate matches your pinset; reject it with `callback(-2)` otherwise.

## References

- [Android: Network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [Apple: NSPinnedDomains (App Transport Security)](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains)
- [OWASP MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/)
