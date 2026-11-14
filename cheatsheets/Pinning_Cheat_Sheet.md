# Pinning Cheat Sheet

## Introduction

The Pinning Cheat Sheet is a technical guide to implementing public key pinning. It provides clear, simple, actionable guidance for securing the communication channel in a hostile environment where actors could be malicious and granting trust is a liability.

**Note:** Pinning of the whole certificate is discouraged. If the site rotates its certificate, then your application would need to be updated. If you do not control when this certificate is put into service, then pinning will lead to an outage. Instead the hash of the public key of the X.509 certificate should be pinned, as this stays the same if the same Certificate Signing Request (CSR) is used.

## What's the problem

For baseline TLS configuration, see the [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md).

Users expect security on their communication channels, but some channels may not meet this expectation. Channels built using well known protocols like TLS can be vulnerable to Machine-in-the-Middle (MITM) attacks if certificate-based trusts are misused. Malicious attacks come in two forms:

1. An attacker is able to obtain a fraudulently issued digital certificate from a trusted certificate authority (CA) in the name of the victim site;
2. The attacker is able to place a CA controlled by the attacker into the client’s trust store.

In the case of the latter issue, an attacker with the access to update a trust store will have the access to change the workings of the mobile application, potentially defeating pinning.

As [Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) makes clear, this problem is very small due to years of security advancements by the certificate authority and browser communities.

## What Is Pinning

Pinning is the process of associating a host with their *expected* X509 public key. Once a public key is known or seen for a host, the public key is associated or 'pinned' to the host. If more than one certificate or public key is acceptable, then the program holds a *pinset* (taken from [Jon Larimer and Kenny Root Google I/O talk](https://www.youtube.com/watch?v=RPJENzweI-A)). In this case, the advertised credential must match one of the elements in the pinset.

**Note:** Implementing pinning also introduces a risk, as the certificate and public key need to be maintained in the mobile app. [Changing to another CA renders apps with pinned certificates unable to connect to the server without receiving a client software update.](https://developer.android.com/privacy-and-security/security-ssl#Pinning)

### When to Add a Pin

A host or service's certificate or public key can be added to an application at development time, it can be added upon first encountering the certificate or public key (an approach commonly known as “Trust On First Use”, or TOFU), or it can be added and updated in real time via an unpinned channel. The former - adding at development time - is preferred since *preloading* the certificate or public key *out-of-band* usually means the attacker cannot taint the pin.

Keep in mind that this "when" is about at what point in time you pin. The first question should be, “Should I Pin?”. The answer to this is probably never.

### When Do You Perform Pinning

There is almost no situation where you should consider pinning. The risk of outages almost always outweighs any security risks given advances in security. If you consider pinning, you should read [Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) and fully understand the threat model.

### When Do You Not Pin?

- If you don’t control the client and server side of the connection, don’t pin.
- If you can’t update the pinset securely, don’t pin.
- If updating the pinset is disruptive, such as requiring application redeployment, probably don’t pin. (A possible exception is when you control the redeployment of the application, such as in forced updates within the confines of a corporation.)
- If the certificate key pair cannot be predicted in advance before it is put into service, don’t pin.
- If it is not a native mobile application, do not pin.

### When to Apply Exceptions

If you are working for an organization which practices "egress filtering" as part of a Data Loss Prevention (DLP) strategy, you will likely encounter *Interception Proxies*. We like to refer to these things as **"good" bad actors** (as opposed to **"bad" bad actors**) since both break end-to-end security and we can't tell them apart. In this case, **do not** offer to allow-list the interception proxy since it defeats your security goals. Add the interception proxy's public key to your pinset after being **instructed** to do so by the folks in Risk Acceptance.

### How Do You Pin

The idea is to reuse the existing protocols and infrastructure, but use them in a hardened manner. For reuse, a program would keep doing the things it used to do when establishing a secure connection.

To harden the channel, the program would take advantage of the `OnConnect` callback offered by a library, framework or platform. In the callback, the program would verify the remote host's identity by validating its certificate or public key. See [some examples](#examples-of-pinning) below.

### What Should Be Pinned

In order to decide what should be pinned you can follow the following steps.

1. Decide if you want to pin the root CA, intermediate CA or leaf certificate:

- Pinning the **root CA** narrows trust from every CA in the device trust store down to one, but the app still trusts every certificate that root and its intermediates ever issue. Use it only as a backup pin, not as the primary pin.
- Pinning a specific **issuing or intermediate CA** reduces the risk further, but the application will still trust any other certificate issued by that CA or its sub-CAs, not only the ones meant for your application. Apple's [Identity Pinning](https://developer.apple.com/news/?id=g9ejcf8y) guidance recommends pinning CA public keys rather than server keys so that the server can rotate its certificate under the same CA without an app update, and pinning more than one key for redundancy.
- Pinning a **leaf certificate** gives the strongest guarantee that the app talks only to the hosts it was designed for, but it must include a backup (e.g. the intermediate CA or a pinset containing alternates) to survive failover and certificate rotation.

**Recommendation:** pin the leaf or issuing CA public key as the primary pin, and add a backup pin for the intermediate or root CA. Never ship a single pin.

For example, the application pins the remote endpoint leaf certificate but includes a backup pin for the intermediate CA. This increases the risk by trusting more certificate authorities but decreases the chances of bricking your app. If there's any issue with the leaf certificate, the app can always fall back to the intermediate CA until you release an app update.

To pin the public key, pin the SHA-256 hash of the `SubjectPublicKeyInfo`. This is the format expected by [Android's Network Security Configuration](https://developer.android.com/privacy-and-security/security-config#CertificatePinning), [Apple's `NSPinnedDomains`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains), and third-party networking libraries, and it matches the pin format defined in [RFC 7469](https://datatracker.ietf.org/doc/html/rfc7469).

## Examples of Pinning

This section discusses public key pinning in Android Java, iOS, .Net, and OpenSSL. Code has been omitted for brevity, but the key points for the platform are highlighted.

Implementing pinning validation from scratch should be avoided, as implementation mistakes are extremely likely and usually lead to severe vulnerabilities.

### Android

Since Android N, the preferred way for implementing pinning is by leveraging Android's [Network Security Configuration](https://developer.android.com/training/articles/security-config.html) feature, which lets apps customize their network security settings in a safe, declarative configuration file without modifying app code.

To enable pinning, [the `<pin-set>` configuration setting](https://developer.android.com/training/articles/security-config.html#CertificatePinning) can be used.

Alternatively you can use several methods to set specific pins programmatically, as explained in the [OWASP MAS - MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/).

The Android documentation provides information of how you can trust additional CAs that aren't trusted by the system SSL validation in the [Unknown Certificate Authority](https://developer.android.com/training/articles/security-ssl.html#UnknownCa) section, by using the Network Security Configuration.

Lastly, if you want to validate whether the pinning is successful, please follow the technique [MASTG-TECH-0012: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/) and the [OWASP MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) that summarizes all information including the test cases for Android.

### iOS

Apple supports declarative pinning through `NSPinnedDomains` in the [App Transport Security (ATS)](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) settings of `Info.plist`. Apple advises against pinning unless you have a specific regulatory or threat-model reason, and recommends pinning CA public keys with backups rather than a single leaf key. See the article ["Identity Pinning: How to configure server certificates for your app"](https://developer.apple.com/news/?id=g9ejcf8y).

Use ATS pinning through `NSPinnedDomains` as the only pinning mechanism on iOS. Do not write custom server trust evaluation in a `URLSessionDelegate`; it is error-prone and offers no additional protection over a correctly configured `NSPinnedDomains` entry.

Lastly, if you want to validate whether the pinning is successful, please follow the technique [MASTG-TECH-0064: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/) and the [OWASP MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) that summarizes all information including the test cases for iOS.

### .Net

.Net pinning can be achieved by using [`ServicePointManager`](https://docs.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager?view=netframework-4.7.2). An example can be found at the [OWASP MSTG](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#xamarin-applications).

Download the [.Net sample program](../assets/Pinning_Cheat_Sheet_Certificate_DotNetSample.zip).

### OpenSSL

Pinning can occur at one of two places with OpenSSL. First is the user supplied `verify_callback`. Second is after the connection is established via `SSL_get_peer_certificate`. Either method will allow you to access the peer's certificate.

Though OpenSSL performs the X509 checks, you must fail the connection and tear down the socket on error. By design, a server that does not supply a certificate will result in `X509_V_OK` with a **NULL** certificate. To check the result of the customary verification:

1. You must call `SSL_get_verify_result` and verify the return code is `X509_V_OK`;
2. You must call `SSL_get_peer_certificate` and verify the certificate is **non-NULL**.

Download: [OpenSSL sample program](../assets/Pinning_Cheat_Sheet_Certificate_OpenSSLSample.zip).

### Electron

[electron-ssl-pinning](https://github.com/dialogs/electron-ssl-pinning), an open-source SSL pinning library for [Electron](https://electronjs.org) based applications. It provides an easy-to-use API for implementing pinning and also provides a tool for fetching configuration based on needed hosts.

Otherwise, you can validate certificates by yourself using [ses.setCertificateVerifyProc(proc)](https://electronjs.org/docs/api/session#sessetcertificateverifyprocproc).

## References

- [Android: Network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
