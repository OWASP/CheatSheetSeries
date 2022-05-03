# Pinning Cheat Sheet

## Introduction

The Pinning Cheat Sheet is a technical guide to implementing certificate and public key pinning as discussed at the Virginia chapter's presentation [Securing Wireless Channels in the Mobile Space](https://wiki.owasp.org/images/8/8f/Securing-Wireless-Channels-in-the-Mobile-Space.ppt). This guide is focused on providing clear, simple, actionable guidance for securing the channel in a hostile environment where actors could be malicious and the conference of trust a liability.

## What's the problem

Users, developers, and applications expect end-to-end security on their secure channels, but some secure channels are not meeting the expectation. Specifically, channels built using well known protocols such as VPN, SSL, and TLS can be vulnerable to a number of attacks.

## What Is Pinning

Pinning is the process of associating a host with their *expected* X509 certificate or public key. Once a certificate or public key is known or seen for a host, the certificate or public key is associated or 'pinned' to the host. If more than one certificate or public key is acceptable, then the program holds a *pinset* (taking from [Jon Larimer and Kenny Root Google I/O talk](https://developers.google.com/events/io/sessions/gooio2012/107/)). In this case, the advertised identity must match one of the elements in the pinset.

### When to Add a Pin

A host or service's certificate or public key can be added to an application at development time, or it can be added upon first encountering the certificate or public key. The former - adding at development time - is preferred since *preloading* the certificate or public key *out of band* usually means the attacker cannot taint the pin.

### When Do You Perform Pinning

You should pin anytime you want to be relatively certain of the remote host's identity or when operating in a hostile environment. Since one or both are almost always true, you should probably pin all the time.

### When to Apply Exceptions

If you are working for an organization which practices "egress filtering" as part of a Data Loss Prevention (DLP) strategy, you will likely encounter *Interception Proxies*. I like to refer to these things as **"good" bad actors** (as opposed to **"bad" bad actors**) since both break end-to-end security and we can't tell them apart. In this case, **do not** offer to allow-list the interception proxy since it defeats your security goals. Add the interception proxy's public key to your pinset after being **instructed** to do so by the folks in Risk Acceptance.

### How Do You Pin

The idea is to re-use the exiting protocols and infrastructure, but use them in a hardened manner. For re-use, a program would keep doing the things it used to do when establishing a secure connection.

To harden the channel, the program would take advantage of the `OnConnect` callback offered by a library, framework or platform. In the callback, the program would verify the remote host's identity by validating its certificate or public key. See [some examples](#examples-of-pinning) below.

### What Should Be Pinned

In order to decide what should be pinned you can follow the following steps.

1. Decide if you want to pin the root CA, intermediate CA or leaf certificate:

    - Pinning the **root CA** is generally not recommended since it highly increases the risk because it implies also trusting all its intermediate CAs.
    - Pinning a specific **intermediate CA** reduces the risk but the application will be also trusting any other certificates issues by that CA, not only the ones meant for your application.
    - Pinning a **leaf certificate** is recommended but must include backup (e.g. intermediate CA). It provides 100% certainty that the app exclusively trusts the remote hosts it was designed to connect to.

    For example, the application pins the remote endpoint leaf certificate but includes a backup pin for the intermediate CA. This increases the risk by trusting more certificate authorities but decreases the chances of bricking your app. If there's any issue with the leaf certificate, the app can always fall back to the intermediate CA until you release an app update.

2. Choose if you want to pin the **whole certificate** or just its **public key**.

3. If you chose the public key, you have two additional choices:

- Pin the `subjectPublicKeyInfo`.
- Pin one of the concrete types such as `RSAPublicKey` or `DSAPublicKey`.

**subjectPublicKeyInfo**:

![RandomOrgDERDump](../assets/Pinning_Cheat_Sheet_RandomOrgDERDump.png)

The three choices are explained below in more detail. I would encourage you to pin the `subjectPublicKeyInfo` because it has the public parameters (such as `{e,n}` for an RSA public key) **and** contextual information such as an algorithm and OID. The context will help you keep your bearings at times, and the figure to the right shows the additional information available.

#### Certificate

![Certificate](../assets/Pinning_Cheat_Sheet_Certificate.png)

The certificate is easiest to pin. You can fetch the certificate out of band for the website, have the IT folks email your company certificate to you, use `openssl s_client` to retrieve the certificate etc. At runtime, you retrieve the website or server's certificate in the callback. Within the callback, you compare the retrieved certificate with the certificate embedded within the program. If the comparison fails, then fail the method or function.

**Benefits:**

- It might be easier to implement than the other methods, especially in languages such as Cocoa/CocoaTouch and OpenSSL.

**Downsides:**

- If the site rotates its certificate on a regular basis, then your application would need to be updated regularly. For example, Google rotates its certificates, so you will need to update your application about once a month (if it depended on Google services).

#### Public Key

![PublicKey](../assets/Pinning_Cheat_Sheet_PublicKey.png)

Public key pinning is more flexible but a little trickier due to the extra steps necessary to extract the public key from a certificate. As with a certificate, the program checks the extracted public key with its embedded copy of the public key.

**Benefits:**

- It allows access to public key parameters (such as `{e,n}` for an RSA public key) and contextual information such as an algorithm and OID.
- It's more flexible than certificate pinning. Even if the server rotates its certificates, the underlying public keys (within the certificate) remain static.

**Downsides:**

- It's harder to work with keys (versus certificates) since you must extract the key from the certificate. Extraction is a minor inconvenience in Java and .Net, but it's uncomfortable in Cocoa/CocoaTouch and OpenSSL.
- The key is static and may violate key rotation policies.
- It's not possible to anonymize the public keys.

#### Hash

While the three choices above used DER encoding, its also acceptable to use a hash of the information. In fact, the original sample programs were written using digested certificates and public keys. The samples were changed to allow a programmer to inspect the objects with tools like `dumpasn1` and other ASN.1 decoders.

**Benefits:**

- It's convenient to use. A digested certificate fingerprint is often available as a native API for many libraries.
- Hashing allows you to anonymize a certificate or public key. This might be important if you application is concerned about leaking information during decompilation and re-engineering.
- An organization might want to supply a reserve (or back-up) identity in case the primary identity is compromised. Hashing ensures your adversaries do not see the reserved certificate or public key in advance of its use. In fact, Google's IETF draft *websec-key-pinning* uses the technique.

**Downsides:**

- No access to public key parameters nor contextual information such as an algorithm and OID which might be needed in certain use cases.

## Examples of Pinning

This section discusses certificate and public key pinning in Android Java, iOS, .Net, and OpenSSL. Code has been omitted for brevity, but the key points for the platform are highlighted.

### Android

Since Android N, the preferred way for implementing pinning is by leveraging Android's [Network Security Configuration](https://developer.android.com/training/articles/security-config.html) feature, which lets apps customize their network security settings in a safe, declarative configuration file without modifying app code.

To enable pinning, [the `<pin-set>` configuration setting](https://developer.android.com/training/articles/security-config.html#CertificatePinning) can be used.

If devices running a version of Android that is earlier than N need to be supported, a backport of the Network Security Configuration pinning functionality is available via the [TrustKit Android library](https://github.com/datatheorem/TrustKit-Android).

Alternatively you can use methods such as the pinning from OkHTTP in order to set specific pins programmatically, as explained in the [OWASP Mobile Security Testing Guide (MSTG)](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#network-libraries-and-webviews) and [the OKHttp documentation](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html).

The Android documentation provides an example of how SSL validation can be customized within the app's code (in order to implement pinning) in the [Unknown CA implementation document](https://developer.android.com/training/articles/security-ssl.html#UnknownCa). However, implementing pinning validation from scratch should be avoided, as implementation mistakes are extremely likely and usually lead to severe vulnerabilities.

Lastly, if you want to validate whether the pinning is successful, please follow instructions from the [introduction into testing network communication](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04f-Testing-Network-Communication.md#testing-network-communication) and the [Android specific network testing](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md) chapters of the OWASP Mobile Security Testing Guide (MSTG).

### iOS

Apple suggests pinning a CA public key by specifying it in `Info.plist` file under [App Transport Security Settings](https://developer.apple.com/documentation/security/preventing_insecure_network_connections). More details in the article ["Identity Pinning: How to configure server certificates for your app"](https://developer.apple.com/news/?id=g9ejcf8y).

[TrustKit](https://github.com/datatheorem/TrustKit), an open-source SSL pinning library for iOS and macOS is available. It provides an easy-to-use API for implementing pinning, and has been deployed in many apps.

Otherwise, more details regarding how SSL validation can be customized on iOS (in order to implement pinning) are available in the [HTTPS Server Trust Evaluation](https://developer.apple.com/library/content/technotes/tn2232/_index.html) technical note. However, implementing pinning validation from scratch should be avoided, as implementation mistakes are extremely likely and usually lead to severe vulnerabilities.

Lastly, if you want to validate whether the pinning is successful, please follow instructions from the [introduction into testing network communication](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04f-Testing-Network-Communication.md#testing-network-communication) and the [iOS specific network testing](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06g-Testing-Network-Communication.md) chapters of the OWASP Mobile Security Testing Guide (MSTG).

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

[electron-ssl-pinning](https://github.com/dialogs/electron-ssl-pinning), an open-source SSL pinning library for [Electron](https://electronjs.org) based applications. It provides an easy-to-use API for implementing pinning and also provides tool for fetching configuration based on needed hosts.

Otherwise, you can validate certificates by yourself using [ses.setCertificateVerifyProc(proc)](https://electronjs.org/docs/api/session#sessetcertificateverifyprocproc).

## References

- OWASP [Injection Theory](https://owasp.org/www-community/Injection_Theory)
- OWASP [Data Validation](https://wiki.owasp.org/index.php/Data_Validation)
- OWASP [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md)
- OWASP [Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg)
- IETF [RFC 1421 (PEM Encoding)](http://www.ietf.org/rfc/rfc1421.txt)
- IETF [RFC 4648 (Base16, Base32, and Base64 Encodings)](http://www.ietf.org/rfc/rfc4648.txt)
- IETF [RFC 5280 (Internet X.509, PKIX)](http://www.ietf.org/rfc/rfc5280.txt)
- IETF [RFC 3279 (PKI, X509 Algorithms and CRL Profiles)](http://www.ietf.org/rfc/rfc3279.txt)
- IETF [RFC 4055 (PKI, X509 Additional Algorithms and CRL Profiles)](http://www.ietf.org/rfc/rfc4055.txt)
- IETF [RFC 2246 (TLS 1.0)](http://www.ietf.org/rfc/rfc2246.txt)
- IETF [RFC 4346 (TLS 1.1)](http://www.ietf.org/rfc/rfc4346.txt)
- IETF [RFC 5246 (TLS 1.2)](http://www.ietf.org/rfc/rfc5246.txt)
- IETF [PKCS #1: RSA Cryptography Specifications Version 2.2](https://tools.ietf.org/html/rfc8017)
