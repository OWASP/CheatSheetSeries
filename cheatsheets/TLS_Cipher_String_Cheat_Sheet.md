# TLS Cipher String Cheat Sheet

## Introduction

This article is focused on providing clear and simple examples for the cipher string. They are based on different scenarios where you use the Transport Layer Security (TLS) protocol.

## Recommendations for a cipher string

### Scenarios

The cipher strings are based on the recommendation to setup your policy to get a whitelist for your ciphers as described in the *[Transport Layer Protection Cheat Sheet (Rule - Only Support Strong Cryptographic Ciphers)](Transport_Layer_Protection_Cheat_Sheet.md)*. The latest and strongest ciphers are solely available with TLSv1.2, older protocols don't support them. Please find enclosed all supported protocols by the scenario.

We have not included any `ChaCha20-Poly1305` ciphers, yet. One reason is that we haven't found various assessments yet, the other is that implementations of new ciphers may be more buggy.

Finally we have compiled the oldest versions of different client agents that are still compatible with a cipher string. We provide this information according to the ciphers and protocols supported by browsers, libraries, bots on the basis of *[ssllabs's list of user agent capabilities](https://www.ssllabs.com/ssltest/clients.html)* and tests on our own.

We have checked this thoroughly, but please accept that all data is provided without any warranty of any kind. The list of the oldest supported clients assumes that the server supports all ciphers by the scenario (Please contact the authors if you find any errors or if you can provide additional data).

The recommended cipher strings are based on different scenarios:

**OWASP Cipher String 'A'** (Advanced, wide browser compatibility, e.g. to most newer browser versions):

- Recommended if you control the server and the clients. Make sure to check the compatibility before using it.
- Includes solely the strongest [Perfect Forward Secrecy (PFS)](https://scotthelme.co.uk/perfect-forward-secrecy/) ciphers.
- Protocols: `TLSv1.3`, `TLSv1.2` (and newer or better).
- Oldest known clients that are compatible: Android 4.4.2, BingPreview Jan 2015, Chrome 32/Win 7, Chrome 34/OS X, Edge 12/Win 10, Firefox 27/Win 8, Googlebot Feb 2015, IE11/Win 7 + MS14-066, Java8b132, OpenSSL 1.0.1e, Safari 9/iOS 9, Yahoo Slurp Jun 2014, YandexBot Sep 2014.

**OWASP Cipher String 'B'** (Broad compatibility to browsers, check the compatibility to other protocols before using it, e.g. IMAPS):

- Recommended if you solely control the server, the clients use their browsers and if you check the compatibility before using it for other protocols than https.
- Includes solely the strongest and stronger [PFS](https://scotthelme.co.uk/perfect-forward-secrecy/) ciphers.
- Protocols: `TLSv1.2` (and newer or better).
- Oldest known clients that are compatible: Android 4.4.2, BingPreview Jan 2015, Chrome 30/Win 7, Chrome 34/OS X, Edge 12/Win 10, Firefox 27/Win 8, Googlebot Feb 2015, IE11/Win 7, IE 11/WinPhone 8.1, Java8b132, OpenSSL 1.0.1e, Opera 17/Win 7, Safari 5/iOS 5.1.1, Safari 7/OS X 10.9, Yahoo Slurp Jun 2014, YandexBot Sep 2014

**OWASP Cipher String 'C'** (Widest Compatibility, compatibility to most legacy browsers, legacy libraries (still patched) and other application protocols besides https, e.g. IMAPS):

- You may use this if you solely control the server, your clients use elder browsers and other elder libraries or if you use other protocols than https.
- Includes solely [PFS](https://scotthelme.co.uk/perfect-forward-secrecy/) ciphers.
- Be aware of additional risks and of new vulnerabilities that may appear are more likely than above.
- Plan to phase out SHA-1 and TLSv1, TLSv1.1 for https in middle-term.
- Protocols: `TLSv1.3`, `TLSv1.2`, `TLSv1.1`, `TLSv1` (and newer or better).
- Oldest known clients that are compatible: Android 2.3.7/4.0.4, Baidu Jan 2015, BingPreview Dec 2013, Chrome 27/Win 7, Chrome 34/OS X, Edge 12/Win 10, Firefox 10.0.12 ESR/Win 7, Firefox 21/Win 7+Fedora 19, Googlebot Oct 2013, IE 7/Vista, IE 10/WinPhone 8.0, Java 7u25, OpenSSL 0.9.8y, Opera 12.15/Win 7, Safari 5/iOS 5.1.1, Safari 5.1.9/OS X 10.6.8, Yahoo Slurp Oct 2013, YandexBot May 2014

**OWASP Cipher String 'D'** (Legacy, widest compatibility to real old browsers and legacy libraries and other application protocols like SMTP):

- Take care, use this cipher string only if you are forced to support non [PFS](https://scotthelme.co.uk/perfect-forward-secrecy/) for real old clients with very old libraries or for other protocols besides https.
- Be aware of the existing risks (e.g. ciphers without PFS, ciphers with 3DES) and of new vulnerabilities that may appear the most likely.
- **Do not use** WEAK ciphers based on `3DES` e.g. (`TLS_RSA_WITH_3DES_EDE_CBC_SHA`, `DES-CBC3-SHA`)
- **Never use** even more INSECURE or elder ciphers based on `RC2`, `RC4`, `DES`, `MD4`, `MD5`, `EXP`, `EXP1024`, `AH`, `ADH`, `aNULL`, `eNULL`, `SEED` nor `IDEA`.
- [PFS](https://scotthelme.co.uk/perfect-forward-secrecy/) ciphers are preferred, except all [DHE](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) ciphers that use SHA-1 (to prevent possible incompatibility issues caused by the length of the [DHparameter](https://wiki.openssl.org/index.php/Diffie-Hellman_parameters)).
- Plan to move to 'A' for https or at least 'B' otherwise in middle-term.
- Protocols: `TLSv1.3`, `TLSv1.2`, `TLSv1.1`, `TLSv1` (and newer or better).

### Table of the ciphers (and their priority from high (1) to low (e.g. 18))

IANA, OpenSSL and other crypto libraries use slightly different names for the same ciphers.

This table lists the names used by IANA and by openssl in brackets `[]`. Additional you can find the unambiguously hex values defined by IANA. Mozilla offers a larger *[cipher names correspondence table](https://wiki.mozilla.org/Security/Server_Side_TLS#Cipher_names_correspondence_table)*.

<!-- markdownlint-disable MD033 -->
| Cipher name:<br>IANA, [OpenSSL] | Cipher HEX value | Advanced<br>(A) | Broad Compatibility<br>(B) | Widest Compatibility<br>(C) | Legacy<br>(D) |
| --- | :---: | :---: | :---: | :---: | :---: |
| `TLS_AES_256_GCM_SHA384` *(TLSv1.3)*,<br>[`TLS_AES_256_GCM_SHA384`] | 0x1302 | 1 | 1 | 1 | 1 |
| `TLS_CHACHA20_POLY1305_SHA256` *(TLSv1.3)*,<br>[`TLS_CHACHA20_POLY1305_SHA256`] | 0x1303 | 2 | 2 | 2 | 2 |
| `TLS_AES_128_GCM_SHA256` *(TLSv1.3)*,<br>[`TLS_AES_128_GCM_SHA256`] | 0x1301 | 3 | 3 | 3 | 3 |
| `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`,<br>[`DHE-RSA-AES256-GCM-SHA384`] | 0x009f | 4 | 4 | 4 | 4 |
| `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`,<br>[`DHE-RSA-AES128-GCM-SHA256`] | 0x009e | 5 | 5 | 5 | 5 |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,<br>[`ECDHE-RSA-AES256-GCM-SHA384`] | 0xc030 | 6 | 6 | 6 | 6 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,<br>[`ECDHE-RSA-AES128-GCM-SHA256`] | 0xc02f | 7 | 7 | 7 | 7 |
| `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`,<br>[`DHE-RSA-AES256-SHA256`] | 0x006b |  | 8 | 8 | 8 |
| `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256`,<br>[`DHE-RSA-AES128-SHA256`] | 0x0067 |  | 9 | 9 | 9 |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`,<br>[`ECDHE-RSA-AES256-SHA384`] | 0xc028 |  | 10 | 10 | 10 |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`,<br>[`ECDHE-RSA-AES128-SHA256`] | 0xc027 |  | 11 | 11 | 11 |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`,<br>[`ECDHE-RSA-AES256-SHA`] | 0xc014 |  |  | 12 | 12 |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`,<br>[`ECDHE-RSA-AES128-SHA`] | 0xc013 |  |  | 13 | 13 |
| `TLS_RSA_WITH_AES_256_GCM_SHA384`,<br>[`AES256-GCM-SHA384`] | 0x009d |  |  |  | 14 |
| `TLS_RSA_WITH_AES_128_GCM_SHA256`,<br>[`AES128-GCM-SHA256`] | 0x009c |  |  |  | 15 |
| `TLS_RSA_WITH_AES_256_CBC_SHA256`,<br>[`AES256-SHA256`] | 0x003d |  |  |  | 16 |
| `TLS_RSA_WITH_AES_128_CBC_SHA256`,<br>[`AES128-SHA256`] | 0x003c |  |  |  | 17 |
| `TLS_RSA_WITH_AES_256_CBC_SHA`,<br>[`AES256-SHA`] | 0x0035 |  |  |  | 18 |
| `TLS_RSA_WITH_AES_128_CBC_SHA`,<br>[`AES128-SHA`] | 0x002f |  |  |  | 19 |
| `TLS_DHE_RSA_WITH_AES_256_CBC_SHA`,<br>[`DHE-RSA-AES256-SHA`] | 0x0039 |  |  | 14 | 20 |
| `TLS_DHE_RSA_WITH_AES_128_CBC_SHA`,<br>[`DHE-RSA-AES128-SHA`] | 0x0033 |  |  | 15 | 21 |
<!-- markdownlint-enable MD033 -->

**Remarks:**

Elder versions of Internet-Explorer and Java do **NOT** support Diffie-Hellman parameters superior to 1024 bit. So the ciphers `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` and `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` were moved to the end to prevent possible incompatibility issues.

Other option: *Delete this two ciphers from your list*.

### Examples for cipher strings

#### OpenSSL

<!-- markdownlint-disable MD033 -->
| Cipher-String | OpenSSL syntax |
| --- | --- |
| Advanced<br>(A) | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256` |
| Broad Compatibility<br>(B) | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256` |
| Widest Compatibility<br>(C) | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA` |
| Legacy<br>(D) | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA` |
<!-- markdownlint-enable MD033 -->

## How to use this Cipher Strings

Inform yourself how to securely configure the settings for the services or hardware that you do use, e.g. *[BetterCrypto.org: Applied Crypto Hardening (DRAFT)](https://bettercrypto.org)*, *[Mozilla: Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)*.

We recommend to use one of the cipher strings described above.

## Example configs

### Apache

**Cipher String 'B':**

```text
SSLProtocol +TLSv1.2                  # for Cipher-String 'A', 'B'
##SSLProtocol +TLSv1.2 +TLSv1.1 +TLSv1 # for Cipher-String 'C', 'D'
SSLCompression off
SSLHonorCipherOrder on
SSLCipherSuite 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256'
##add optionally ':!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!ECDSA:!ADH:!IDEA:!3DES'
```

**Remarks:**

- The cipher string is compiled as a whitelist of individual ciphers to get a better compatibility even with old versions of OpenSSL.
- Monitor the performance of your server, e.g. the TLS handshake with DHE hinders the CPU about 2.4 times more than ECDHE, cf. *[Vincent Bernat, 2011](http://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy.html#some-benchmarks)*, *[nmav's Blog, 2011](https://nikmav.blogspot.com/2011/12/price-to-pay-for-perfect-forward.html)*.
- Verify your cipher string using your crypto library, e.g. openssl using cipher string 'B':

```text
openssl ciphers -V "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256"
##add optionally ':!aNULL:!eNULL:!LOW:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!ECDSA:!ADH:!IDEA' to protect
##older Versions of OpenSSL
##use openssl ciphers -v "..." for openssl < 1.0.1:

0x00,0x9F - DHE-RSA-AES256-GCM-SHA384   TLSv1.2 Kx=DH     Au=RSA  Enc=AESGCM(256) Mac=AEAD
0x00,0x9E - DHE-RSA-AES128-GCM-SHA256   TLSv1.2 Kx=DH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
0xC0,0x30 - ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH   Au=RSA  Enc=AESGCM(256) Mac=AEAD
0xC0,0x2F - ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH   Au=RSA  Enc=AESGCM(128) Mac=AEAD
0x00,0x6B - DHE-RSA-AES256-SHA256       TLSv1.2 Kx=DH     Au=RSA  Enc=AES(256)    Mac=SHA256
0x00,0x67 - DHE-RSA-AES128-SHA256       TLSv1.2 Kx=DH     Au=RSA  Enc=AES(128)    Mac=SHA256
0xC0,0x28 - ECDHE-RSA-AES256-SHA384     TLSv1.2 Kx=ECDH   Au=RSA  Enc=AES(256)    Mac=SHA384
0xC0,0x27 - ECDHE-RSA-AES128-SHA256     TLSv1.2 Kx=ECDH   Au=RSA  Enc=AES(128)    Mac=SHA256
```

**CAUTION:** You must **not** use legacy versions of OpenSSL if you use this cipher string! We strongly recommend to verify if it works!

## Related Articles

- [OWASP: Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md).
- [BetterCrypto.org: Applied Crypto Hardening (DRAFT)](https://bettercrypto.org).
- [Mozilla: Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS).
