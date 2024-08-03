# Transport Layer Security Cheat Sheet

## Introduction

This cheat sheet provides guidance on implementing transport layer protection for applications using Transport Layer Security (TLS). It primarily focuses on how to use TLS to protect clients connecting to a web application over HTTPS, though much of this guidance is also applicable to other uses of TLS. When correctly implemented, TLS can provide several security benefits:

- **Confidentiality**: Provides protection against attackers reading the contents of the traffic.
- **Integrity**: Provides protection against traffic modification, such as an attacker replaying requests against the server.
- **[Authentication](Authentication_Cheat_Sheet.md)**: Enables the client to confirm they are connected to the legitimate server. Note that the identity of the client is not verified unless [client certificates](#client-certificates-and-mutual-tls) are employed.

### SSL vs TLS

Secure Socket Layer (SSL) was the original protocol that was used to provide encryption for HTTP traffic, in the form of HTTPS. There were two publicly released versions of SSL - versions 2 and 3. Both of these have serious cryptographic weaknesses and should no longer be used.

For [various reasons](http://tim.dierks.org/2014/05/security-standards-and-name-changes-in.html) the next version of the protocol (effectively SSL 3.1) was named Transport Layer Security (TLS) version 1.0. Subsequently TLS versions 1.1, 1.2 and 1.3 have been released.

The terms "SSL", "SSL/TLS" and "TLS" are frequently used interchangeably, and in many cases "SSL" is used when referring to the more modern TLS protocol. This cheat sheet will use the term "TLS" except where referring to the legacy protocols.

## Server Configuration

### Only Support Strong Protocols

General purpose web applications should default to **TLS 1.3** (support TLS 1.2 if necessary) with all other protocols disabled.

 In specific and uncommon situations where a web server is required to accommodate legacy clients that depend on outdated and unsecured browsers (like Internet Explorer 10), activating TLS 1.0 may be the only option. However, this approach should be exercised with caution and is generally not advised due to the security implications. Additionally, ["TLS_FALLBACK_SCSV" extension](https://tools.ietf.org/html/rfc7507) should be enabled in order to prevent downgrade attacks against newer clients.

Note that PCI DSS [forbids the use of legacy protocols such as TLS 1.0](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf).

### Only Support Strong Ciphers

There are a large number of different ciphers (or cipher suites) that are supported by TLS, that provide varying levels of security. Where possible, only GCM ciphers should be enabled. However, if it is necessary to support legacy clients, then other ciphers may be required. At a minimum, the following types of ciphers should always be disabled:

- Null ciphers
- Anonymous ciphers
- EXPORT ciphers

The Mozilla Foundation provides an [easy-to-use secure configuration generator](https://ssl-config.mozilla.org/) for web, database and mail servers. This tool allows site administrators to select the software they are using and receive a configuration file that is optimized to balance security and compatibility for a wide variety of browser versions and server software.

### Set the appropriate Diffie-Hellman groups

The practice of earlier than TLS 1.3 protocol versions of Diffie-Hellman parameter generation for use by the ephemeral Diffie-Hellman key exchange (signified by the "DHE" or "EDH" strings in the cipher suite name) had practical issues. For example, the client had no say in the selection of server parameters, meaning it could only unconditionally accept or drop, and the random parameter generation often resulted to denial of service attacks (CVE-2022-40735, CVE-2002-20001).

TLS 1.3 restricts Diffie-Hellman group parameters to known groups via the `supported_groups` extension. The available
Diffie-Hellman groups are `ffdhe2048`, `ffdhe3072`, `ffdhe4096`, `ffdhe6144`, `ffdhe8192` as specified in [RFC7919](https://www.rfc-editor.org/rfc/rfc7919).

By default openssl 3.0 enables all the above groups. To modify them ensure that the right Diffie-Hellman group parameters are present in `openssl.cnf`. For example

```text
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_module
[ssl_module]
system_default = tls_system_default
[tls_system_default]
Groups = x25519:prime256v1:x448:ffdhe2048:ffdhe3072
```

An apache configuration would look like

```text
SSLOpenSSLConfCmd Groups x25519:secp256r1:ffdhe3072
```

The same group on NGINX would look like the following

```text
ssl_ecdh_curve x25519:secp256r1:ffdhe3072;
```

For TLS 1.2 or earlier versions it is recommended not to set Diffie-Hellman parameters.

### Disable Compression

TLS compression should be disabled in order to protect against a vulnerability (nicknamed [CRIME](https://threatpost.com/crime-attack-uses-compression-ratio-tls-requests-side-channel-hijack-secure-sessions-091312/77006/)) which could potentially allow sensitive information such as session cookies to be recovered by an attacker.

### Patch Cryptographic Libraries

As well as the vulnerabilities in the SSL and TLS protocols, there have also been a large number of historic vulnerability in SSL and TLS libraries, with [Heartbleed](http://heartbleed.com) being the most well known. As such, it is important to ensure that these libraries are kept up to date with the latest security patches.

### Test the Server Configuration

Once the server has been hardened, the configuration should be tested. The [OWASP Testing Guide chapter on SSL/TLS Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security) contains further information on testing.

There are a number of online tools that can be used to quickly validate the configuration of a server, including:

- [SSL Labs Server Test](https://www.ssllabs.com/ssltest)
- [CryptCheck](https://cryptcheck.fr/)
- [Hardenize](https://www.hardenize.com/)
- [ImmuniWeb](https://www.immuniweb.com/ssl/)
- [Observatory by Mozilla](https://observatory.mozilla.org)
- [Scanigma](https://scanigma.com)
- [Stellastra](https://stellastra.com/tls-cipher-suite-check)
- [OWASP PurpleTeam](https://purpleteam-labs.com/) `cloud`

Additionally, there are a number of offline tools that can be used:

- [O-Saft - OWASP SSL advanced forensic tool](https://wiki.owasp.org/index.php/O-Saft)
- [CipherScan](https://github.com/mozilla/cipherscan)
- [CryptoLyzer](https://gitlab.com/coroner/cryptolyzer)
- [SSLScan - Fast SSL Scanner](https://github.com/rbsec/sslscan)
- [SSLyze](https://github.com/nabla-c0d3/sslyze)
- [testssl.sh - Testing any TLS/SSL encryption](https://testssl.sh)
- [tls-scan](https://github.com/prbinu/tls-scan)
- [OWASP PurpleTeam](https://purpleteam-labs.com/) `local`

## Certificates

### Use Strong Keys and Protect Them

The private key used to generate the cipher key must be sufficiently strong for the anticipated lifetime of the private key and corresponding certificate. The current best practice is to select a key size of at least 2048 bits. Additional information on key lifetimes and comparable key strengths can be found [here](http://www.keylength.com/en/compare/) and in [NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf).

The private key should also be protected from unauthorized access using filesystem permissions and other technical and administrative controls.

### Use Strong Cryptographic Hashing Algorithms

Certificates should use SHA-256 for the hashing algorithm, rather than the older MD5 and SHA-1 algorithms. These have a number of cryptographic weaknesses, and are not trusted by modern browsers.

### Use Correct Domain Names

The domain name (or subject) of the certificate must match the fully qualified name of the server that presents the certificate. Historically this was stored in the `commonName` (CN) attribute of the certificate. However, modern versions of Chrome ignore the CN attribute, and require that the FQDN is in the `subjectAlternativeName` (SAN) attribute. For compatibility reasons, certificates should have the primary FQDN in the CN, and the full list of FQDNs in the SAN.

Additionally, when creating the certificate, the following should be taken into account:

- Consider whether the "www" subdomain should also be included.
- Do not include non-qualified hostnames.
- Do not include IP addresses.
- Do not include internal domain names on externally facing certificates.
    - If a server is accessible using both internal and external FQDNs, configure it with multiple certificates.

### Carefully Consider the use of Wildcard Certificates

Wildcard certificates can be convenient, however they violate [the principle of least privilege](https://wiki.owasp.org/index.php/Least_privilege), as a single certificate is valid for all subdomains of a domain (such as *.example.org). Where multiple systems are sharing a wildcard certificate, the likelihood that the private key for the certificate is compromised increases, as the key may be present on multiple systems. Additionally, the value of this key is significantly increased, making it a more attractive target for attackers.

The issues around the use of wildcard certificates are complicated, and there are [various](https://blog.sean-wright.com/wildcard-certs-not-quite-the-star/) other [discussions](https://gist.github.com/joepie91/7e5cad8c0726fd6a5e90360a754fc568) of them online.

When risk assessing the use of wildcard certificates, the following areas should be considered:

- Only use wildcard certificates where there is a genuine need, rather than for convenience.
    - Consider the use of the [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) to allow systems to automatically request and update their own certificates instead.
- Never use a wildcard certificates for systems at different trust levels.
    - Two VPN gateways could use a shared wildcard certificate.
    - Multiple instances of a web application could share a certificate.
    - A VPN gateway and a public web server **should not** share a wildcard certificate.
    - A public web server and an internal server **should not** share a wildcard certificate.
- Consider the use of a reverse proxy server which performs TLS termination, so that the wildcard private key is only present on one system.
- A list of all systems sharing a certificate should be maintained to allow them all to be updated if the certificate expires or is compromised.
- Limit the scope of a wildcard certificate by issuing it for a subdomain (such as `*.foo.example.org`), or a for a separate domain.

### Use an Appropriate Certification Authority for the Application's User Base

In order to be trusted by users, certificates must be signed by a trusted certificate authority (CA). For Internet facing applications, this should be one of the CAs which are well-known and automatically trusted by operating systems and browsers.

The [LetsEncrypt](https://letsencrypt.org) CA provides free domain validated SSL certificates, which are trusted by all major browsers. As such, consider whether there are any benefits to purchasing a certificate from a CA.

For internal applications, an internal CA can be used. This means that the FQDN of the certificate will not be exposed (either to an external CA, or publicly in certificate transparency lists). However, the certificate will only be trusted by users who have imported and trusted the internal CA certificate that was used to sign them.

### Use CAA Records to Restrict Which CAs can Issue Certificates

Certification Authority Authorization (CAA) DNS records can be used to define which CAs are permitted to issue certificates for a domain. The records contains a list of CAs, and any CA who is not included in that list should refuse to issue a certificate for the domain. This can help to prevent an attacker from obtaining unauthorized certificates for a domain through a less-reputable CA. Where it is applied to all subdomains, it can also be useful from an administrative perspective by limiting which CAs administrators or developers are able to use, and by preventing them from obtaining unauthorized wildcard certificates.

### Consider the Certificate’s Validation Type

Certificates come in different types of validation. Validation is the process the Certificate Authority (CA) uses to make sure you are allowed to have the certificate. This is authorization. The [CA/Browser Forum](https://cabforum.org/working-groups/server/baseline-requirements/documents/) is an organization made of CA and browser vendors, as well as others with an interest in web security. They set the rules which CAs must follow based on the validation type. The base validation is called Domain Validated (DV). All publicly issued certificates must be domain validated. This process involves practical proof of control of the name or endpoint requested in the certificate. This usually involves a challenge and response in DNS, to an official email address, or to the endpoint that will get the certificate.

Organization Validated (OV) certificates include the requestor’s organization information in the certificates subject. E.g. C = GB, ST = Manchester, **O = Sectigo Limited**, CN = sectigo.com. The process to acquire an OV certificate requires official contact with the requesting company via a method that proves to the CA that they are truly talking to the right company.

Extended validation (EV) certificates provide an even higher level of verification as well as all the DV and OV verifications. This can effectively be viewed as the difference between "This site is really run by Example Company Inc." vs "This domain is really example.org". [Latest Extended Validation Guidelines](https://cabforum.org/working-groups/server/extended-validation/guidelines/)

Historically these displayed differently in the browser, often showing the company name or a green icon or background in the address bar. However, as of 2019 no major browser shows EV status like this as they do not believe that EV certificates provide any additional protection. ([Chromium](https://groups.google.com/a/chromium.org/forum/m/#!msg/security-dev/h1bTcoTpfeI/jUTk1z7VAAAJ) Covering Chrome, Edge, Brave, and Opera. [Firefox](https://groups.google.com/forum/m/?fromgroups&hl=en#!topic/firefox-dev/6wAg_PpnlY4) [Safari](https://cabforum.org/2018/06/06/minutes-of-the-f2f-44-meeting-in-london-england-6-7-june-2018/#apple-root-program-update))

As all browsers and TLS stacks are unaware of the difference between DV, OV, and EV certificates, they are effectively the same in terms of security. An attacker only needs to reach the level of practical control of the domain to get a rogue certificate.  The extra work for an attacker to get an OV or EV certificate in no way increases the scope of an incident. In fact, those actions would likely mean detection. The additional pain in getting OV and EV certificates may create an availability risk and their use should be reviewed with this in mind.

## Application

### Use TLS For All Pages

TLS should be used for all pages, not just those that are considered sensitive such as the login page. If there are any pages that do not enforce the use of TLS, these could give an attacker an opportunity to sniff sensitive information such as session tokens, or to inject malicious JavaScript into the responses to carry out other attacks against the user.

For public facing applications, it may be appropriate to have the web server listening for unencrypted HTTP connections on port 80, and then immediately redirecting them with a permanent redirect (HTTP 301) in order to provide a better experience to users who manually type in the domain name. This should then be supported with the [HTTP Strict Transport Security (HSTS)](#use-http-strict-transport-security) header to prevent them accessing the site over HTTP in the future.

API-only endpoints should disable HTTP altogether and only support encrypted connections. When that is not possible, API endpoints should fail requests made over unencrypted HTTP connections instead of redirecting them.

### Do Not Mix TLS and Non-TLS Content

A page that is available over TLS should not include any resources (such as JavaScript or CSS) files which are loaded over unencrypted HTTP. These unencrypted resources could allow an attacker to sniff session cookies or inject malicious code into the page. Modern browsers will also block attempts to load active content over unencrypted HTTP into secure pages.

### Use the "Secure" Cookie Flag

All cookies should be marked with the "[Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)" attribute, which instructs the browser to only send them over encrypted HTTPS connections, in order to prevent them from being sniffed from an unencrypted HTTP connection. This is important even if the website does not listen on HTTP (port 80), as an attacker performing an active man in the middle attack could present a spoofed web server on port 80 to the user in order to steal their cookie.

### Prevent Caching of Sensitive Data

Although TLS provides protection of data while it is in transit, it does not provide any protection for data once it has reached the requesting system. As such, this information may be stored in the cache of the user's browser, or by any intercepting proxies which are configured to perform TLS decryption.

Where sensitive data is returned in responses, HTTP headers should be used to instruct the browser and any proxy servers not to cache the information, in order to prevent it being stored or returned to other users. This can be achieved by setting the following HTTP headers in the response:

```text
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

### Use HTTP Strict Transport Security

HTTP Strict Transport Security (HSTS) instructs the user's browser to always request the site over HTTPS, and also prevents the user from bypassing certificate warnings. See the [HTTP Strict Transport Security Cheat Sheet](HTTP_Strict_Transport_Security_Cheat_Sheet.md) for further information on implementing HSTS.

### Client Certificates and Mutual TLS

In a typical TLS configuration, a certificate on the server allows the client to verify the server's identity and provides an encrypted connection between them. However, this approach has two main weaknesses:

- The server lacks a mechanism to verify the client's identity.
- An attacker, obtaining a valid certificate for the domain, can intercept the connection. This interception is often used by businesses to inspect TLS traffic, by installing a trusted CA certificate on their client systems.

Client certificates, central to mutual TLS (mTLS), address these issues. In mTLS, both the client and server authenticate each other using TLS. The client proves their identity to the server with their own certificate. This not only enables strong authentication of the client but also prevents an intermediate party from decrypting TLS traffic, even if they have a trusted CA certificate on the client system.

Challenges and Considerations

Client certificates are rarely used in public systems due to several challenges:

- Issuing and managing client certificates involves significant administrative overhead.
- Non-technical users may find installing client certificates difficult.
- Organizations' TLS decryption practices can cause client certificate authentication, a key component of mTLS, to fail.

Despite these challenges, client certificates and mTLS should be considered for high-value applications or APIs, particularly where users are technically sophisticated or part of the same organization.

### Public Key Pinning

Public key pinning can be used to provides assurance that the server's certificate is not only valid and trusted, but also that it matches the certificate expected for the server. This provides protection against an attacker who is able to obtain a valid certificate, either by exploiting a weakness in the validation process, compromising a trusted certificate authority, or having administrative access to the client.

Public key pinning was added to browsers in the HTTP Public Key Pinning (HPKP) standard. However, due to a number of issues, it has subsequently been deprecated and is no longer recommended or [supported by modern browsers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins).

However, public key pinning can still provide security benefits for mobile applications, thick clients and server-to-server communication. This is discussed in further detail in the [Pinning Cheat Sheet](Pinning_Cheat_Sheet.md).

## Related Articles

- OWASP - [Testing for Weak TLS](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)
- OWASP - [Application Security Verification Standard (ASVS) - Communication Security Verification Requirements (V9)](https://github.com/OWASP/ASVS/blob/v4.0.1/4.0/en/0x17-V9-Communications.md)
- Mozilla - [Mozilla Recommended Configurations](https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations)
- NIST - [SP 800-52 Rev. 2 Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- NIST - [NIST SP 800-57 Recommendation for Key Management, Revision 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- NIST - [SP 800-95 Guide to Secure Web Services](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-95.pdf)
- IETF - [RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)
- IETF - [RFC 2246 The Transport Layer Security (TLS) Protocol Version 1.0 (JAN 1999)](https://tools.ietf.org/html/rfc2246)
- IETF - [RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1 (APR 2006)](https://tools.ietf.org/html/rfc4346)
- IETF - [RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2 (AUG 2008)](https://tools.ietf.org/html/rfc5246)
- Bettercrypto - [Applied Crypto Hardening: HOW TO for secure crypto settings of the most common services)](https://bettercrypto.org)
