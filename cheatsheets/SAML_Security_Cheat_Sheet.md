# SAML Security Cheat Sheet

## Introduction

The **S**ecurity **A**ssertion **M**arkup **L**anguage ([SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)) is an open standard for exchanging authorization and authentication information. The *Web Browser SAML/SSO Profile with Redirect/POST bindings* is one of the most common SSO implementation. This cheatsheet will focus primarily on that profile.

## Validate Message Confidentiality and Integrity

[TLS 1.2](Transport_Layer_Security_Cheat_Sheet.md) is the most common solution to guarantee message confidentiality and integrity at the transport layer. Refer to [SAML Security (section 4.2.1)](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf) for additional information. This step will help counter the following attacks:

- Eavesdropping 7.1.1.1
- Theft of User Authentication Information 7.1.1.2
- Theft of the Bearer Token 7.1.1.3
- Message Deletion 7.1.1.6
- Message Modification 7.1.1.7
- Man-in-the-middle 7.1.1.8

A digitally signed message with a certified key is the most common solution to guarantee message integrity and authentication. Refer to [SAML Security (section 4.3)](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf) for additional information. This step will help counter the following attacks:

- Man-in-the-middle 6.4.2
- Forged Assertion 6.4.3
- Message Modification 7.1.1.7

Assertions may be encrypted via XMLEnc to prevent disclosure of sensitive attributes post transportation. Refer to [SAML Security (section 4.2.2)](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf) for additional information. This step will help counter the following attacks:

- Theft of User Authentication Information 7.1.1.2

## Validate Protocol Usage

This is a common area for security gaps - see [Google SSO vulnerability](https://www.kb.cert.org/vuls/id/612636/) for a real life example. Their SSO profile was vulnerable to a Man-in-the-middle attack from a malicious SP (Service Provider).

The SSO Web Browser Profile is most susceptible to attacks from trusted partners. This particular security flaw was exposed because the SAML Response did not contain all of the required data elements necessary for a secure message exchange. Following the [SAML Profile](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) usage requirements for AuthnRequest (4.1.4.1) and Response (4.1.4.2) will help counter this attack.

The *AVANTSSAR* team suggested the following data elements should be required:

- **AuthnRequest(ID, SP):** An `AuthnRequest` must contain and `ID` and `SP`. Where `ID` is a string uniquely identifying the request and an `SP` identifies the `Service Provider` that initiated the request. Furthermore, the request `ID` attribute must be returned in the response (`InResponseTo="<requestId>"`). `InResponseTo` helps guarantee authenticity of the response from the trusted IdP. This was one of the missing attributes that left Google's SSO vulnerable.
- **Response(ID, SP, IdP, {AA} K -1/IdP):** A Response must contain all these elements. Where `ID` is a string uniquely identifying the response. `SP` identifies the recipient of the response. `IdP` identifies the identity provider authorizing the response. `{AA} K -1/IdP` is the assertion digitally signed with the private key of the `IdP`.
- **AuthAssert(ID, C, IdP, SP):** An authentication assertion must exist within the Response. It must contain an `ID`, a client `(C)`, an identity provider `(IdP)`, and a service provider `(SP)` identifier.

### Validate Signatures

Vulnerabilities in SAML implementations due to XML Signature Wrapping attacks were described in 2012, [On Breaking SAML: Be Whoever You Want to Be](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf).

The following recommendations were proposed in response ([Secure SAML validation to prevent XML signature wrapping attacks](https://arxiv.org/pdf/1401.7483v1.pdf)):

- Without exception, always perform schema validation on the XML document prior to using it for any security-related purposes::
    - Always use local, trusted copies of schemas for validation.
    - Never allow automatic download of schemas from third party locations.
    - If possible, inspect schemas and perform schema hardening, to disable possible wildcard type or relaxed processing statements.
- Securely validate the digital signature:
    - If you expect only one signing key, use `StaticKeySelector`. Obtain the key directly from the identity provider, store it in a local file and ignore any `KeyInfo` elements in the document.
    - If you expect more than one signing key, use `X509KeySelector` (the JKS variant). Obtain these keys directly from the identity providers, store them in local JKS and ignore any `KeyInfo` elements in the document.
- Avoid signature-wrapping attacks.
    - Never use `getElementsByTagName` to select security related elements in an XML document without prior validation.
    - Always use absolute XPath expressions to select elements, unless a hardened schema is used for validation.

## Validate Protocol Processing Rules

This is another common area for security gaps simply because of the vast number of steps to assert.

Processing a SAML response is an expensive operation but all steps must be validated:

- Validate AuthnRequest processing rules. Refer to [SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) (3.4.1.4) for all AuthnRequest processing rules. This step will help counter the following attacks:
    - Man-in-the-middle (6.4.2)
- Validate Response processing rules. Refer to [SAML Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) (4.1.4.3) for all Response processing rules. This step will help counter the following attacks:
    - Stolen Assertion (6.4.1)
    - Man-in-the-middle (6.4.2)
    - Forged Assertion (6.4.3)
    - Browser State Exposure (6.4.4)

## Validate Binding Implementation

- For an HTTP Redirect Binding refer to [SAML Binding](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) (3.4). To view an encoding example, you may want to reference RequestUtil.java found within [Google's reference implementation](https://developers.google.com/google-apps/sso/saml_reference_implementation_web).
- For an HTTP POST Binding refer to [SAML Binding](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) (3.5). The caching considerations are also very important. If a SAML protocol message gets cached, it can subsequently be used as a Stolen Assertion (6.4.1) or Replay (6.4.5) attack.

## Validate Security Countermeasures

Revisit each security threat that exists within the [SAML Security](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf) document and assert you have applied the appropriate countermeasures for threats that may exist for your particular implementation.

Additional countermeasures considered should include:

- Prefer IP Filtering when appropriate. For example, this countermeasure could have prevented Google's initial security flaw if Google provided each trusted partner with a separate endpoint and setup an IP filter for each endpoint. This step will help counter the following attacks:
    - Stolen Assertion (6.4.1)
    - Man-in-the-middle (6.4.2)
- Prefer short lifetimes on the SAML Response. This step will help counter the following attacks:
    - Stolen Assertion (6.4.1)
    - Browser State Exposure (6.4.4)
- Prefer OneTimeUse on the SAML Response. This step will help counter the following attacks:
    - Browser State Exposure (6.4.4)
    - Replay (6.4.5)

Need an architectural diagram? The [SAML technical overview](https://www.oasis-open.org/committees/download.php/11511/sstc-saml-tech-overview-2.0-draft-03.pdf) contains the most complete diagrams. For the Web Browser SSO Profile with Redirect/POST bindings refer to the section 4.1.3. In fact, of all the SAML documentation, the technical overview is the most valuable from a high-level perspective.

## Unsolicited Response (ie. IdP Initiated SSO) Considerations for Service Providers

Unsolicited Response is inherently less secure by design due to the lack of **login [CSRF](https://owasp.org/www-community/attacks/csrf)** protection. This limitation arises because the Service Provider (SP) has no opportunity to create a pre-login session or verify that the authentication request was intentionally initiated by the user.  

While this design does not make IdP-initiated SSO uniquely vulnerable to Man-in-the-Middle (MITM) attacks—those risks apply equally to SP-initiated flows if transport security is compromised—it does remove an important layer of login intent validation.  

Despite these concerns, IdP-initiated SSO remains supported for backward compatibility (notably with SAML 1.1). If it must be enabled, the following steps (in addition to those mentioned above) should help secure this flow:

- Follow the validation process mentioned in [SAML Profiles (section 4.1.5)](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf). This step will help counter the following attacks:
    - Replay (6.1.2)
    - Message Insertion (6.1.3)
- If the contract of the `RelayState` parameter is a URL, make sure the URL is validated and explicitly on an allowlist. This step will help counter the following attack:
    - [Open Redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- Implement proper replay detection either at the response or assertion level. This will help counter the following attack:
    - Replay (6.1.2)

## Identity Provider and Service Provider Considerations

The SAML protocol is rarely the attack vector of choice, though it's important to have cheatsheets to make sure that this is robust. The various endpoints are more targeted, so how the SAML token is generated and how it is consumed are both important in practice.

### X.509 Certificate Considerations

Typically the security association between the Identity Provider (IdP) and Service Provider (SP) is created when the SP explicitly chooses to trust the IdP's X.509 signing certificate. Exactly how this occurs can have a strong bearing on overall security posture. How the certificate is generated, what the contents of the certificate are, and how the certificate's corresponding private key is protected all have strong bearing on security posture. e.g., if an attacker has access to use the IdP’s signing key, they can mint SAML responses containing any assertion they wish.

In many cases, the method of manually setting the association is akin to [Certificate Pinning](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html), which is not ideal. Depending on the IdP and SP software, or various design considerations, this may be unavoidable.

Keep in mind that the certificate's signature type can be different from that of the XML document signing type. The certificate's corresponding private key is the only key that can be used to sign the XML document, but the signing algorithm is chosen at the IdP's discretion. The most commonly supported signing algorithm is rsa-sha256.

#### SAML Parties vs Organizations

The most common SAML use cases are those of business-to-business (B2B). This means that the two parties have different security polices, practices, and risk tolerances. This guidance focuses mainly on the B2B use case. However SAML based federation or SSO is commonly used inside of an organization. In this case the term third-party CA does not apply. It is likely that the CA has been built and run to company standards and it poses no more or less risk to the SAML systems. The term third-party CA is meant to indicate a private CA run by a third-party.

#### Certificate Use Cases

There are actually 5 separate use cases for certificates in a SAML system. While this document mainly talks about the IdP’s SAML signing certificate, the security considerations apply to all four SAML related certificates. The fifth certificate, the IdP’s TLS server certificate is no more or less special than any other server certificate.

##### IdP SAML Signing

This is the certificate that an SP uses to validate an IdD’s SAML response. The IdP signs that response with the certificate’s corresponding private key. This is often the most important certificate and private key, as this protects the identity assertions being sent to the SP.

##### IdP SAML Encryption

This is less commonly used, as this is used when the SP wants to protect the SAML request sent to the IdP, not just from tampering, but from information disclosure. There should be no sensitive information in the SAML request, so it is less commonly used. If used, the certificate and private key must be different from that of the SAML signing certificate.

##### SP Signing

It is a best practice, though not required, that SPs and IdPs not allow IdP Initiated SSO. This means that the caller starts their SAML flow at the SP, which produces a signed SAML request intended for the IdP.

##### SP Encryption

It is a best practice to avoid placing sensitive data in the IdP’s SAML response, but sometimes it is unavoidable. This could be usernames or other PII. When information disclosure is a consideration, an SP will have a SAML encryption certificate. The IdP will use this and the embedded public key, in order to encrypt the SAML response. The SP must use a separate certificate and key pair for SAML signing and encryption.

#### Certificate Contents

In the context of SAML signing and encryption, X.509 certificates are most often treated simply as a wrapper to hold a public key that is used to verify a signature, or to wrap a symmetric key for SAML encryption. Nonetheless, a certificate can contain attributes that can be used to further enhance security.

OWASP recommends that IdPs and SPs move to adopt the EKU, KU, and key lifetimes mentioned below. These legitimately enhance security and allow the verifying party to further protect themselves. They also help show compliance with PKI norms.

##### Keys and Signing Algorithms

The key pair size and type and signing algorithm choice has strong bearing on security and interoperability.  Not all IdP and SP software packages or libraries support all combinations of options. As one IdP often has many SPs associated with it, the only option is to pick the least secure option that is still considered secure. The most supported and currently secure combination is using RSA 2048 bit keys and SHA-256 hashing/signing. This is referring to the certificate’s signing algorithm and not the SAML XML signing.

As post-quantum algorithms become more prevalent, and ultimately required, this becomes even more complex. Those writing SAML SP and IdP software should begin looking at options to support more key and signing algorithms.

###### Keys

ECC Keys can be much smaller while providing more security than RSA keys and the math involved is faster to perform. These are preferred when all parties can use them. ECC keys can be as low as 256 bit and still be secure. RSA keys are more interoperable. The minimum RSA key size should be 2048 bit.
At least one major vendor [Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp) doesn’t support ECC keys.

###### Signing Algorithms

When public key cryptography is used for signing data, the data is first hashed with an chosen algorithm and then the hash is signed using the private key.

No IdP should use SHA-1 as the certificate signing hash. SHA-256 is the minimum bar. That said, if possible moving to larger hash algorithms like SHA-384 or SHA-512 means you are better future-proofing your service. In this context we are talking about the certificate’s signing algorithm and not the one used to sign the SAML response XML.

##### Certificate Lifetime

Certificates contain a NotBefore and NotOnorAfter attribute. Most IdPs ignore these in favor of guaranteeing uptime if certificate rotation does not happen on time. The SAML certificate lifetime should be handled well enough that ignoring these is not needed. Ignoring the certificate's validity period is fundamentally a bad idea. While [NIST SP 800-57 (Part 1, Rev. 5)](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) allows RSA 2048 bit keys to last for 3 years, the maximum lifetime of a SAML signing certificate should be two years. If the private key is not well protected, such as in a Hardware Security Module (HSM), that may be too long to be safe.

##### Extended Key Usage (EKU) and Key Usage (KU)

[EKU](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12) describes a specific use case that the certificate is intended for. These are use cases like server authentication, client authentication, and code signing, which are not appropriate for SAML signing. There is no widely accepted EKU for SAML signing, but [RFC 9336](https://www.rfc-editor.org/rfc/rfc9336.txt) defines one that is ideal, id-kp-documentSigning (1.3.6.1.5.5.7.3.36). IdPs and SPs may consider standardizing on this EKU.

[KU](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3) describes the underlying cryptographic operations that the private key is meant for. There are things like digitalSignature, nonRepudiation, keyEncipherment, etc. IdPs and SPs may consider requiring digitalSignature and further, disallowing certificates that have other KUs, as certificates should only be used for one use case. e.g. the IdP's TLS server certificate must never be the SAML signing certificate.

##### CRL Distribution Point (CDP)

[Certificate Revocation List (CRL) Distribution Point](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13) are a list of certificates that the CA says should no longer be trusted. They are most often delivered over HTTP and the CRL URLs are generally embedded in each CA issued certificate. The [CRL](https://www.rfc-editor.org/rfc/rfc5280#appendix-C.4) is signed by the CA, so a man-in-the-middle attack against the HTTP cannot harm the integrity of the list, other than to tamper with, and thus invalidate, it. That is, it can't be altered by an attacker. Only CA signed certificates can have a CRL. If the SAML certificate has a CRL listed, it should be reachable by the validating party and the party should [validate](https://www.rfc-editor.org/rfc/rfc5280#section-6.3) it.

Considering the level of risk, if a private key is compromised, and the smaller scale of IdP to SP relationships, parties in a SAML system should establish a plan with contact lists to notify and rotate certificates rapidly in case of an incident. Many SAML products and libraries don’t support revocation checking, and simply revoking the certificate, without coordinated replacement, means there is an outage.

##### Online Certificate Status Protocol (OCSP)

[OCSP](https://datatracker.ietf.org/doc/html/rfc6960) is another way of checking to see if a certificate  is revoked. The OCSP URL is embedded in the certificate , like a CRL, and should be reachable  over HTTP. The response is signed, so MITM attacks are not an integrity concern. OCSP is becoming less favored, as the exchange creates privacy concerns. The caller's IP address can be seen and the certificate that is being used is disclosed. This is less of a concern for SAML, as this does not disclose a destination website, use overall has declined. If an OCSP URL is present on any certificate in the chain, it should be used to check if the certificate is revoked.

#### Certificate Hierarchy

The SAML signing certificate can be signed by one of three things. The certificate can be self-signed, public CA signed, or private CA signed. Each has pros and cons, however, given the current state of WebPKI (public) and private PKI, using self-signed SAML certificates are the clear winner when proper precautions are taken for exchanging the certificates.

##### Certificate Issuer

All X.509 certificates are signed, using a private key, by an authority known as an [Issuer](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4). This may be a CA or in the case of a self-signed certificate the certificate's corresponding private key. In the case of a CA signed certificate, the signer may also have a certificate that has an Issuer, and so on. This is called chain, or path, and should terminate in a Root CA (which is self-signed by definition). The issuer should be inspected. If the issuer is a CA, its attributes, such as EKU, KU, and CRLs, may also be validated. This should happen for each certificate in the [path](https://datatracker.ietf.org/doc/html/rfc5280#section-3.2) all the way to the root.

##### Public Certificate Authority (CA) Signed

With this certificate type, a Public CA issues the certificate, in accordance with their rules and the rules of the [CA Browser Forum](https://cabforum.org/) (CABF). These public root CAs get bundled into trust stores maintained by major browser vendors. Most things on the web trust these, because someone makes sure the trust stores are where they need to be.

When an IdP rotates its SAML Signing certificate, each SP must simultaneously update its explicit trust of that certificate. This can be challenging with only a few SPs. With many, it is nearly impossible. This pain has led to the use of SAML signing certificates with the longest possible lifetimes. This used to be two years with public CAs, then 398 days. The focus of WebPKI standards and the CABF is on server certificates for TLS. Recent and ongoing changes in certificate lifetimes make Public CA issued certificates less appealing. This is because the CABF has a path to making public CA issued certificates last only [47 days](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/). As the IdP must get the certificate, announce the change for a reasonable amount of time, and then execute the change, this would mean IdPs and SPs would be in a perpetual state of certificate updates.

It is worth noting that the CABF does not have governance around the use or acquisition of SAML certificates, certificates from their member CAs are what are widely considered Public CAs. That is, they are widely trusted by browsers, operating systems, and various development frameworks.

Using Public CA signed certificates allows for revocation checking, which can increase security, but if the certificate exchange is not secured, this could lead to a false sense of security.

##### Private CA Signed

As most IdPs and SPs treat the X.509 certificates as an explicit trust, private CAs and PKI could be used. How private CAs are designed, built, and run varies wildly and ultimately running CAs well is very costly. In order to trust a third-party's CAs, one would need to clearly understand the lifecycle of the CA. There are two audit types that would cover this, both of which are very costly, on top of building and running the CAs. If you rely on third-party CAs, they should be [WebTrust](http://www.webtrust.org/), [ETSI](http://www.etsi.org/technologies-clusters/technologies/security/certification-authorities-and-other-certification-service-providers), or [SOC 2 Type II](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) audited.

Trusting third-party CAs, if done improperly, could result in unintended over-trust, for things such as TLS and code signing. If you choose to trust third-party CAs, make sure they are only trusted for the process of IdP signature validation.

If third-party CAs are used they still should not issue SAML signing certificates where the lifetime of the certificate exceeds that of the underlying key pair, based on guidance from a standards organization such as [NIST, NSA, etc.](https://www.keylength.com/en/). If using the strongest private key types, this puts the upper limit at two years.

##### Self-Signed

Due to the explicit nature of most SAML security associations, self-signed certificates are ideal for the use case. The contents of the certificate and lifetime are not constrained by the policy or process of the issuing CA, be it public or private. As rotating SAML certificates can be painful and labor intensive, setting the certificate lifetime as long as safely possible is key. Few CAs allow long enough lifetimes, due to their focus on the TLS threat model.

###### Creating a Self-Signed SAML Certificate

If you are using a Hardware Security Module (HSM), follow the vendor's instructions. This process uses openssl. The example uses an overly generic distinguished name. Your Common Name (CN) should be meaningful and specific.

1. Generate a Private Key:
openssl genrsa -out private.key 2048
or
openssl ecparam -genkey -name prime256v1 -out private.pem

2. Create a Configuration File (e.g., cert.cnf):

\[req\]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

\[req_distinguished_name\]
C = US
ST = California
L = San Francisco
O = MyOrganization
OU = MyUnit
CN = SAML Signing

\[v3_ca\]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36

3. Generate the Self-Signed Certificate:
openssl req -x509 -new -nodes -key private.key -sha256 -days 365 -out certificate.crt -config cert.cnf -extensions v3_ca

#### Certificate Metadata URLs

Many IdPs publish a metadata URL that contains basic configuration information including the SAML signing certificate. Many SPs can consume the data from the IdP, updating the Signing certificate information in near real-time. Using these options is ideal. This model matches exactly the intent of the [Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) when pinning must be used.

The metadata URL should be protected using TLS where the server certificate comes from a WebPKI CA that is widely trusted and matches the guidance in the [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#certificates).

The ideal state of the IdP to SP relationship is that of using the metadata URLs, regardless of what type of certificate is used. If metadata URLs are not used, great care must be taken to assure that an attacker does not convince an SP to trust the wrong certificate. Avoid emailing certificates. Instead, like the metadata URL, present them over properly configured TLS.

#### Signing Key Protection

SAML Signing keys are a top security asset and [target of attackers](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/). Great care should be taken when creating the keys and as needed, copying them to nodes of an IdP cluster. File based keys are trivial for an attacker with access to exfiltrate. IdP operators should strongly consider protecting the private keys using a Hardware Security Module (HSM). [HSMs](https://en.wikipedia.org/wiki/Hardware_security_module) allow an application to use a key without it being exportable or copyable. They have mechanisms to safely replicate the keys into a failover HSM, without ever exposing the keys outside of the HSMs. Quality HSMs would be rated [FIPS 140-2](https://csrc.nist.gov/pubs/fips/140-2/upd2/final) or [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final).

### Identity Provider (IdP) Considerations

- Validate X.509 Certificate for algorithm compatibility, strength of encryption, export restrictions, and content above
- Validate Strong Authentication options for generating the SAML token
- IDP validation (which IDP mints the token)
- Synchronize to a common Internet timesource
- Define levels of assurance for identity verification
- Prefer asymmetric identifiers for identity assertions over personally identifiable information (e.g. SSNs, etc)
- Sign each individual Assertion or the entire Response element

### Service Provider (SP) Considerations

- Validating session state for user
- Level of granularity in setting authorization context when consuming SAML token (do you use groups, roles, attributes)
- Ensure each Assertion or the entire Response element is signed
- [Validate Signatures](#validate-signatures)
- Validate if signed by an authorized IdP
- Validate IDP certificates for revocation against CRL/OCSP if they are present
- Validate NotBefore and NotOnorAfter
- Validate Recipient attribute
- Define criteria for SAML logout
- Exchange assertions only over secure transports like TLS
- Define criteria for session management
- Verify user identities obtained from SAML ticket assertions whenever possible.

## Input Validation

Just because SAML is a security protocol does not mean that input validation goes away.

- Ensure that all SAML providers/consumers do proper [input validation](Input_Validation_Cheat_Sheet.md).

## Cryptography

Solutions relying cryptographic algorithms need to follow the latest developments in cryptoanalysis.

- Ensure all SAML elements in the chain use [strong encryption](Cryptographic_Storage_Cheat_Sheet.md#algorithms)
- Consider deprecating support for [insecure XMLEnc algorithms](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-1_5)
