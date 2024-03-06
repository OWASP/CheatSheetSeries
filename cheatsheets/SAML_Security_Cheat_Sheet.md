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

- Always perform schema validation on the XML document prior to using it for any security-­related purposes:
    - Always use local, trusted copies of schemas for validation.
    - Never allow automatic download of schemas from third party locations.
    - If possible, inspect schemas and perform schema hardening, to disable possible wildcard ­type or relaxed processing statements.
- Securely validate the digital signature:
    - If you expect only one signing key, use `StaticKeySelector`. Obtain the key directly from the identity provider, store it in local file and ignore any `KeyInfo` elements in the document.
    - If you expect more than one signing key, use `X509KeySelector` (the JKS variant). Obtain these keys directly form the identity providers, store them in local JKS and ignore any `KeyInfo` elements in the document.
    - If you expect a heterogeneous signed documents (many certificates from many identity providers, multi­level validation paths), implement full trust establishment model based on PKIX and trusted root certificates.
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

Unsolicited Response is inherently [less secure](https://www.identityserver.com/articles/the-dangers-of-saml-idp-initiated-sso) by design due to the lack of [CSRF](https://owasp.org/www-community/attacks/csrf) protection. However, it is supported by many due to the backwards compatibility feature of SAML 1.1. The general security recommendation is to not support this type of authentication, but if it must be enabled, the following steps (in additional to everything mentioned above) should help you secure this flow:

- Follow the validation process mentioned in [SAML Profiles (section 4.1.5)](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf). This step will help counter the following attacks:
    - Replay (6.1.2)
    - Message Insertion (6.1.3)
- If the contract of the `RelayState` parameter is a URL, make sure the URL is validated and explicitly on an allowlist. This step will help counter the following attack:
    - [Open Redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- Implement proper replay detection either at the response or assertion level. This will help counter the following attack:
    - Replay (6.1.2)

## Identity Provider and Service Provider Considerations

The SAML protocol is rarely the vector of choice, though it's important to have cheatsheets to make sure that this is robust. The various endpoints are more targeted, so how the SAML token is generated and how it is consumed are both important in practice.

### Identity Provider (IdP) Considerations

- Validate X.509 Certificate for algorithm compatibility, strength of encryption, export restrictions
- Validate Strong Authentication options for generating the SAML token
- IDP validation (which IDP mints the token)
- Use/Trust Root CAs whenever possible
- Synchronize to a common Internet timesource
- Define levels of assurance for identity verification
- Prefer asymmetric identifiers for identity assertions over personally identifiable information (e.g. SSNs, etc)
- Sign each individual Assertion or the entire Response element

### Service Provider (SP) Considerations

- Validating session state for user
- Level of granularity in setting authorization context when consuming SAML token (do you use groups, roles, attributes)
- Ensure each Assertion or the entire Response element is signed
- [Validate Signatures](#validate-signatures)
- Validate if signed by authorized IDP
- Validate IDP certificates for expiration and revocation against CRL/OCSP
- Validate NotBefore and NotOnorAfter
- Validate Recipient attribute
- Define criteria for SAML logout
- Exchange assertions only over secure transports
- Define criteria for session management
- Verify user identities obtained from SAML ticket assertions whenever possible.

## Input Validation

Just because SAML is a security protocol does not mean that input validation goes away.

- Ensure that all SAML providers/consumers do proper [input validation](Input_Validation_Cheat_Sheet.md).

## Cryptography

Solutions relying cryptographic algorithms need to follow the latest developments in cryptoanalysis.

- Ensure all SAML elements in the chain use [strong encryption](Cryptographic_Storage_Cheat_Sheet.md#algorithms)
- Consider deprecating support for [insecure XMLEnc algorithms](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-1_5)
