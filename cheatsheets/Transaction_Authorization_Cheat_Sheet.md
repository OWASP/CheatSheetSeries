# Transaction Authorization Cheat Sheet

## Purpose and audience

The Purpose of this cheat sheet is to provide guidelines on how to securely implement transaction authorization to protect it from being bypassed. These guidelines can be used by:

- **Banks** - to define functional and non-functional requirements for transaction authorization.
- **Developers** – to design and implement transaction authorization without vulnerabilities.
- **Pentesters** – to test for transaction authorization security.

## Introduction

Some applications use a second factor to check whether an authorized user is performing sensitive operations. A common example is wire transfer authorization, typically used in online or mobile banking applications.

For the purpose of this document we will call that process: *transaction authorization*.

Usage scenarios are not only limited to financial systems. For example: an email with a secret code or a link with some kind of token to unlock a user account is also a special case of transaction authorization. A user authorizes the operation of account unlocking by using a second factor (a unique code sent to his email address). Transaction authorization can be implemented using various methods, e.g.:

- Cards with transaction authorization numbers (TAN),
- Time based OTP tokens, such as [OATH TOTP (Time-based One-Time Password)](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm),
- OTP sent by SMS or provided by phone
- Digital signature using e.g. a smart card or a smart phone,
- Challenge-response tokens, including unconnected card readers or solutions which scan transaction data from the user's computer screen.

Some of these can be implemented on a physical device or in a mobile application.

Transaction authorization is implemented in order to protect for unauthorized wire transfers as a result of attacks using malware, phishing, password or session hijacking, CSRF, XSS, etc.. Unfortunately, as with any piece of code, this protection can be improperly implemented and as a result it might be possible to bypass this safeguard.

## 1. Functional Guidelines

### 1.1 Transaction authorization method has to allow a user to identify and acknowledge significant transaction data

User's computers cannot be trusted due to malware threats. Hence a method that prevents a user from identifying transaction on an external device cannot be considered as secure. Transaction data should be presented and acknowledged using an external authorization component.

Such transaction authorization components should be built using the *What You See Is What You Sign* principle. When a user authorizes a transaction they need to know what they are authorizing. Based on this principle, an authorization method must permit a user to identify and acknowledge the data that is significant to a given transaction. For example, in the case of a wire transfer: the target account and amount.

The decision about which transaction data can be considered as significant should be chosen based on:

- The real risk,
- The technical capabilities and constraints of the chosen authorization method,
- Positive user experience.

For example when an SMS message is used to send significant transaction data, it is possible to send the target account, amount and type of transfer. However, for an unconnected [CAP reader](https://en.wikipedia.org/wiki/Chip_Authentication_Program) it is perceived to be inconvenient for a user to enter these data. In such cases, entering only the most significant transaction data (e.g. partial target account number and amount) can be considered sufficient.

In general, significant transaction data should always be presented as an inherent part of the transaction authorization process. Whereas the user experience should be designed to encourage users to verify the transaction data.

If a transaction process requires a user to enter transaction data into an external device, the user should be prompted for providing specific value (e.g. a target account number). Entering a value without meaningful prompt could be easily abused by malware using social engineering techniques as described in the example in paragraph 1.4. Also, for more detailed discussion of input overloading problems, see [here](http://www.cl.cam.ac.uk/~sjm217/papers/fc09optimised.pdf).

### 1.2 Change of authorization token should be authorized using the current authorization token

When a user is allowed to change authorization token by using the application interface, the operation should be authorized by using his current authorization credentials (as is the case with [password change procedure](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities.html)). For example: when a user changes a phone number for SMS codes an authorization SMS code should be sent to the current phone number.

### 1.3 Change of authorization method should be authorized using the current authorization method

Some applications allow a user to chose between multiple methods of transaction authorization. In such cases, the user should authorize the change in authorization method using his current authorization method. Otherwise, malware may change the authorization method to the most vulnerable method.

Additionally, the application should inform the user about the potential dangers associated to the selected authorization method.

### 1.4 Users should be able to easily distinguish the authentication process from the transaction authorization process

Malware can trick users in authorizing fraudulent operations, when an application requires a user to perform the same actions for authentication as for transaction authorization. Consider the following example:

- An application is using the same method for user authentication (usually as a second factor to traditional login/password) and for transaction authorization. E.g. by using a OTP token, Challenge-response codes, operation signing using external smartcard, ...
- A malware may present the user a false error message after the first step (authentication to the application) and trick the user into repeating the authentication procedure. The first authentication code will be used by the malware for authentication, whereas the second code would be used to authorize a fraudulent transaction. Even challenge-response schemes could be abused using this scenario as malware can present a challenge taken from a fraudulent transaction and trick the user to provide response. Such an attack scenario is used widely in [malware attacks against electronic banking](http://securityintelligence.com/back-basics-malware-authors-downgrade-tactics-stay-radar/#.VX_qI_krLDc).

In the abovementioned scenario, the same method was used to authenticate the user and to authorize the transaction. Malware can abuse this behavior to extract transaction authorization credentials without the user's knowledge. Social engineering methods [can be used despite utilized authentication and operation authorization methods](http://securityintelligence.com/tatanga-attack-exposes-chiptan-weaknesses/#.VZAy9PkrLDc) but the application shouldn't simplify such attack scenarios.

Safeguards should allow the user to easily distinguish authentication from transaction authorization. This could be achieved by:

- Using different methods to authenticate and to authorize,
- Or using different actions in an external security component (e.g. different mode of operation in CAP reader),
- Or presenting the user a clear message about what they are "signing" (What You See Is What You Sign Principle).

### 1.5 Each transaction should be authorized using unique authorization credentials

Some applications are asking for transaction authorization credentials only once, e.g. static password, code sent through SMS, token response. Afterwards a user is able to authorize any transaction during the whole user's session or at least they have to reuse the same credentials each time they need to authorize a transaction. Such behavior is not sufficient to prevent malware attacks because malware will sniff such credentials and use them to authorize any transaction without the user's knowledge.

## 2. Non-functional guidelines

### 2.1 Authorization should be performed and enforced server-side

As for [all other security controls](https://cwe.mitre.org/data/definitions/602.html) transaction authorization should be enforced server-side. By no means it should be possible to influence the authorization result by altering data which flows from a client to a server, e.g. by:

- Tampering with parameters that contain transaction data,
- Adding/removing parameters which will disable authorization check,
- Causing an error.

To achieve this, security programming best practices should be applied, such as:

- [Default deny](https://wiki.owasp.org/index.php/Positive_security_model).
- Avoiding debugging functionality in production code.

To avoid tampering, additional safeguards should be considered. For example by cryptographically protecting the data for confidentiality and integrity and while decrypting and verifying the data server side.

### 2.2 Authorization method should be enforced server side

When multiple transaction authorization methods are available to the user. The server should enforce the use of the current authorization method chosen by the user in the application settings or enforced by application policies. It should be impossible to change an authorization method by manipulating the parameters provided from the client. Otherwise, malware can downgrade an authorization method to a less or even the least secure authorization method.

This is especially important when an application is developed to add a new, more secure authorization method. It is not very rare,that a new authorization method is built on top of an old codebase. As a result, when a client is sending parameters using the old method, the transaction may be authorized, despite the fact that the user has already switched to a new method.

### 2.3 Transaction verification data should be generated server-side

When significant transaction data are transmitted programmatically to an authorization component, extra care should be put into denying client modifications on the transaction data at authorization. Significant transaction data that has to be verified by the user, should be generated and stored on a server, then passed to an authorization component without any possibility of tampering by the client.

A common anti pattern is to collect significant transaction data client-side and pass it to the server. In such cases, malware can manipulate these data and as a result, show faked transaction data in an authorization component.

### 2.4 Application should prevent authorization credentials brute-forcing

When transaction authorization credentials are sent to the server for verification, an application has to prevent brute-forcing. The transaction authorization process must be restarted after number of failed authorization attempts. In addition other anti brute-forcing and anti-automation techniques should be considered to prevent an attacker from automating his attacks,see [OWASP Authentication Cheat Sheet](Authentication_Cheat_Sheet.md#prevent-brute-force-attacks).

### 2.5 Application should control which transaction state transitions are allowed

Transaction authorization is usually performed in multiple steps, e.g.:

1. The user enters the transaction data.
2. The user requests authorization.
3. The application initializes an authorization mechanism.
4. The user verifies/confirms the transaction data.
5. The user responds with the authorization credentials.
6. The application validates authorization and executes a transaction.

An application should process such business logic flow in sequential step order and preventing a user from performing these steps out of order or in even skipping any of these steps (see [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) requirement **15.1**).

This should protect against attack techniques such as:

- Overwriting transaction data before user will enter the authorization credentials,
- Skipping transaction authorization.

### 2.6 Transaction data should be protected against modification

The transaction authorization process should protect against attack scenarios that modify transaction data after the initial entry by the user. For example, a bad implementation of a transaction authorization process may allow the following attacks (for reference, see steps of transaction authorization described in paragraph 2.5):

- Replaying step 1 (sending transaction data) in the background and overwriting transaction details with fraudulent transaction, before the user enters authorization credentials.
- Adding parameters with transaction data to a HTTP request which authorizes the transaction. In such a case, poor implementation will authorize the initial transaction and then execute a fraudulent transaction (specific example of [Time of Check to Time of Use vulnerability](https://cwe.mitre.org/data/definitions/367.html)).

The protection against modification could be implemented using various techniques depending on the framework used, but one or more of the following should be present:

- Any modification of transaction data should trigger invalidation of any previously entered authorization data. E.g. Generated OTP or challenge is invalidated.
- Any modification of transaction data should trigger reset of the authorization process.
- Any attempts to modify transaction data after the initial entry by the user is a symptom of tinkering with an application and should be logged, monitored and carefully investigated.

### 2.7 Confidentiality of the transaction data should be protected during any client / server communications

The transaction authorization process should protect the privacy of transaction data being presented to the user to authorize i.e. at section 2.5, steps 2 and 4.

### 2.8 When a transaction is executed, the system should check whether it was authorized

The result of the transaction entry and the authorization process described in paragraph 2.5 is the transaction execution. Just before the transaction is executed there should be a final control gate which verifies whether the transaction was properly authorized by the user. Such control, tied to execution, should prevent attacks such as:

- Time of Check to Time of Use (TOCTOU) – example in paragraph 2.6
- Skipping authorization check in the transaction entry process (see. paragraph 2.5)

### 2.9 Authorization credentials should be valid only by limited period of time

In some malware attacks scenarios, authorization credentials entered by the user is passed to malware command and control server (C&C) and then used from an attacker-controlled machine. Such a process is often performed manually by an attacker. To make such attacks difficult, the server should allow authorizing the transaction only in a limited time window between generating of challenge or OTP and the transaction authorization. Additionally, such safeguard will also aid in preventing resource exhaustion attacks. The time window should be carefully selected to not disrupt normal users' behavior.

### 2.10 Authorization credentials should be unique for every operation

To prevent all sorts of replay attacks, authorization credentials should be unique for every operation. It could be achieved using different methods depending on the applied transaction authorization mechanism. For example: using a timestamp, a sequence number or a random value in signed transaction data or as a part of a challenge.

## Remarks

We identify other issues that should be taken into consideration while implementing transaction authorization. However we deem to be beyond the scope of this cheat sheet:

- Which transactions should be authorized? All transactions or only some of them. Each application is different and an application owner should decide if all transactions should be authorized or only some of them, considering risk analysis, risk exposition of given application, and other safeguards implemented in an application.
- We recommend the use of cryptographic operations to protect transactions and to ensure integrity, confidentiality and non-repudiation.
- Device enrolment or "pairing" of an external authorization device (or a mobile application) with the user account.
- Provisioning & protection of the device signing keys, during device "pairing" is as critical as the signing protocol itself. Malware may attempt to inject/replace or steal the signing keys.
- User awareness. E.g.: For transaction authorization methods, when a user types-in significant transaction data to an authorization component (e.g. an external dedicated device or a mobile application), users should be trained to rewrite transaction data from trusted source and not from a computer screen.
- There are some anti-malware solutions that protect against malware threats but such solutions [do not guarantee 100% effectiveness](http://www.securing.pl/en/script-based-malware-detection-in-online-banking-security-overview/index.html) and should be used only as an additional layer of protection.
- Protection of the signing keys using a second factor either be password, biometric, etc..
- Protection of the signing keys leveraging secure elements (TEE, TPM, Smart card..)

## References and future reading

References and future reading:

- Wojciech Dworakowski: [E-banking transaction authorization - possible vulnerabilities, security verification and best practices for implementation. Presentation from AppSec EU 2015](http://www.slideshare.net/wojdwo/ebanking-transaction-authorization-appsec-eu-2015-amsterdam).
- Saar Drimer, Steven J. Murdoch, and Ross Anderson: [Optimised to Fail - Card Readers for Online Banking](http://www.cl.cam.ac.uk/~sjm217/papers/fc09optimised.pdf).
- Jakub Kałużny, Mateusz Olejarka: [Script-based Malware Detection in Online Banking Security Overview](http://www.securing.pl/en/script-based-malware-detection-in-online-banking-security-overview/index.html).
- [List of websites and whether or not they support 2FA](https://twofactorauth.org/).
- Laerte Peotta, Marcelo D. Holtz, Bernardo M. David, Flavio G. Deus, Rafael Timóteo de Sousa Jr: [A Formal Classification Of Internet Banking Attacks and Vulnerabilities](http://airccse.org/journal/jcsit/0211ijcsit13.pdf).
- Marco Morana, Tony Ucedavelez: [Threat Modeling of Banking Malware-Based Attacks](https://owasp.org/www-pdf-archive/Marco_Morana_and_Tony_UV_-_Threat_Modeling_of_Banking_Malware.pdf).
- OWASP [Anti-Malware - Knowledge Base](https://wiki.owasp.org/index.php/OWASP_Anti-Malware_-_Knowledge_Base).
- OWASP [Anti-Malware Project - Awareness Program](https://wiki.owasp.org/index.php/OWASP_Anti-Malware_Project_-_Awareness_Program).
- Arjan Blom , Gerhard de Koning Gans , Erik Poll , Joeri de Ruiter , and Roel Verdult: [Designed to Fail - A USB-Connected Reader for Online Banking](http://www.cs.ru.nl/~rverdult/Designed_to_Fail_A_USB-Connected_Reader_for_Online_Banking-NORDSEC_2012.pdf).
