# Transaction Authorization Cheat Sheet

## Purpose and audience

This cheat sheet discusses how developers can secure transaction authorizations and prevent them from being bypassed. These guidelines are for:

- **Banks** - who must create functional and non-functional requirements for transaction authorization.
- **Developers** – who need to eliminate vulnerabilities in transaction authorizations.
- **Pentesters** – who must determine if transaction authorizations are secure.

## Introduction

Generally, mobile and online applications will require users to submit a second factor so the system can check whether they are authorized to perform a sensitive operation (such as wire transfer authorization). In this document, we say that these actions are *transaction authorizations*.

Transaction authorizations are often used in financial systems, but the need for secure transactions has driven the adoption of authorizations across the internet.  For example, an email that allows users to unlock a user account by providing them with a secret code or a link that has a token contains a transaction authorization. A transaction authorization can be implemented with methods such as:

- A card that has a transaction authorization number
- A time-based one-time password (OTP) token, such as an [OATH TOTP (Time-based One-Time Password)](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
- A OTP sent by SMS or provided by phone
- A digital signature provided by a smart card or a smartphone
- A challenge-response token, including unconnected card readers or solutions which scan transaction data from the user's computer screen

Some of these forms of transaction authorizations can be implemented with a physical device or in a mobile application.

## 1. Functional Guidelines

### 1.1 Transaction authorization method has to allow a user to identify and acknowledge significant transaction data

Since developers cannot assume that a user's computer is secure, an external authorization component would be have to check data for a typical transaction.

When the developer builds components for transaction authorizations, they should use the *What You See Is What You Sign* principle. An authorization method must permit a user to identify and acknowledge the data that is significant to a given transaction. For example, in the case of a wire transfer, the user should be able to identify the target account and amount.

As developers determine what transaction data is significant, their decisions should be based on:

- The real risk
- The technical capabilities and constraints of the chosen authorization method
- The users having a positive experience

For example, if an SMS message confirms significant transaction data, the developer could respond by returning the target account, amount and type of transfer to the user. However, it is inconvenient for an unconnected [CAP reader](https://en.wikipedia.org/wiki/Chip_Authentication_Program) to require users to enter that data. In such cases, the developer should probably return the minimium amount of significant transaction data (e.g. partial target account number and amount) for confirmation.

In general, the user must verify all significant transaction data as a part of the transaction authorization process. If a transaction process requires a user to enter transaction data into an external device, the user should be prompted to confirm a specific value in the transaction (e.g. a target account number). The absence of a meaningful prompt could be easily abused by social engineering techniques and malware as described below in Section 1.4. Also, for more detailed discussion of input overloading problems, see [here](http://www.cl.cam.ac.uk/~sjm217/papers/fc09optimised.pdf).

### 1.2 Change of authorization token should be authorized using the current authorization token

If a user can use the application interface to change the authorization token, they should be able to authorize the operation with their current authorization credentials (as is the case with [password change procedure](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities.html)). For example: when a user changes a phone number for SMS codes an authorization SMS code should be sent to the current phone number.

### 1.3 Change of authorization method should be authorized using the current authorization method

Some applications allow a user to chose how their transactions will be authorized. In such cases, the developer should make sure that the application can confirm the user's method of authorization to prevent any malware from changing the user's authorization method to the most vulnerable method. Additionally, the application should inform the user about any potential dangers associated with their authorization method.

### 1.4 Users should be able to easily distinguish the authentication process from the transaction authorization process

Since developers need to prevent users from authorizing fraudulent operations, their applications should not require a user to perform the same actions for authentication and transaction authorization. Consider the following example:

1. An application is using the same method for user authentication and for transaction authorization {i.e. with an OTP token).
2. Malware could use a man-in-the-middle attack to present a user with a false error message when they submit credentials to the application, which could trick the user into repeating the authentication procedure. The first credential will be used by the malware for authentication and the second credential would be used to authorize a fraudulent transaction. Even challenge-response schemes could be abused using this scenario, since malware can present a challenge taken from a fraudulent transaction and trick the user to provide a response. Such an attack scenario is used widely in [malware attacks against electronic banking](http://securityintelligence.com/back-basics-malware-authors-downgrade-tactics-stay-radar/#.VX_qI_krLDc).

To stop such attacks, developers can make sure that authentication actions are different than transaction authorizations by:

- Using different methods to authenticate and to authorize
- Employing different actions in an external security component (i.e using a different mode of operation in a CAP reader)
- Presenting the user with a clear message about what they are "signing" (What You See Is What You Sign Principle)

Social engineering methods [can be used despite authentication and operation authorization methods](http://securityintelligence.com/tatanga-attack-exposes-chiptan-weaknesses/#.VZAy9PkrLDc) but the application shouldn't make it easier for such attack scenarios.

### 1.5 Each transaction should be authorized using unique authorization credentials

If applications only ask for transaction authorization credentials once (such as a static password, code sent through SMS, or a token response), the user could authorize any transaction during the entire session or reuse the same credentials when they need to authorize a transaction. In this scenario, attackers can employ malware to sniff credentials and use them to authorize any transaction without the user's knowledge.

## 2. Non-functional guidelines

### 2.1 Authorization should be performed and enforced server-side

Like [all other security controls](https://cwe.mitre.org/data/definitions/602.html), transaction authorizations should be enforced on the server side. It should **never** be possible to influence an authorization's result by altering the data that flows from a client to a server by:

- Tampering with parameters that contain transaction data
- Adding/removing parameters which will disable authorization check
- Causing an error

To ensure that data is only managed on the server side, security programming best practices should be applied, such as:

- [Default deny](https://wiki.owasp.org/index.php/Positive_security_model)
- Avoiding debugging functionality in production code

Other safeguards should be considered to prevent tampering, such as encrypting the data for confidentiality and integrity, then decrypting and verifying the data on the server side.

### 2.2 Authorization method should be enforced server-side

If multiple transaction authorization methods are made available to the user, the server side must make sure that the transaction occurs with the user's chosen authorization method or the authorization method enforced by application policies. Otherwise, malware could downgrade an authorization method to even the least secure authorization method. Developers must make it impossible for attackers to change a chosen authorization method by manipulating the parameters provided from the client.

Developers should be especially careful if they are asked to add a new authorization method that enhances security. Unfortunately, developers often decide to build a new authorization method on top of an old codebase. This case is insecure and an attacker could manipulate a client to successfully authorize a transaction by sending parameters using the old method, despite the fact that the application has already switched to a new method.

### 2.3 Transaction verification data should be generated server-side

If developers decide to transmit significant transaction data programmatically to an authorization component, they should take extra care to prevent any client modifications to the transaction data at authorization. **All significant transaction data must be verified by the user, generated and stored on a server, then passed to an authorization component without any possibility of tampering by the client.**

And when developers collect significant transaction data on the client side and pass it on to the server, malware could manipulate the data and show faked transaction data in an authorization component.

### 2.4 Application should prevent authorization credentials brute-forcing

**Developers must make sure that their application can't allow attackers to brute-force a transaction at the point where transaction authorization credentials are submitted to the server for verification. After a set number of failed authorization attempts, the entire transaction authorization process should be restarted.** Also, there are other methods to prevent brute-forcing and stop other automation-related techniques, see [OWASP Authentication Cheat Sheet](Authentication_Cheat_Sheet.md#prevent-brute-force-attacks).

### 2.5 Application should control which transaction state transitions are allowed

Transaction authorization is usually performed in multiple steps, e.g.:

1. The user enters the transaction data.
2. The user requests authorization from the application.
3. The application initializes an authorization mechanism.
4. The user verifies/confirms the transaction data.
5. The user responds with the authorization credentials.
6. The application validates authorization and executes a transaction.

**The developers must ensure that the business logic flow for a transaction authorization occurs in in sequential order so users (or attackers) cannot perform the steps out of order or even skip any of the steps. This should protect against attack techniques such as:

- Overwriting transaction data before user will enter the authorization credentials
- Skipping transaction authorization

 See [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) requirement **15.1**).

### 2.6 Transaction data should be protected against modification

Developers must not allow attackers to modify transaction data when the user enters the data for the first time. Poor implementations may allow malware to:

1. Replay the first step in Section 2.5 (sending transaction data) in the background before the user enters authorization credentials and then overwrite transaction details with a fraudulent transaction.
2. Create and add new transaction data parameters to a HTTP request that is authorizing the transaction. In such a case, a transaction authorization process that is poorly implemented might authorize the initial transaction and then execute a fraudulent transaction (specific example of [Time of Check to Time of Use vulnerability](https://cwe.mitre.org/data/definitions/367.html)).

There are multiple methods that can prevent transaction data from being modified during authorization:

1. If transaction data is modified, the code could invalidate any previously entered authorization data (e.g. Generated OTP) and the challenge.
2. Modifications to transaction data could trigger a reset of the authorization process.
3. Any attempt to modify transaction data after user entry is an attack on the system and it should be logged, monitored, and carefully investigated.

### 2.7 Confidentiality of transaction data should be protected during all client-server communications

The transaction authorization process should protect the privacy of transaction data that the user will be authorizing (i.e. at Section 2.5, steps 2 and 4).

### 2.8 System should check each transaction execution and make sure it has been properly authorized

The final result of the transaction entry and authorization process (as described in Section 2.5) is also called the *transaction execution*. There should be a final control gate before transaction execution which verifies whether the transaction was properly authorized by the user. This control should be tied to execution and prevent attacks such as:

- Time of Check to Time of Use (TOCTOU) – example in Section 2.6
- Skipping authorization check in the transaction entry process (see. Section 2.5)

### 2.9 Authorization credentials should only be valid during a limited time period

In some attacks, a user's authorization credentials are passed by malware to a command-and-control server and then are used from an attacker-controlled machine. Often, this process is often performed manually by an attacker. To make sure that these are attacks are difficult, the server should only allow transaction authorization to occur in a limited time window which should occur between the generation of a challenge (or OTP) and the completion of an authorization. Additionally, such safeguards will also help stop resource exhaustion attacks. This time period should be carefully selected so it will not disrupt normal user behavior.

### 2.10 Authorization credentials should be unique for every operation

To prevent multiple replay attacks, each set of authorization credentials should be unique for every operation. These credentials can be generated with different methods depending on the mechanism. For example: developers can use a timestamp, a sequence number, or a random value in signed transaction data or as a part of a challenge.

## Remarks

Here are some other issues that should be considered while implementing transaction authorizations, but are beyond the scope of this cheat sheet:

- Which transactions should be authorized? All transactions or only some of them? Each application is different and an application owner should decide if all transactions should be authorized or only some of them. The developers should consider risk analysis, risk exposition of given application, and other safeguards implemented in an application.
- **We recommend the use of cryptographic operations to protect transactions and to ensure integrity, confidentiality and non-repudiation.**
- **It is critically important to provision & protect the device signing keys during device "pairing" is as is the actual signing protocol itself. Malware may attempt to inject/replace or steal the signing keys.**
- User awareness: For example in transaction authorization methods, when a user types in significant transaction data to an authorization component (e.g. an external dedicated device or a mobile application), users should be trained to rewrite transaction data from a trusted source and not from a computer screen.
- **There are some anti-malware solutions that protect against such threats but these solutions [cannot be 100% effective](http://www.securing.pl/en/script-based-malware-detection-in-online-banking-security-overview/index.html) and should be used only as an additional layer of protection.**
- Protecting your signing keys with a second factor such as passwords, biometrics, etc. or leveraging secure elements (TEE, TPM, Smart card).

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
- Arjan Blom , Gerhard de Koning Gans , Erik Poll , Joeri de Ruiter , and Roel Verdult: [Designed to Fail - A USB-Connected Reader for Online Banking](http://www.cs.ru.nl/~rverdult/Designed_to_Fail_A_USB-Connected_Reader_for_Online_Banking-NORDSEC_2012.pdf)
