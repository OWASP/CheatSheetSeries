# Credential Stuffing Prevention Cheat Sheet

## Introduction

This cheatsheet covers defences against two common types of authentication-related attacks: credential stuffing and password spraying. Although these are separate, distinct attacks, in many cases the defences that would be implemented to protect against them are the same, and they would also be effective at protecting against brute-force attacks.  A summary of these different attacks is listed below:

| Attack Type | Description |
|-------------|-------------|
| Brute Force | Testing multiple passwords from dictionary or other source against a single account. |
| Credential Stuffing | Testing username/password pairs obtained from the breach of another site. |
| Password Spraying | Testing a single weak password against a large number of different accounts.|

## Multi-Factor Authentication

[Multi-factor authentication (MFA)](Multifactor_Authentication_Cheat_Sheet.md) is by far the best defense against the majority of password-related attacks, including credential stuffing and password spraying, with analysis by Microsoft suggesting that it would have stopped [99.9% of account compromises](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984). As such, it should be implemented wherever possible. Historically, depending on the audience of the application, it may not have been practical or feasible to enforce the use of MFA, however with modern browsers and mobile devices now supporting FIDO2 Passkeys and other forms of MFA, it is attainable for most use cases.

In order to balance security and usability, multi-factor authentication can be combined with other techniques to require the 2nd factor only in specific circumstances where there is reason to suspect that the login attempt may not be legitimate, such as a login from:

- A new browser/device or IP address.
- An unusual country or location.
- Specific countries that are considered untrusted or typically do not contain users of a service.
- An IP address that appears on known denylists or is associated with anonymization services, such as proxy or VPN services.
- An IP address that has tried to login to multiple accounts.
- A login attempt that appears to be scripted or from a bot rather than a human (i.e. large login volume sourced from a single IP or subnet).

Or an organization may choose to require MFA in the form of a "step-up" authentication for the above scenarios during a session combined with a request for a high risk activity such as:

- Large currency transactions
- Privileged or Administrative configuration changes

Additionally, for enterprise applications, known trusted IP ranges could be added to an allowlist so that MFA is not required when users connect from these ranges.

## Alternative Defenses

Where it is not possible to implement MFA, there are many alternative defenses that can be used to protect against credential stuffing and password spraying. In isolation none of these are as effective as MFA, however multiple, layered defenses can provide a reasonable degree of protection. In many cases, these mechanisms will also protect against brute-force or password spraying attacks.

Where an application has multiple user roles, it may be appropriate to implement different defenses for different roles. For example, it may not be feasible to enforce MFA for all users, but it should be possible to require that all administrators use it.

## Defense in Depth & Metrics

While not a specific technique, it is important to implement defenses that consider the impact of individual defenses being defeated or otherwise failing.  As an example, client-side defenses, such as device fingerprinting or JavaScript challenges, may be spoofed or bypassed and other layers of defense should be implemented to account for this.

Additionally, each defense should generate volume metrics for use as a detective mechanism. Ideally the metrics will include both detected and mitigated attack volume and allow for filtering on fields such as IP address.  Monitoring and reporting on these metrics may identify defense failures or the presence of unidentified attacks, as well as the impact of new or improved defenses.

Finally, when administration of different defenses is performed by multiple teams, care should be taken to ensure there is communication and coordination when separate teams are performing maintenance, deployment or otherwise modifying individual defenses.

### Secondary Passwords, PINs and Security Questions

As well as requiring a user to enter their password when authenticating, users can also be prompted to provide additional security information such as:

- A PIN
- Specific characters from a secondary passwords or memorable word
- Answers to [security questions](Choosing_and_Using_Security_Questions_Cheat_Sheet.md)

It must be emphasised that this **does not** constitute multi-factor authentication (as both factors are the same - something you know). However, it can still provide a useful layer of protection against both credential stuffing and password spraying where proper MFA can't be implemented.

### CAPTCHA

Requiring a user to solve a "Completely Automated Public Turing test to tell Computers and Humans Apart" (CAPTCHA) or similar puzzle for each login attempt can help to identify automated/bot attacks and help prevent automated login attempts, and may slow down credential stuffing or password spraying attacks.  However, CAPTCHAs are not perfect, and in many cases tools or services exist that can be used to break them with a reasonably high success rate.  Monitoring CAPTCHA solve rates may help identify impact to good users, as well as automated CAPTCHA breaking technology, possibly indicated by abnormally high solve rates.

To improve usability, it may be desirable to only require the user solve a CAPTCHA when the login request is considered suspicious or high risk, using the same criteria discussed in the MFA section.

### IP Mitigation and Intelligence

Blocking IP addresses may be sufficent to stop less sophisticated attacks, but should not be used as the primary defense due to the ease in circumvention.  It is more effective to have a graduated response to abuse that leverages multiple defensive measures depending on different factors of the attack.

Any process or decision to mitigate (including blocking and CAPTCHA) credential stuffing traffic from an IP address should consider a multitude of abuse scenarios, and not rely on a single predictable volume limit.  Short (i.e. burst) and long time periods should be considered, as well as high request volume and instances where one IP address, likely in concert with _many_ other IP addresses, generates low but consistent volumes of traffic.  Additionally, mitigation decisions should consider factors such as IP address classification (ex: residential vs hosting) and geolocation.  These factors may be leveraged to raise or lower mitigation thresholds in order to reduce potential impact on legitimate users or more aggresively mitigate abuse originating from abnormal sources.  Mitigations, especially blocking an IP address, should be temporary and processes should be in place to remove an IP address from a mitigated state as abuse declines or stops.

Many credential stuffing toolkits, such as [Sentry MBA](https://federalnewsnetwork.com/wp-content/uploads/2020/06/Shape-Threat-Research-Automating-Cybercrime-with-SentryMBA.pdf), offer built-in use of proxy networks to distribute requests across a large volume of unique IP addressess.  This may defeat both IP block-lists and rate limiting, as per IP request volume may remain relatively low, even on high volume attacks.  Correlating authentication traffic with proxy and similar IP address intelligence, as well as hosting provider IP address ranges can help identify highly distributed credential stuffing attacks, as well as serve as a mitigation trigger.  For example, every request originating from a hosting provider could be required to solve CAPTCHA.

There are both public and commercial sources of IP address intelligence and classification that may be leveraged as data sources for this purpose.  Additionally, some hosting providers publish their own IP address space, such as [AWS](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html).

Separate from blocking network connections, consider storing an account's IP address authentication history.  In case a recent IP address is added to a block or mitigation list, it may be appropriate to lock the account and notify the user.

### Device Fingerprinting

Aside from the IP address, there are a number of different factors that can be used to attempt to fingerprint a device. Some of these can be obtained passively by the server from the HTTP headers (particularly the "User-Agent" header), including:

- Operating system & version
- Browser & version
- Language

Using JavaScript it is possible to access far more information, such as:

- Screen resolution
- Installed fonts
- Installed browser plugins

Using these various attributes, it is possible to create a fingerprint of the device. This fingerprint can then be matched against any browser attempting to login to the account, and if it doesn't match then the user can be prompted for additional authentication. Many users will have multiple devices or browsers that they use, so it is not practical to simply block attempts that do not match the existing fingerprints, however it is common to define a process for users or customers to view their device history and manage their remembered devices.  Also these attributes can be used to detect anomalous activity such as a device appearing to be running an older version of OS or Browser.

The [fingerprintjs2](https://github.com/Valve/fingerprintjs2) JavaScript library can be used to carry out client-side fingerprinting.

It should be noted that as all this information is provided by the client, it can potentially be spoofed by an attacker. In some cases spoofing these attributes is trivial (such as the "User-Agent") header, but in other cases it may be more difficult to modify these attributes.

### Connection Fingerprinting

Similar to device fingerprinting, there are numerous fingerprinting techniques available for network connections.  Some examples include [JA3](https://github.com/salesforce/ja3), HTTP/2 fingerprinting and HTTP header order.  As these techniques typically focus on how a connection is made, connection fingerprinting may provide more accurate results than other defenses that rely on an indicator, such as an IP address, or request data, such as user agent string.

Connection fingerprinting may also be used in conjunction with other defenses to ascertain the truthfulness of an authentication request.  For example, if the user agent header and device fingerprint indicates a mobile device, but the connection fingerprint indicates a Python script, the request is likely suspect.

### Require Unpredictable Usernames

Credential stuffing attacks rely on not just the re-use of passwords between multiple sites, but also the re-use of usernames. A significant number of websites use the email address as the username, and as most users will have a single email address they use for all their accounts, this makes the combination of an email address and password very effective for credential stuffing attacks.

Requiring users to create their own username when registering on the website makes it harder for an attacker to obtain valid username and password pairs for credential stuffing, as many of the available credential lists only include email addresses. Providing the user with a generated username can provide a higher degree of protection (as users are likely to choose the same username on most websites), but is user unfriendly. Additionally, care needs to be taken to ensure that the generated username is not predictable (such as being based on the user's full name, or sequential numeric IDs), as this could make enumerating valid usernames for a password spraying attack easier.

### Multi-Step Login Processes

The majority of off-the-shelf tools are designed for a single step login process, where the credentials are POSTed to the server, and the response indicates whether or not the login attempt was successful. By adding additional steps to this process, such as requiring the username and password to be entered sequentially, or requiring that the user first obtains a random [CSRF Token](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) before they can login, this makes the attack slightly more difficult to perform, and doubles the number of requests that the attacker must make.

Multi-step login processes, however, should be mindful that they do not faciliate [user enumeration](Authentication_Cheat_Sheet.md).  Enumerating users prior to a credential stuffing attack may result in a harder to identify, lower request volume attack.

### Require JavaScript and Block Headless Browsers

Most tools used for these types of attacks will make direct POST requests to the server and read the responses, but will not download or execute JavaScript that was contained in them. By requiring the attacker to evaluate JavaScript in the response (for example to generate a valid token that must be submitted with the request), this forces the attacker to either use a real browser with an automation framework like Selenium or Headless Chrome, or to implement JavaScript parsing with another tool such as PhantomJS. Additionally, there are a number of techniques that can be used to identify [Headless Chrome](https://antoinevastel.com/bot%20detection/2018/01/17/detect-chrome-headless-v2.html) or [PhantomJS](https://blog.shapesecurity.com/2015/01/22/detecting-phantomjs-based-visitors/).

Please note that blocking visitors who have JavaScript disabled will reduce the accessibility of the website, especially to visitors who use screen readers. In certain jurisdictions this may be in breach of equalities legislation.

### Degredation

A more aggresive defense against credential stuffing is to implement measures that increase the amount of time the attack takes to complete.  This may include incrementally increasing the complexity of the JavaScript that must be evaluated, introducing long wait periods before responding to requests, returning overly large HTML assets or returning randomized error messages.

Due to their potential negative impact on legitimate users, great care must be taken with this type of defense, though it may be needed in order to mitigate more sophisticated credential stuffing attacks.

### Identifying Leaked Passwords

[ASVS v4.0 Password Security Requirements](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md#v21-password-security-requirements) provision (2.1.7) on verifying new passwords presence in breached password datasets should be implemented.

There are both commercial and free services that may be of use for validating passwords presence in prior breaches.  A well known free service for this is [Pwned Passwords](https://haveibeenpwned.com/Passwords). You can host a copy of the application yourself, or use the [API](https://haveibeenpwned.com/API/v2#PwnedPasswords).

### Notify users about unusual security events

When suspicious or unusual activity is detected, it may be appropriate to notify or warn the user. However, care should be taken that the user does not get overwhelmed with a large number of notifications that are not important to them, or they will just start to ignore or delete them.  Additionally, due to frequent reuse of passwords across multiple sites, the possibility that the users email account has also been compromised should be considered.

For example, it would generally not be appropriate to notify a user that there had been an attempt to login to their account with an incorrect password. However, if there had been a login with the correct password, but which had then failed the subsequent MFA check, the user should be notified so that they can change their password.  Subsequently, should the user request multiple password resets from different devices or IP addresses, it may be appropriate to prevent further access to the account pending further user verification processes.

Details related to current or recent logins should also be made visible to the user. For example, when they login to the application, the date, time and location of their previous login attempt could be displayed to them. Additionally, if the application supports concurrent sessions, the user should be able to view a list of all active sessions, and to terminate any other sessions that are not legitimate.

## References

- [OWASP Credential Stuffing Article](https://owasp.org/www-community/attacks/Credential_stuffing)
- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- Project: [OAT-008 Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing), which is one of 20 defined threats in the [OWASP Automated Threat Handbook](https://owasp.org/www-pdf-archive/Automated-threat-handbook.pdf) this project produced.
