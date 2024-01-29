# User Privacy Protection Cheat Sheet

## Introduction

This OWASP Cheat Sheet introduces mitigation methods that web developers may utilize in order to protect their users from a vast array of potential threats and aggressions that might try to undermine their privacy and anonymity. This cheat sheet focuses on privacy and anonymity threats that users might face by using online services, especially in contexts such as social networking and communication platforms.

## Guidelines

### Strong Cryptography

Any online platform that handles user identities, private information or communications must be secured with the use of strong cryptography. User communications must be encrypted in transit and storage. User secrets such as passwords must also be protected using strong, collision-resistant hashing algorithms with increasing work factors, in order to greatly mitigate the risks of exposed credentials as well as proper integrity control.

To protect data in transit, developers must use and adhere to TLS/SSL best practices such as verified certificates, adequately protected private keys, usage of strong ciphers only, informative and clear warnings to users, as well as sufficient key lengths. Private data must be encrypted in storage using keys with sufficient lengths and under strict access conditions, both technical and procedural. User credentials must be hashed regardless of whether or not they are encrypted in storage.

For detailed guides about strong cryptography and best practices, read the following OWASP references:

1. [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md).
2. [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md).
3. [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md).
4. [Guide to Cryptography](https://wiki.owasp.org/index.php/Guide_to_Cryptography).
5. [Testing for TLS/SSL](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection.html).

### Support HTTP Strict Transport Security

HTTP Strict Transport Security (HSTS) is an HTTP header set by the server indicating to the user agent that only secure (HTTPS) connections are accepted, prompting the user agent to change all insecure HTTP links to HTTPS, and forcing the compliant user agent to fail-safe by refusing any TLS/SSL connection that is not trusted by the user.

HSTS has average support on popular user agents, such as Mozilla Firefox and Google Chrome. Nevertheless, it remains very useful for users who are in consistent fear of spying and Man in the Middle Attacks.

If it is impractical to force HSTS on all users, web developers should at least give users the choice to enable it if they wish to make use of it.

For more details regarding HSTS, please visit:

1. [HTTP Strict Transport Security in Wikipedia](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security).
2. [IETF for HSTS RFC](https://tools.ietf.org/html/rfc6797).
3. [OWASP Appsec Tutorial Series - Episode 4: Strict Transport Security](http://www.youtube.com/watch?v=zEV3HOuM_Vw).

### Digital Certificate Pinning

Certificate Pinning is the practice of hardcoding or storing a predefined set of information (usually hashes) for digital certificates/public keys in the user agent (be it web browser, mobile app or browser plugin) such that only the predefined certificates/public keys are used for secure communication, and all others will fail, even if the user trusted (implicitly or explicitly) the other certificates/public keys.

Some advantages for pinning are:

- In the event of a CA compromise, in which a compromised CA trusted by a user can issue certificates for any domain, allowing evil perpetrators to eavesdrop on users.
- In environments where users are forced to accept a potentially-malicious root CA, such as corporate environments or national PKI schemes.
- In applications where the target demographic may not understand certificate warnings, and is likely to just allow any invalid certificate.

For details regarding certificate pinning, please refer to the following:

1. [OWASP Certificate Pinning Cheat Sheet](Pinning_Cheat_Sheet.md).
2. [Public Key Pinning Extension for HTTP RFC](https://tools.ietf.org/html/rfc7469).
3. [Securing the SSL channel against man-in-the-middle attacks: Future technologies - HTTP Strict Transport Security and Pinning of Certs, by Tobias Gondrom](https://owasp.org/www-pdf-archive/OWASP_defending-MITMA_APAC2012.pdf).

### Panic Modes

A panic mode is a mode that threatened users can refer to when they fall under direct threat to disclose account credentials.

Giving users the ability to create a panic mode can help them survive these threats, especially in tumultuous regions around the world. Unfortunately many users around the world are subject to types of threats that most web developers do not know of or take into account.

Examples of panic modes are modes where distressed users can delete their data upon threat, log into fake inboxes/accounts/systems, or invoke triggers to backup/upload/hide sensitive data.

The appropriate panic mode to implement differs depending on the application type. A disk encryption software such as VeraCrypt might implement a panic mode that starts up a fake system partition if the user entered their distressed password.

Email providers might implement a panic mode that hides predefined sensitive emails or contacts, allowing reading innocent email messages only, usually as defined by the user, while preventing the panic mode from overtaking the actual account.

An important note about panic modes is that they must not be easily discoverable, if at all. An adversary inside a victim's panic mode must not have any way, or as few possibilities as possible, of finding out the truth. This means that once inside a panic mode, most non-sensitive normal operations must be allowed to continue (such as sending or receiving email), and that further panic modes must be possible to create from inside the original panic mode (If the adversary tried to create a panic mode on a victim's panic mode and failed, the adversary would know they were already inside a panic mode, and might attempt to hurt the victim).

Another solution would be to prevent panic modes from being generated from the user account, and instead making it a bit harder to spoof by adversaries. For example it could be only created Out Of Band, and adversaries must have no way to know a panic mode already exists for that particular account.

The implementation of a panic mode must always aim to confuse adversaries and prevent them from reaching the actual accounts/sensitive data of the victim, as well as prevent the discovery of any existing panic modes for a particular account.

For more details regarding VeraCrypt's hidden operating system mode, please refer to:

- [VeraCrypt Hidden Operating System](https://www.veracrypt.fr/en/Hidden%20Operating%20System.html).

### Remote Session Invalidation

In case user equipment is lost, stolen or confiscated, or under suspicion of cookie theft; it might be very beneficial for users to able to see view their current online sessions and disconnect/invalidate any suspicious lingering sessions, especially ones that belong to stolen or confiscated devices. Remote session invalidation can also helps if a user suspects that their session details were stolen in a Man-in-the-Middle attack.

For details regarding session management, please refer to:

- [OWASP Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md).

### Allow Connections from Anonymity Networks

Anonymity networks, such as the Tor Project, give users in tumultuous regions around the world a golden chance to escape surveillance, access information or break censorship barriers. More often than not, activists in troubled regions use such networks to report injustice or send uncensored information to the rest of the world, especially mediums such as social networks, media streaming websites and email providers.

Web developers and network administrators must pursue every avenue to enable users to access services from behind such networks, and any policy made against such anonymity networks need to be carefully re-evaluated with respect to impact on people around the world.

If possible, application developers should try to integrate or enable easy coupling of their applications with these anonymity networks, such as supporting SOCKS proxies or integration libraries (e.g. OnionKit for Android).

For more information about anonymity networks, and the user protections they provide, please refer to:

1. [The Tor Project](https://www.torproject.org).
2. [I2P Network](http://www.i2p2.de).
3. [OnionKit: Boost Network Security and Encryption in your Android Apps](https://github.com/guardianproject/OnionKit).

### Prevent IP Address Leakage

Preventing leakage of user IP addresses is of great significance when user protection is in scope. Any application that hosts external third-party content, such as avatars, signatures or photo attachments; must take into account the benefits of allowing users to block third-party content from being loaded in the application page.

If it was possible to embed 3rd-party, external domain images, for example, in a user's feed or timeline; an adversary might use it to discover a victim's real IP address by hosting it on his domain and watch for HTTP requests for that image.

Many web applications need user content to operate, and this is completely acceptable as a business process; however web developers are advised to consider giving users the option of blocking external content as a precaution. This applies mainly to social networks and forums, but can also apply to web-based e-mail, where images can be embedded in HTML-formatted emails.

A similar issue exists in HTML-formatted emails that contain third-party images, however most email clients and providers block loading of third-party content by default; giving users better privacy and anonymity protection.

### Honesty & Transparency

If the web application cannot provide enough legal or political protections to the user, or if the web application cannot prevent misuse or disclosure of sensitive information such as logs, the truth must be told to the users in a clear understandable form, so that users can make an educated choice about whether or not they should use that particular service.

If it doesn't violate the law, inform users if their information is being requested for removal or investigation by external entities.

Honesty goes a long way towards cultivating a culture of trust between a web application and its users, and it allows many users around the world to weigh their options carefully, preventing harm to users in various contrasting regions around the world.

More insight regarding secure logging can be found at:

- [OWASP Logging Cheat Sheet](Logging_Cheat_Sheet.md)
