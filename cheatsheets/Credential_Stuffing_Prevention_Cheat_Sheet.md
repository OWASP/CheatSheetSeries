# Introduction

[Credential stuffing](https://www.owasp.org/index.php/Credential_stuffing) is the automated testing of breached username/password pairs (typically from other sites) in order to identify accounts on the target system that use the same credentials. 

This is different from a brute-force attack (where a large number of passwords are tried against a single user) or a password spraying attack (where a few weak passwords are tried against a large number of users). 

# Multi-Factor Authentication
Multi-factor authentication (MFA) is by far the best defense against the majority of password-related attacking, including credential stuffing attacks. It should be implemented wherever possible; however depending on the audience of the application it may not be practical or feasible to enforce the use of MFA. 

In order to balance security and usability, multi-factor authentication can be combined with other techniques to require for 2nd factor only in specific circumstances where there is reason to suspect that the login attempt may not be legitimate, such as a login from:

- A new browser/device or IP address.
- An unusual country or location.
- Specific countries that are considered untrusted.
- An IP address that appears on known blacklists.
- An IP address that has tried to login to multiple accounts.
- A login attempt that appears to be scripted rather than manual.

Additionally, for enterprise applications, known trusted IP ranges could be added to a whitelist so that MFA is not required when users connect from these ranges.

# Alternative Defenses

Where it is not possible to implement MFA, there are a number of alternative defenses that can be used to protect against credential stuffing. In isolation none of these are as effective as MFA, however if multiple defenses are implemented in a layered approach, they can provide a reasonable degree of protection. In many cases, these mechanisms will also protect against brute-force or password spraying attacks.

Where an application has multiple user roles, it may be appropraite to implement difference defenses for different roles. For example, it may not be feasible to enforce MFA for all users, but it should be possible to require that all administrators use it.

## CAPTCHA

Requiring a user to solve a CAPTCHA for each login attempt can help to preven tautomated login attemps, which would significantly slow down a credential stuffing attack. However, CAPTCHAs are not perfect, and in many cases tools exist that can be used to break them with a reasonably high success rate.

To improve usability, it may be desirable to only require the user solve a CAPTCHA when the login request is considered suspicious, using the same criteria discussed above.

## IP Blacklisting

Less sophisticated attacks will often use a relatively small number of IP addresses, which can be blacklisted after a number of failed login attempts. These failures should be tracked separately to the per-user failures, which are intended to protect against brute-force attacks. The blacklist should be temporary, in order to reduce the likelihood of permenantly blocking legitimate users.

Additionally, there are a number of publicly available blacklists of known bad IP addresses which are collected by websites such as [AbuseIPDB](https://www.abuseipdb.com) based on abuse reports from users. 

Consider storing the last IP address which successfully logged in to each account, and if this IP address is added to a blacklist, then taking appropriate action such as locking the account and notifying the user, as it likely that their account has been compromised.

## Defense Option 4: Device Fingerprinting

By running some simple JavaScript device information collections, you can learn certain things about the device(s) used to log into each account. If a `Windows(OS)/English(Language)/Chrome(Browser)` device logged in the last 5 times, and we have a new geolocation source with `Linux/FireFox/Spanish`, then we can be pretty certain that the user is not the original one (other options include time zones, last login times, user agents, plugins version, flash, etc).

The most simple implementation, while minimizing reduction in effectiveness, would be **Operating System + Geolocation + Language**.

How you deal with mismatches is also a major consideration. If you are performing complex device fingerprinting, using many variables, then more severe actions might be taken, such as locking the account.

Using simple fingerprinting, with maybe 2 or 3 variables would require that less stringent actions be taken, due to it's higher likelihood of a false positive. In this case, maybe the source IP is blocked if it attempts more than 3 user IDs.

Example library that can be used is [fingerprintjs2](https://github.com/Valve/fingerprintjs2)

## Defense Option 5: Disallow Email Addresses as User IDs

In many cases, credential reuse is an issue because user IDs are the same on multiple sites. In most cases, they are the email address of the user, for usability. This is an obvious problem when considering Credential Stuffing. One possible approach is to avoid use of email addresses as userids. Not using email addresses as userids also helps prevent spearfishing attacks against such users, because the email associated with the user account is far less obvious.

# Secondary Defenses

These techniques are, in most cases, only slowing the attacker down. If the credential stuffing is a serious threat to you, they can buy you some time to defend against ongoing attacks. They can be also useful, against opportunistic attackers, who use standard tools and probably will choose easier targets to attack.

## Multi-Step Login Process

*Most of the automated account validation we've seen is using single step validation and checking for a success conditions. By forcing the client to render the response and include that in the next request (and including [Synchronizer (CSRF) Tokens](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)), we are just eliminating the basic attempts. It's not comprehensive.*

## Require JavaScript and/or block headless browsers

Requiring JavaScript will increase cost of attack because attacker have to run real browser.
Blocking headless browsers is another step after requiring javascript to block browsers similar to PhantomJS or Headless Chrome. To detect such browsers application should check JavaScript properties that are used in these browsers like:
`navigator.webdriver`, `window._phantom`, `window.callPhantom` and user-agents `PhantomJS`, `HeadlessChrome`.

## Pwned Passwords

Application can check whether passwords used by users were previously or recently exposed in data breaches. After check application can either notify user about it or force changing password to new one. Trustworthy, big and updated data source for such password is Troy Hunt's service - [Pwned Passwords](https://haveibeenpwned.com/Passwords). You can host it yourself or use [API](https://haveibeenpwned.com/API/v2#PwnedPasswords). 
In order to protect the value of the source password being searched for, Pwned Passwords implements a [k-Anonymity model](https://en.wikipedia.org/wiki/K-anonymity) that allows a password to be searched for by partial hash. This allows the first 5 characters of a SHA-1 password hash to be passed to the API.

Remember that you should have access to passwords only just after user log-in or register new account (after that passwords will be stored in [hashed form](cheatsheets/Password_Storage_Cheat_Sheet.md#leverage-an-adaptive-one-way-function)). This is the only one place, where you can check if password was leaked. Make sure that you do not log or store plaintext password during this operation.

## Notify users about unusual security events 

Many applications sends notification to their users about unusual security events like: password change, e-mail change, login from new browser, high number of unsuccessful logins etc. This notifications are useful because it allows users to verify and take actions themselves e.g. change password, invalidate sessions or contact your support if the action was really malicious. It will help you spot the real issue and allow you to defend user.

There is also a risk associated with such notifications, if your customers will receive a lot of such messages with false positives or if they don't understand the message it may cause more harm than good.

You may go further and create full webpage with recent security events.

# References

- [OWASP Credential Stuffing Article](https://www.owasp.org/index.php/Credential_stuffing)
- [OWASP Automated Threats to Web Applications](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)
- Project: [OAT-008 Credential Stuffing](https://www.owasp.org/index.php/OAT-008_Credential_Stuffing), which is one of 20 defined threats in the [OWASP Automated Threat Handbook](https://www.owasp.org/index.php/File:Automated-threat-handbook.pdf) this project produced.
