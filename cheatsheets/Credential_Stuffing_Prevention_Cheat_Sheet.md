# Introduction

[Credential stuffing](https://www.owasp.org/index.php/Credential_stuffing) is the automated injection of breached username/password pairs (typically from other sites) in order to identify accounts on the target system that use the same credentials. 

This is a subset of the brute force attack category: large numbers of spilled credentials are automatically entered into websites looking for matches to existing accounts, which the attacker can then hijack for their own purposes.

# Primary Defenses

It should be noted that defense mechanisms are intended to be used in a layered approach. In most cases, a single defense option would be inadequate to stop most Credential Stuffing attacks.

In many cases, brute force protections will overlap with credential stuffing defenses.

Keep in mind that application can have different security levels for different users/roles or actions. For example for casual customers multi-factor authentication may be optional but for admins or some other special roles it should be enforced.

## Defense Option 1: Multi-Factor Authentication

True multi-factor authentication is the best defense against Credential Stuffing attacks, but can have significant deployment and usability impacts, and so is frequently not a feasible option. If this defense is not feasible for your application, consider adopting as many of these other defenses as you can.

In order to balance security and usability, multi-factor authentication can be combined with other techniques to ask for 2nd factor only in special situations. For example, it can be combined with [device fingerprinting](cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md#defense-option-4-device-fingerprinting), in that scenario, the application can ask for a 2nd factor only when the application is accessed by an unknown, new browser. Similary, cookies can also be used for remembering known browsers or the application can ask about another factor based on the login success ratio, IP address (like users from different network than company one like remote workers) etc.

## Defence Option 2: Use a CAPTCHA

Similar to Multi-Factor Authentication this defence can be combined with other techniques to ask user to solve CAPTCHA only in special situations. 

Lots of CAPTCHA examples can be reviewed [here](https://www.whoishostingthis.com/resources/captcha/)

## Defense Option 3: IP blacklists

Because the attacker requests will likely originate from a few (or one) IP, addresses attempting to log into multiple accounts can be blocked or sandboxed.

Further, login monitoring with IP tracking could be used to eliminate (most) false positives. Use the last several IPs that the user's account logged in from and compare them to the suspected "bad" IP.

Making the IP bans temporary, say 15 minutes, would reduce the negative impact to the customer and business services (who would have to fix false positives) significantly.

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

Application can check whether passwords used by users were previously or recently exposed in data breaches. After check application can either notify user about it or force changing password to new one. Trustworthy, big and updated data source for such password is Troy Hunt’s service - [Pwned Passwords](https://haveibeenpwned.com/Passwords). You can host it yourself or use [API](https://haveibeenpwned.com/API/v2#PwnedPasswords). 
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