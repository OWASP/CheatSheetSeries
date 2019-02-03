# Introduction

[Credential stuffing](https://www.owasp.org/index.php/Credential_stuffing) is the automated injection of breached username/password pairs (typically from other sites) in order to identify accounts on the target system that use the same credentials. 

This is a subset of the brute force attack category: large numbers of spilled credentials are automatically entered into websites looking for matches to existing accounts, which the attacker can then hijack for their own purposes.

# Primary Defenses

It should be noted that defense mechanisms are intended to be used in a layered approach. In most cases, a single defense option would be inadequate to stop most Credential Stuffing attacks.

In many cases, brute force protections will overlap with credential stuffing defenses.

## Defense Option 1: Multi-Factor Authentication

True multi-factor authentication is the best defense against Credential Stuffing attacks, but can have significant deployment and usability impacts, and so is frequently not a feasible option. If this defense is not feasible for your application, consider adopting as many of these other defenses as you can.

## Defense Option 2: Multi-Step Login Process

*Most of the automated account validation we've seen is using single step validation and checking for a success conditions. By forcing the client to render the response and include that in the next request (and including [Synchronizer (CSRF) Tokens](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)), we are just eliminating the basic attempts. It's not comprehensive.*

## Defense Option 3: IP blacklists

Because the attacker requests will likely originate from a few (or one) IP, addresses attempting to log into multiple accounts can be blocked or sandboxed.

Further, login monitoring with IP tracking could be used to eliminate (most) false positives. Use the last several IPs that the user's account logged in from and compare them to the suspected "bad" IP.

Making the IP bans temporary, say 15 minutes, would reduce the negative impact to the customer and business services (who would have to fix false positives) significantly.

## Defense Option 4: Device Fingerprinting

By running some simple JavaScript device information collections, you can learn certain things about the device(s) used to log into each account. If a `Windows(OS)/English(Language)/Chrome(Browser)` device logged in the last 5 times, and we have a new geolocation source with `Linux/FireFox/Spanish`, then we can be pretty certain that the user is not the original one (other options include time zones, last login times, user agents, plugins version, flash, etc).

The most simple implementation, while minimizing reduction in effectiveness, would be **Operating System + Geolocation + Language**.

How you deal with mismatches is also a major consideration. If you are performing complex device fingerprinting, using many variables, then more severe actions might be taken, such as locking the account.

Using simple fingerprinting, with maybe 2 or 3 variables would require that less stringent actions be taken, due to it's higher likelihood of a false positive. In this case, maybe the source IP is blocked if it attempts more than 3 user IDs.

## Defense Option 5: Disallow Email Addresses as User IDs

In many cases, credential reuse is an issue because user IDs are the same on multiple sites. In most cases, they are the email address of the user, for usability. This is an obvious problem when considering Credential Stuffing. One possible approach is to avoid use of email addresses as userids. Not using email addresses as userids also helps prevent spearfishing attacks against such users, because the email associated with the user account is far less obvious.

# References

- [OWASP Credential Stuffing Article](https://www.owasp.org/index.php/Credential_stuffing)
- [OWASP Automated Threats to Web Applications](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)
- Project: [OAT-008 Credential Stuffing](https://www.owasp.org/index.php/OAT-008_Credential_Stuffing), which is one of 20 defined threats in the [OWASP Automated Threat Handbook](https://www.owasp.org/index.php/File:Automated-threat-handbook.pdf) this project produced.

# Authors and Primary Editors

Brad Causey