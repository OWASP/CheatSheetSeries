# Email Security Cheat Sheet

## Security of Email as an Authentication Channel

Many authentication and account recovery workflows rely on email delivery to verify user identity, including password resets, account activation, and email address changes. When email is used in this way, it becomes part of the authentication trust boundary and should be treated as a security-critical component.

Applications implicitly assume that:

- Email messages are delivered only to the legitimate mailbox owner  
- The sender domain cannot be spoofed  
- Attackers cannot impersonate the application by sending fraudulent messages  

To support these assumptions, organizations should implement and enforce modern email authentication controls on all domains used for transactional or security-related email:

- **SPF (Sender Policy Framework)** to restrict which mail servers are authorized to send on behalf of the domain  
- **DKIM (DomainKeys Identified Mail)** to cryptographically sign outbound messages and ensure message integrity  
- **DMARC (Domain-based Message Authentication, Reporting and Conformance)** to define enforcement policy and prevent unauthenticated or spoofed messages from being delivered  

Domains used for authentication or account recovery email should publish a DMARC policy with enforcement (`p=quarantine` or `p=reject`). Without DMARC enforcement, attackers may be able to spoof messages that appear to originate from the application, weakening all email-based authentication workflows and increasing exposure to phishing and account takeover.

Email authentication mechanisms are not only deliverability controls; they are security controls that directly affect the integrity of identity verification processes.
