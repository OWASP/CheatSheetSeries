# Subdomain Takeover Prevention Cheat Sheet

## Introduction

Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists. An attacker can claim the orphaned resource and serve arbitrary content on the victim's subdomain.

This vulnerability is consistently among the most reported findings in bug bounty programs. Despite being well understood, it remains prevalent because it is fundamentally an operational problem: teams create DNS records when spinning up services but rarely have processes to clean them up during decommissioning.

The impact extends far beyond serving a defacement page. An attacker controlling a subdomain can:

- **Steal session cookies** scoped to the parent domain (e.g., cookies set on `.example.com` are sent to `attacker-controlled.example.com`)
- **Bypass Content Security Policy** rules that trust wildcard subdomains (`*.example.com`)
- **Host convincing phishing pages** on a domain the organization's users and customers already trust
- **Compromise OAuth and SSO flows** that whitelist the subdomain as a valid redirect URI
- **Obtain valid TLS certificates** for the subdomain from Certificate Authorities that use HTTP or email-based domain validation
- **Receive email** addressed to the subdomain if MX records are involved, enabling password resets or account verification on third-party services

This cheat sheet provides practical guidance for developers, DevOps engineers, and infrastructure teams to prevent subdomain takeovers, detect dangling records before attackers do, and respond effectively when they are discovered.

## How Subdomain Takeover Works

### The Basic Mechanism

1. An organization creates a DNS record: `blog.example.com CNAME example-blog.herokuapp.com`
2. The Heroku app serves content on `blog.example.com`
3. Months later, the team decommissions the Heroku app but forgets to remove the DNS record
4. The CNAME still points to `example-blog.herokuapp.com`, which no longer exists
5. An attacker creates a new Heroku app with the name `example-blog` and claims the hostname
6. The attacker now controls what is served on `blog.example.com`

### Why It Keeps Happening

The root cause is almost always a disconnect between infrastructure provisioning and DNS management:

- **Cloud resources are temporary, DNS records are persistent.** Teams spin up and tear down services frequently, but DNS records tend to accumulate unless explicitly managed.
- **Different teams own different parts.** The team that created the cloud resource may not have access to DNS management, and the team that manages DNS may not know the resource was removed.
- **No automated link between resources and DNS.** Most organizations have no mechanism to detect when a DNS target stops existing.
- **Shadow IT and forgotten proof-of-concepts.** Developers create temporary subdomains for testing or demos and never clean them up.
- **Mergers, acquisitions, and reorganizations.** DNS zones inherited from acquired companies are often poorly inventoried, and the original infrastructure owners are no longer available.

### Record Types at Risk

- **CNAME records** are the most common vector. If the canonical name resolves to a service that can be claimed, takeover is possible.
- **A records** pointing to released IP addresses can be vulnerable if the IP is reassigned and the attacker obtains it. This is common in cloud environments where elastic IPs are released back to the provider's pool.
- **NS records** delegating a subdomain to a third-party DNS provider are particularly dangerous. If the account at the DNS provider is closed, anyone who creates a new account can potentially claim the delegated zone and control all records under that subdomain.
- **MX records** pointing to deprovisioned mail services can allow an attacker to receive email for the subdomain. Beyond intercepting password reset emails, this enables a more severe attack: most Certificate Authorities accept email-based domain validation (DV) using addresses like `admin@subdomain.example.com`. An attacker controlling MX records can complete DV challenges and obtain legitimate TLS certificates for the subdomain, enabling transparent HTTPS phishing or man-in-the-middle attacks.

## Cloud Provider Vulnerability Reference

Not all cloud services are equally vulnerable. The key factor is whether the service allows a new customer to claim a previously used hostname or resource name. This table is a snapshot; cloud providers continuously update their policies, so always verify current behavior against the community-maintained [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository.

### High Risk: Takeover Possible When Resource Is Removed

| Provider/Service | Vulnerable Resource | Indicator (CNAME Target) | Takeover Mechanism |
|---|---|---|---|
| AWS S3 (Website Hosting) | S3 bucket | `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com` | Bucket names are globally unique across all AWS accounts. If a bucket is deleted, any AWS account can recreate it with the same name and serve content on the CNAME. |
| AWS Elastic Beanstalk | Environment | `*.elasticbeanstalk.com` | Environment CNAMEs are globally unique and released on environment termination. An attacker can create a new environment with the same CNAME prefix. |
| Azure App Service | Web App | `*.azurewebsites.net` | App names are globally unique. After deletion, any Azure tenant can create a new app with the same name. Azure offers a [domain verification mechanism](https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain) to mitigate this; see Prevention Strategies. |
| Azure Traffic Manager | Profile | `*.trafficmanager.net` | Profile names are globally unique and reclaimable after deletion. |
| Azure CDN | Endpoint | `*.azureedge.net` | Endpoint names are globally unique. A deleted endpoint name can be registered by another tenant. |
| GitHub Pages (Custom Domains) | Custom domain on repository | `*.github.io` | The primary risk is with custom domain configurations. When a repository using a custom domain is deleted or made private, the custom domain association is removed and an attacker can configure the same custom domain on their own GitHub Pages repository. Note: claiming the default `username.github.io` subdomain requires registering that GitHub username, which is not possible while the original account exists. |
| Heroku | App | `*.herokuapp.com` | App names are globally unique and released on app deletion. Any Heroku account can claim the name. |
| Shopify | Store | `shops.myshopify.com` | Custom domain associations can be claimed by any Shopify store. |
| Netlify | Site | `*.netlify.app`, `*.netlify.com` | Site names are reclaimable after deletion. |
| Fastly | CDN service | `*.fastly.net`, `*.global.ssl.fastly.net` | An attacker with a Fastly account can add the victim's domain to their own Fastly service configuration. |
| Zendesk | Support portal | `*.zendesk.com` | Support portal subdomain names can be reclaimed by new Zendesk accounts. |
| Cargo Collective | Portfolio | `*.cargocollective.com` | Portfolio names are reclaimable. |
| Tumblr | Blog | `*.tumblr.com` | Custom domain associations are released when a blog is deleted. |

### Conditional Risk: Takeover Possible Under Specific Circumstances

| Provider/Service | Condition | Details |
|---|---|---|
| AWS CloudFront | Distribution deleted while CNAME remains | When a CloudFront distribution is deleted but the CNAME record still points to the `*.cloudfront.net` hostname, an attacker can create a new CloudFront distribution and add the victim's domain as an alternate domain name (CNAME). CloudFront does not always verify domain ownership when adding alternate domain names, making this exploitable. If the distribution still exists but is merely disabled, takeover is not possible. |
| AWS Route 53 (NS Delegation) | NS delegation to deleted hosted zone | If a subdomain's NS records delegate to a Route 53 hosted zone that has been deleted, an attacker can create a new hosted zone for the same subdomain and may receive the same NS server assignments, effectively taking control of all DNS records for that subdomain. |
| Google Cloud Storage | Bucket deleted | GCS bucket names are globally unique and can be reclaimed after deletion. Google imposes rate limits on bucket creation and may temporarily reserve recently deleted names, but this is not a documented security guarantee and should not be relied upon as a protection. Remove DNS records when decommissioning GCS buckets. |
| Cloudflare | Misconfigured SaaS setup | Standard Cloudflare usage requires domain ownership verification via nameserver delegation. However, Cloudflare for SaaS (custom hostnames) configurations should use the [custom hostname verification](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/) feature to prevent hostname claim conflicts. |

### Service Fingerprints for Detection

When scanning for potential subdomain takeovers, look for these distinctive error responses that indicate the backend resource no longer exists:

| Service | Error Response Pattern |
|---|---|
| AWS S3 | `NoSuchBucket`, `The specified bucket does not exist` |
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| Heroku | `No such app`, `herokucdn.com/error-pages/no-such-app.html` |
| Azure App Service | `404 Web Site not found` on `*.azurewebsites.net` |
| Shopify | `Sorry, this shop is currently unavailable.` |
| Netlify | `Not Found - Request ID:` |
| Fastly | `Fastly error: unknown domain:` |
| Zendesk | `Help Center Closed` |

## Prevention Strategies

### 1. Manage DNS Record Lifecycle During Decommissioning

The correct order of operations when decommissioning a service is:

1. **Redirect or serve a maintenance page** at the subdomain to avoid broken links and user confusion during the transition period
2. **Update or remove the DNS record** pointing to the resource
3. **Wait for DNS propagation** (at least the TTL duration, typically 300 to 3600 seconds)
4. **Then decommission the cloud resource**

The common mistake is doing these steps in reverse: deleting the cloud resource first, which creates an immediate window for takeover that persists until someone notices the dangling record.

In practice, immediately deleting the DNS record can cause disruption if the subdomain is linked from other pages, bookmarked by users, or indexed by search engines. Pointing the record to an internal server that returns an HTTP redirect to the main domain or a simple maintenance page is a reasonable intermediate step that eliminates the takeover risk while preserving a functional user experience during the transition.

### 2. Maintain a DNS Inventory Linked to Resource Ownership

Keep a documented mapping between DNS records and the cloud resources they point to:

- **What resource** does each CNAME, A, or NS record resolve to?
- **Which team** owns the resource?
- **What project or service** is it part of?
- **When** was it created and when is it expected to be decommissioned?
- **What is the business justification** for the subdomain?

This can be as simple as a spreadsheet for small organizations or integrated into a Configuration Management Database (CMDB) for larger ones. The critical requirement is that it is consulted and updated during every infrastructure change. Infrastructure-as-Code tools like Terraform, Pulumi, or AWS CDK can also serve as a living inventory when DNS records and cloud resources are managed in the same codebase.

### 3. Implement Automated Dangling Record Detection

Regularly scan DNS records to identify entries pointing to non-existent resources:

- **Scheduled scans:** Run automated checks daily or weekly against all DNS records to verify that targets still resolve and respond with expected content, not cloud provider error pages.
- **CI/CD integration:** Add DNS validation to deployment and teardown pipelines. When a service is removed, the pipeline should verify that associated DNS records are also removed before marking the decommissioning as complete.
- **DNS change monitoring:** Alert when new CNAME records are created and when target resources return errors such as HTTP 404, NXDOMAIN, or cloud provider default error pages.

Open-source tools for detection:

- [dnsReaper](https://github.com/punk-security/dnsReaper): Actively maintained subdomain takeover scanner supporting 40+ service fingerprints with signature-based detection
- [nuclei](https://github.com/projectdiscovery/nuclei): General-purpose vulnerability scanner with a dedicated set of [subdomain takeover detection templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/dns)
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz): Community-maintained reference documenting which services are and are not vulnerable, with proof-of-concept details

### 4. Use Domain Verification Where Available

Several cloud providers offer domain verification mechanisms that prevent unauthorized users from associating a custom domain with their account. When available, these provide a strong defense layer:

- **Azure App Service:** Supports [custom domain verification via TXT records](https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain). Adding a verification TXT record (e.g., `asuid.subdomain TXT <verification-id>`) ties the custom domain to a specific Azure subscription. Keep this TXT record in place even after decommissioning the App Service to prevent another tenant from claiming the domain.
- **Google Cloud:** Many GCP services require domain verification through Google Search Console or a DNS TXT record before a custom domain can be associated. Retain verification records as long as the DNS record exists.
- **Cloudflare:** Standard setup requires domain ownership via nameserver delegation. Cloudflare for SaaS configurations should use the [custom hostname verification](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/) feature.
- **AWS:** AWS does not currently offer a universal domain verification mechanism for services like S3 or Elastic Beanstalk. For CloudFront, associating a distribution with a custom domain and keeping the distribution active (even if serving a redirect) prevents another account from claiming the domain name as an alternate CNAME.

Where no domain verification is available, the DNS record itself is the only control. Removing it promptly on decommissioning is the only reliable protection.

### 5. Restrict Wildcard DNS Records

Wildcard DNS records (`*.example.com`) are especially dangerous because they resolve for any subdomain, including those matching services that no longer exist. Any service that previously existed under the wildcard could potentially be taken over, and the organization may not even know which subdomains were in use.

Avoid wildcard records unless absolutely necessary. If required:

- Scope them as narrowly as possible (e.g., `*.staging.example.com` rather than `*.example.com`)
- Combine with a reverse proxy or load balancer that maintains an allowlist of valid hostnames and returns an error for unrecognized ones
- Monitor Certificate Transparency logs for unexpected certificate issuance on subdomains matching the wildcard

### 6. Establish a Decommissioning Checklist

Create a formal checklist that teams must follow when removing any externally facing service:

- [ ] Identify all DNS records (CNAME, A, MX, NS, TXT) associated with the service
- [ ] Point the DNS record to a maintenance page or redirect (if immediate removal causes user-facing disruption)
- [ ] Remove or update DNS records
- [ ] Wait for DNS propagation (at least the TTL duration)
- [ ] Decommission the cloud resource
- [ ] Revoke or let expire any SSL/TLS certificates issued for the subdomain
- [ ] Update the DNS inventory documentation
- [ ] Remove the subdomain from any OAuth redirect URI allowlists, CSP directives, or CORS configurations
- [ ] Verify that the subdomain no longer resolves or returns expected content
- [ ] Run a takeover detection scan against the subdomain to confirm it is not claimable

### 7. Limit the Blast Radius with Proper Security Scoping

Even if a subdomain takeover occurs, limit the damage by properly scoping security controls:

- **Cookies:** Do not scope session cookies to the parent domain (`.example.com`) unless necessary. Prefer setting cookies on the specific fully qualified subdomain (`app.example.com`). Use the `__Host-` cookie prefix where possible, which restricts the cookie to the exact origin.
- **Content Security Policy:** Avoid using `*.example.com` in CSP directives. Explicitly list trusted subdomains. A taken-over subdomain matching a CSP wildcard allows the attacker to inject scripts or exfiltrate data without violating the policy.
- **CORS:** Do not use wildcard subdomain patterns in `Access-Control-Allow-Origin` validation. Validate against an explicit allowlist of trusted origins.
- **OAuth/SSO:** Do not whitelist entire subdomain patterns in redirect URI validations. Use exact-match redirect URIs. A taken-over subdomain in an OAuth redirect allowlist enables token theft.
- **Email (SPF/DKIM/DMARC):** If SPF records include mechanisms that match the taken-over subdomain's IP, the attacker can send SPF-authenticated email appearing to originate from your domain.

## Monitoring and Detection

### Continuous DNS Monitoring

Implement ongoing monitoring to catch dangling records before attackers do:

- **Compare DNS records against live resources.** For every CNAME in your zone, verify the target still exists and responds with expected content rather than a cloud provider error page.
- **Monitor for service fingerprints.** The error responses listed in the Service Fingerprints table above are strong indicators that a resource has been removed while the DNS record remains. Automated scanning for these patterns should run at least weekly.
- **Track DNS zone changes.** Use version-controlled DNS management (e.g., Terraform, OctoDNS, or DNSControl) so all record additions and removals are reviewed, approved, and logged. This also creates an audit trail for investigating how a dangling record was introduced.
- **Monitor Certificate Transparency logs.** Use services like [crt.sh](https://crt.sh) or [certspotter](https://sslmate.com/certspotter/) to alert on any certificate issuance for your subdomains. An unexpected certificate issued for a subdomain you don't control is a strong indicator that takeover has already occurred or is in progress.

### Indicators of Compromise

Signs that a subdomain may have already been taken over:

- Subdomain suddenly serves unexpected content, a parking page, or a different application than expected
- SSL/TLS certificate for the subdomain was issued to an unknown entity or organization (visible in Certificate Transparency logs)
- Users report phishing emails or pages appearing to come from the subdomain
- Web application firewall or proxy logs show the subdomain resolving to an IP address outside your known infrastructure ranges
- DMARC aggregate reports show email being sent from the subdomain that your organization did not originate

## Incident Response

If a subdomain takeover is discovered:

1. **Remove the DNS record immediately.** This is the fastest mitigation. It breaks the link between your domain and the attacker's resource. If the record cannot be removed quickly, update it to point to an IP or CNAME you control.
2. **Revoke or request revocation of any certificates** issued for the subdomain during the takeover period. Check Certificate Transparency logs to identify all certificates that were issued.
3. **Assess the impact.** Determine whether cookies scoped to the parent domain could have been stolen, whether phishing content was served and for how long, whether any OAuth or SSO flows referenced the subdomain, and whether the attacker could have received email for the subdomain (MX-based takeover).
4. **Notify affected users** if there is evidence that sensitive data was exposed, credentials were phished, or session cookies were intercepted.
5. **Investigate the root cause.** Identify the process gap that allowed the dangling record to persist and update decommissioning procedures to prevent recurrence.
6. **Scan all DNS zones** owned by the organization for other dangling records. The same process gap likely affects other subdomains.
7. **Document the incident** with a timeline, impact assessment, and corrective actions for internal review and to improve organizational response to future occurrences.

## References

- [OWASP Web Security Testing Guide: Test for Subdomain Takeover (WSTG-CONFIG-10)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- [can-i-take-over-xyz: Community-maintained list of vulnerable services](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Microsoft: Prevent dangling DNS entries and avoid subdomain takeover](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)
- [dnsReaper: Subdomain takeover detection tool](https://github.com/punk-security/dnsReaper)
- [HackerOne Hacktivity: Subdomain takeover reports](https://hackerone.com/hacktivity?querystring=subdomain+takeover)
