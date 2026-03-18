# Subdomain Takeover Prevention Cheat Sheet

## Introduction

Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists. An attacker can claim the orphaned resource and serve arbitrary content on the victim's subdomain.

This vulnerability is consistently among the most reported findings in bug bounty programs. Despite being well understood, it remains prevalent because it is fundamentally an operational problem — teams create DNS records when spinning up services but rarely have processes to clean them up during decommissioning.

The impact goes beyond hosting a defacement page. An attacker controlling a subdomain can steal cookies scoped to the parent domain, bypass Content Security Policy rules that trust wildcard subdomains, host convincing phishing pages on a trusted domain, and in some cases compromise OAuth or SSO flows that whitelist the subdomain.

This cheat sheet provides practical guidance for developers, DevOps engineers, and infrastructure teams to prevent subdomain takeovers, detect dangling records before attackers do, and respond effectively when they are discovered.

## How Subdomain Takeover Works

### The Basic Mechanism

1. An organization creates a DNS record: `blog.example.com CNAME example-blog.herokuapp.com`
2. The Heroku app serves content on `blog.example.com`
3. Months later, the team decommissions the Heroku app but forgets to remove the DNS record
4. The CNAME still points to `example-blog.herokuapp.com`, which no longer exists
5. An attacker creates a new Heroku app with the name `example-blog` and claims the hostname
6. The attacker now controls what is served on `blog.example.com`

### Why It Happens

The root cause is almost always a disconnect between infrastructure provisioning and DNS management:

- **Cloud resources are temporary, DNS records are persistent.** Teams spin up and tear down services frequently, but DNS records tend to accumulate unless explicitly managed.
- **Different teams own different parts.** The team that created the cloud resource may not have access to DNS management, and the team that manages DNS may not know the resource was removed.
- **No automated link between resources and DNS.** Most organizations have no mechanism to detect when a DNS target stops existing.
- **Shadow IT and forgotten proof-of-concepts.** Developers create temporary subdomains for testing or demos and never clean them up.

### Record Types at Risk

- **CNAME records** are the most common vector. If the canonical name resolves to a service that can be claimed, takeover is possible.
- **A records** pointing to released IP addresses can be vulnerable if the IP is reassigned and the attacker obtains it (common in cloud environments with elastic IPs).
- **NS records** delegating a subdomain to a third-party DNS provider are particularly dangerous — if the account at the DNS provider is closed, anyone who creates a new account can claim the zone.
- **MX records** pointing to deprovisioned mail services can allow an attacker to receive email for the subdomain, potentially enabling password resets or verification flows.

## Cloud Provider Vulnerability Reference

Not all cloud services are equally vulnerable. The key factor is whether the service allows a new customer to claim a previously used hostname or resource name.

### High Risk — Takeover Possible When Resource Is Removed

| Provider/Service | Vulnerable Resource | Indicator (CNAME Target) | Notes |
|---|---|---|---|
| AWS S3 (Website Hosting) | S3 bucket | `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com` | Bucket names are globally unique. If deleted, anyone can recreate it. |
| AWS Elastic Beanstalk | Environment | `*.elasticbeanstalk.com` | Environment names can be reclaimed. |
| Azure App Service | Web App | `*.azurewebsites.net` | App names are globally unique and reclaimable after deletion. |
| Azure Traffic Manager | Profile | `*.trafficmanager.net` | Profile names are globally unique. |
| GitHub Pages | Repository | `*.github.io` | If the repo is deleted or made private, another user can create a repo with the same organization/user name. |
| Heroku | App | `*.herokuapp.com` | App names are globally unique and released on deletion. |
| Shopify | Store | `shops.myshopify.com` | Custom domain associations can be claimed. |
| Netlify | Site | `*.netlify.app`, `*.netlify.com` | Site names are reclaimable. |
| Fastly | CDN | `*.fastly.net`, `*.global.ssl.fastly.net` | Requires account access but hostname claims are possible. |
| Zendesk | Support portal | `*.zendesk.com` | Support portal names can be reclaimed. |

### Lower Risk — Takeover Difficult or Not Possible

| Provider/Service | Why | Notes |
|---|---|---|
| AWS CloudFront | Distributions are tied to account-specific identifiers | Requires matching the exact distribution ID, not just the domain name. |
| Google Cloud | Most GCP services use project-scoped naming | Bucket names are globally unique but Google has protections against rapid reclaim. |
| Cloudflare | Custom hostnames require domain verification | Cloudflare validates domain ownership before serving content. |

**Note:** Cloud providers continuously update their policies. Always verify current behavior before assuming a service is safe or vulnerable.

## Prevention Strategies

### 1. Delete DNS Records Before Deprovisioning Resources

This is the single most effective prevention measure. The correct order of operations when decommissioning a service is:

1. Remove or update the DNS record pointing to the resource
2. Wait for the DNS TTL to expire so cached records are flushed
3. Then decommission the cloud resource

The common mistake is doing these steps in reverse — deleting the cloud resource first, which creates an immediate window for takeover.

### 2. Maintain a DNS Inventory Linked to Resource Ownership

Keep a documented mapping between DNS records and the cloud resources they point to:

- **What resource** does each CNAME, A, or NS record resolve to?
- **Which team** owns the resource?
- **What project or service** is it part of?
- **When** was it created and when is it expected to be decommissioned?

This can be as simple as a spreadsheet for small organizations or integrated into a CMDB (Configuration Management Database) for larger ones. The critical requirement is that it is consulted and updated during infrastructure changes.

### 3. Implement Automated Dangling Record Detection

Regularly scan DNS records to identify entries pointing to non-existent resources:

- **Scheduled scans:** Run automated checks daily or weekly against all DNS records to verify that targets still resolve and respond.
- **CI/CD integration:** Add DNS validation to deployment pipelines. When a service is removed, the pipeline should verify that associated DNS records are also removed.
- **DNS change monitoring:** Alert when new CNAME records are created and when target resources return errors (HTTP 404, NXDOMAIN, or cloud provider default pages).

Open-source tools that can help with detection include:

- [subjack](https://github.com/haccer/subjack) — Checks for subdomain takeover vulnerabilities
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — Reference list of which services are vulnerable
- [nuclei](https://github.com/projectdiscovery/nuclei) — Has templates specifically for subdomain takeover detection

### 4. Use Domain Verification Where Available

Many cloud providers offer domain verification mechanisms that prevent unauthorized users from associating a domain with their account:

- **Azure:** Supports custom domain verification via TXT records. Enable the [domain verification feature](https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain) and do not remove the verification TXT record even after the service is decommissioned.
- **AWS:** Use AWS Organizations SCPs (Service Control Policies) to prevent creation of resources with previously used names within your organization.
- **Google Cloud:** Domain verification is required for many services. Keep verification records active.

### 5. Restrict Wildcard DNS Records

Wildcard DNS records (`*.example.com`) are especially dangerous because they resolve for any subdomain, including ones pointing to services that no longer exist. Avoid wildcard records unless absolutely necessary. If required:

- Scope them as narrowly as possible (e.g., `*.staging.example.com` rather than `*.example.com`)
- Combine with a CDN or reverse proxy that validates hostnames before serving content
- Monitor all subdomains that match the wildcard for unexpected content

### 6. Establish a Decommissioning Checklist

Create a formal checklist that teams must follow when removing any externally facing service:

- [ ] Identify all DNS records (CNAME, A, MX, NS, TXT) associated with the service
- [ ] Remove or update DNS records
- [ ] Wait for DNS propagation (at least the TTL duration)
- [ ] Decommission the cloud resource
- [ ] Remove any SSL/TLS certificates associated with the domain
- [ ] Update the DNS inventory documentation
- [ ] Verify that the subdomain no longer resolves or returns expected content

### 7. Scope Cookies and Security Policies Carefully

Even if a subdomain takeover occurs, limit the damage by properly scoping security controls:

- **Cookies:** Do not scope session cookies to the parent domain (`.example.com`) unless necessary. Prefer setting cookies on the specific subdomain (`app.example.com`).
- **Content Security Policy:** Avoid using `*.example.com` in CSP directives. Explicitly list trusted subdomains.
- **CORS:** Do not whitelist `*.example.com` in Access-Control-Allow-Origin headers. Use specific origins.
- **OAuth/SSO:** Do not whitelist entire subdomain patterns in redirect URI validations.

## Monitoring and Detection

### Continuous DNS Monitoring

Implement ongoing monitoring to catch dangling records before attackers do:

- **Compare DNS records against live resources.** For every CNAME in your zone, verify the target still exists and responds with expected content.
- **Monitor for cloud provider error pages.** Services like S3, Azure, and Heroku return distinctive error messages when a resource does not exist (e.g., "NoSuchBucket", "404 Site Not Found"). Detecting these responses on your subdomains is a strong indicator of a dangling record.
- **Track DNS zone changes.** Use version-controlled DNS management (e.g., Terraform, OctoDNS, or DNSControl) so all record additions and removals are reviewed, approved, and logged.

### Indicators of Compromise

Signs that a subdomain may have been taken over:

- Subdomain suddenly serves unexpected content or a default page
- SSL certificate for the subdomain was issued to an unknown entity (check Certificate Transparency logs)
- Users report phishing emails or pages appearing to come from the subdomain
- Web application firewall or proxy logs show the subdomain resolving to an unexpected IP address

## Incident Response

If a subdomain takeover is discovered:

1. **Remove the DNS record immediately.** This is the fastest mitigation — it breaks the link between your domain and the attacker's resource.
2. **Check for damage.** Review whether cookies could have been stolen, whether phishing content was served, and whether any OAuth or SSO flows could have been compromised.
3. **Notify affected users** if there is evidence that sensitive data was exposed or phishing content was served on the subdomain.
4. **Investigate how the dangling record was created.** Identify the process gap and update decommissioning procedures to prevent recurrence.
5. **Scan for other dangling records** across all DNS zones owned by the organization, as the same process gap likely affects other subdomains.

## References

- [OWASP Web Security Testing Guide — Test for Subdomain Takeover (WSTG-CONFIG-10)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- [can-i-take-over-xyz — Community-maintained list of vulnerable services](https://github.com/EdOverflow/can-i-take-over-xyz)
- [HackerOne Hacktivity — Subdomain takeover reports](https://hackerone.com/hacktivity?querystring=subdomain+takeover)
- [Microsoft — Prevent dangling DNS entries and avoid subdomain takeover](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)
