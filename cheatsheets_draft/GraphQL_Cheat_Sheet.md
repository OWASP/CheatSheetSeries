# GraphQL Cheat Sheet

## Introduction

- Strict input validation is highly recommended and easy
- Expensive queries can easily lead to a denial of service, but defending against this is not simple
- It can be tricky and is very important to implement proper access control (authorization)
- Common attacks become much more likely if input from external parties is directly ingested by the service

## Common Attacks

- Injection
    - [SSRF](https://portswigger.net/web-security/ssrf) (also [CRLF](https://owasp.org/www-community/vulnerabilities/CRLF_Injection) [injection](https://www.acunetix.com/websitesecurity/crlf-injection/) or [Request](https://portswigger.net/web-security/request-smuggling) [Smuggling](https://www.pentestpartners.com/security-blog/http-request-smuggling-a-how-to/))
    - [SQL](https://portswigger.net/web-security/sql-injection) [injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [DoS](https://owasp.org/www-community/attacks/Denial_of_Service) ([Denial of Service](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/))
- [IDOR](https://portswigger.net/web-security/access-control/idor)
- Abuse of improper/excessive access

## Best Practices and Recommendations

### Input Validation

Adding strict input validation can help prevent against SSRF, SQL injection, and DoS. The main design for GraphQL is that an identifier is given and the backend has a number of fetchers making HTTP, DB, or other calls. This means that user input will be included in HTTP requests, DB queries, or other requests/calls and there is opportunity for injection that could lead to SSRF or SQL injection. Some pages that may be helpful here are OWASP Cheat Sheets for generic [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) or [Java Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html).

#### General Practices

> We can probably nix this section and just link to the Input Validation Cheat Sheet. I'll leave for now in case there is anything of value somebody else sees and thinks should be left in.

Implementing this should be very simple for most data types. Whitelist the characters that are allowed for any input given to the API and throw an error if illegal characters are given. For example, a user's ID might only contain numbers, so limiting an input field for user IDs to numbers is the best approach. The allowed characters will depend on the piece of data being passed. If alphanumeric characters are allowed there is very little risk of SSRF with an HTTP call. There is also very little risk for SQL injection, but any DB queries should be parameterized anyway. Unicode characters should also be disallowed unless they are specifically required in a field. If the field must have more than alphanumeric characters or Unicode then the other protection options (sanitization and/or parameterization) will be needed.

This can be achieved by using specific GraphQL types (such as numbers or enums) or by writing custom GraphQL [validators](https://graphql.org/learn/validation/) for more complicated validations.  

See the OWASP Cheat Sheet on [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) for more info.

#### SQL Injection Prevention

Anytime a DB or similar query is being made, any input should be properly parameterized with prepared statements or stored procedures in order to prevent SQL/DB injection. See the [OWASP Cheat Sheet for SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) for more info.

#### Process Validation

When using user input, even if sanitized and/or validated it should not be used for certain purposes that would give a user control over data flow. For example, do not make an HTTP/resource request to a host that the user supplies (unless there is a business need).

### Resource Management

> I assume we don't want the "internal vs external" API talk in here?

For a GraphQL API that receives input more or less directly from an external party, it can be difficult to limit the possibilities a malicious user can use to exhaust the API's resources to cause slow downs or indefinite outages. It is easier to protect an API that is only used by other internal services. Because of this, it may be better to only expose your API internally. See the table below for which of these controls should be added to each type of GraphQL API.

#### Depth Limiting

This is limiting the depth of incoming queries so that the user cannot supply unnecessarily deep queries that could consume a lot of resources. See [this](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) and [this blog post](https://www.howtographql.com/advanced/4-security/) as well as [this Github repo](https://github.com/stems/graphql-depth-limit) (old, potentially unsupported) for more details on implementing this control. I'm not sure if there is a good/trusted open source project that does this.

#### Amount Limiting

This is limiting the quantity that can be requested for a given resource/object. See [this](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) and [this blog post](https://www.howtographql.com/advanced/4-security/) as well as [this Github repo](https://github.com/joonhocho/graphql-input-number) for more details on implementing this control. I'm not sure if there is a good/trusted open source project that does this.

#### Timeouts

Adding timeouts can be a simple way to limit how much resources any single request can consume. Timeout requirements will differ by API and data fetching mechanism; there isn't one timeout value that will work across the board. It doesn't seem like GraphQL natively supports timeouts so this would require custom code (non-trivial) or adding a timeout on an HTTP server, reverse proxy, or load balancer (easy). See [this](https://www.howtographql.com/advanced/4-security/) and [this blog post](https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d) about timeouts with GraphQL.

#### Query Cost Analysis

This is not easy to implement and may not always be needed. See [this blog post](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) for more details on implementing this control.

Apollo recommends: "**Before you go ahead and spend a ton of time implementing query cost analysis be certain you need it.** Try to crash or slow down your staging API with a nasty query and see how far you get — maybe your API doesn’t have these kinds of nested relationships, or maybe it can handle fetching thousands of records at a time perfectly fine and doesn’t need query cost analysis!"

#### Rate Limiting

Enforcing rate limiting on a per IP/user basis can help limit a single user's ability to spam requests to the service. Ideally this can be done with a WAF, API gateway, or web server to reduce the cost of adding rate limiting.

Or you could get somewhat complex with throttling and implement it in your code (non-trivial). See [here](https://www.howtographql.com/advanced/4-security/) for more about GraphQL-specific throttling.

### Access Control

There are three main areas for managing access/permissions with GraphQL:

- Queries (data fetching)
- Mutation (write) queries
- [Introspection](https://graphql.org/learn/introspection/) system/query

Each of these need to have permission checks for most GraphQL setups.

#### Query Access

As part of a GraphQL API there will be various data fields that can be returned. One thing to consider is if you want different levels of access around these fields. For example, you may only want certain consumers to be able to fetch certain data fields rather than allowing all consumers to be able to retrieve all available fields. This can be done by adding a check in the code to ensure that the requestor should be able to read a field they are trying to fetch. This may be best implemented with simple [role-based access control](https://auth0.com/docs/authorization/concepts/rbac) ([RBAC](https://en.wikipedia.org/wiki/Role-based_access_control)): by creating roles which have access to certain fields and then attaching the correct roles to individual consumers/users. ABAC or other access control methods could also work.

#### Mutation Access

GraphQL supports mutation, or manipulation of data, in addition to its most common use case of data fetching. If your service implements/allows mutation then there may need to be access controls put in place to restrict which consumers, if any, can modify data through the API. Setups requiring mutation access control include APIs where only read access is intended or where only certain parties should be able to modify certain fields. This should be implemented similarly to Query access: use [RBAC](https://auth0.com/docs/authorization/concepts/rbac) and have the code only allow certain roles to perform mutation on approved data fields.

#### Introspection

Many implementations of GraphQL have Introspection enabled by default and leave it accessible to any incoming requests without requiring authentication. This is usually problematic because introspection allows the requester to learn all about supported schema and queries (see a [real-world example](https://hackerone.com/reports/291531) abusing this). Introspection might be how the API owner wants to educate consumers about how to use the API. However, the preferred way to educate consumers about a service is through a separate documentation channel such as a wiki, Git Readme, or readthedocs.

The safest and usually easiest approach is to just disable introspection system-wide. See [this page](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/) or consult your GraphQL implementation's documentation to learn how to disable introspection altogether. If your implementation does not natively support disabling introspection or if you would like to allow some consumers/roles to have this access you can build a filter in your service to only allow approved consumers to access the introspection system.

### IDOR Protection

See the [IDOR prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) for a comprehensive rundown of preventing IDOR.

More specific to GraphQL, it's likely that you want consumers to be able to provide the direct identifier rather than creating an abstraction layer, which can be fine. In this case you would simply add a check that the requestor is able to access the ID that they gave. For APIs where individuals make their own requests (such as traditional website with backend API) you would just be checking that the ID given is owned by the user who is authenticated (e.g. does user 123 own picture with ID 564?). For more of a service account scenario where one consumer makes requests on behalf of many users it may not make sense to add a check if a given service account should be able to access any object.

> The additional mitigation technique below probably belongs in the IDOR prevention cheat sheet but isn't there so I'll leave it here for now.

One alternative protection would be creating an abstraction of the ID that is usually mapped to the requester's session. For example, instead of the user requesting a picture via its direct ID, they would request picture 2 in their account and the backend would use that abstract ID with the user's ID to derive the actual direct ID of the picture. This prevents the user from being able to provide their own direct identifier for an object and ensures that the user can only access objects belonging to them. Another abstraction mechanism could involve using different IDs for the frontend vs the backend with some unpredictable translation that happens on the backend where the user does not have any influence.

## Other Resources

> I went overboard with external resources, so these should probably be pared down a bunch.

- [https://leapgraph.com/graphql-api-security](https://leapgraph.com/graphql-api-security) - GraphQL security best practices
- [https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) - Covers Depth Limiting, Amount Limiting, & Query Cost Analysis
- [https://blog.doyensec.com/2018/05/17/graphql-security-overview.html](https://blog.doyensec.com/2018/05/17/graphql-security-overview.html) - some common attacks; attacker mindset related to GraphQL
- [https://medium.com/swlh/protecting-your-graphql-api-from-security-vulnerabilities-e8afdfa6fbe4](https://medium.com/swlh/protecting-your-graphql-api-from-security-vulnerabilities-e8afdfa6fbe4) - Protecting GraphQL APIs from security threats
- [https://labs.detectify.com/2018/03/14/graphql-abuse/](https://labs.detectify.com/2018/03/14/graphql-abuse/) - bypassing permissions by smuggling parameters
- [https://nordicapis.com/security-points-to-consider-before-implementing-graphql/](https://nordicapis.com/security-points-to-consider-before-implementing-graphql/)
- [https://www.apollographql.com/docs/graphql-tools/scalars/](https://www.apollographql.com/docs/graphql-tools/scalars/)
- [https://itnext.io/custom-scalars-in-graphql-9c26f43133f3](https://itnext.io/custom-scalars-in-graphql-9c26f43133f3)
- [https://developer.github.com/v4/guides/resource-limitations/](https://developer.github.com/v4/guides/resource-limitations/) - limiting resource usage to prevent DoS (timeouts, throttling, complexity management, depth limiting, etc.)
- [https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d](https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d) - handling timeouts and managing query complexity (preventing DoS)
- [https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9](https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9) - attacker mindset
- [https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/) - attacker mindset
- [https://medium.com/planes-agency/how-to-survive-a-penetration-test-as-a-graphql-developer-2759cababf8e](https://medium.com/planes-agency/how-to-survive-a-penetration-test-as-a-graphql-developer-2759cababf8e) - developer focused security
- [Real](https://vulners.com/myhack58/MYHACK58:62201994269) [world](https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/) [attacks](https://hackerone.com/reports/419883) [against](https://vulners.com/hackerone/H1:435066) [GraphQL](https://www.jonbottarini.com/2018/01/02/abusing-internal-api-to-achieve-idor-in-new-relic/) [in the](https://about.gitlab.com/blog/2019/07/03/security-release-gitlab-12-dot-0-dot-3-released/#authorization-issues-in-graphql) past
- [Security talk about Abusing GraphQL](https://www.youtube.com/watch?v=NPDp7GHmMa0)
- [https://www.abhaybhargav.com/from-the-trenches-diy-security-perspectives-of-graphql/](https://www.abhaybhargav.com/from-the-trenches-diy-security-perspectives-of-graphql/)
- [https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) - OWASP's SQL Injection Prevention Cheat Sheet
- [https://cheatsheetseries.owasp.org/cheatsheets/Insecure\_Direct\_Object\_Reference\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) - OWASP's IDOR prevention Cheat Sheet
