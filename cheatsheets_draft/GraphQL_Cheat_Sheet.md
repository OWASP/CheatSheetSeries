# GraphQL Cheat Sheet

## Introduction

Below are some quick high-level ideas to keep in mind when building a secure API with GraphQL.

- Strict input validation is highly recommended and easy
- Expensive queries can easily lead to a denial of service; there are several defenses ranging from simple to complex
- It is very important to implement proper access control (authorization) but it can be tricky
- Some default configurations (Introspection, GraphiQL) should be disabled/changed before releasing an API to production

## Common Attacks

- [Injection](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa8-injection.md) - this usually includes but is not limited to:
    - [SQL](https://owasp.org/www-community/attacks/SQL_Injection) and [NoSQL](https://www.netsparker.com/blog/web-security/what-is-nosql-injection/) injection
    - [OS Command injection](https://owasp.org/www-community/attacks/Command_Injection)
    - [SSRF](https://portswigger.net/web-security/ssrf) and [CRLF](https://owasp.org/www-community/vulnerabilities/CRLF_Injection) [injection](https://www.acunetix.com/websitesecurity/crlf-injection/)/[Request](https://portswigger.net/web-security/request-smuggling) [Smuggling](https://www.pentestpartners.com/security-blog/http-request-smuggling-a-how-to/)
- [DoS](https://owasp.org/www-community/attacks/Denial_of_Service) ([Denial of Service](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/))
- [IDOR](https://portswigger.net/web-security/access-control/idor)
- Broken authorization: either [improper](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md) or [excessive](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md) access

## Best Practices and Recommendations

### Input Validation

Adding strict input validation can help prevent against injection and DoS. The main design for GraphQL is that the user supplies one or more identifiers and the backend has a number of data fetchers making HTTP, DB, or other calls using the given identifiers. This means that user input will be included in HTTP requests, DB queries, or other requests/calls which provides opportunity for injection that could lead to various injection attacks or DoS.

See the OWASP Cheat Sheets on [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) and general [injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) for full details to best perform input validation and prevent injection.

#### General Practices

Validate all incoming data to only allow valid values (i.e. whitelist).

- Use specific GraphQL [data types](https://graphql.org/learn/schema/#type-language) such as [scalars](https://graphql.org/learn/schema/#scalar-types) or [enums](https://graphql.org/learn/schema/#enumeration-types). Write custom GraphQL [validators](https://graphql.org/learn/validation/) for more complex validations. [Custom scalars](https://itnext.io/custom-scalars-in-graphql-9c26f43133f3) may also come in handy.
- Define [schemas for mutations input](https://graphql.org/learn/schema/#input-types).
- [Whitelist allowed characters](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#whitelisting-vs-blacklisting) - don't use a blacklist
    - The stricter the whitelist the better. A lot of times a good starting point is only allowing alphanumeric, non-unicode characters because it will disallow many attacks.
- To properly handle unicode input, use a [single internal character encoding](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#validating-free-form-unicode-text)
- Gracefully [reject invalid input](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), being careful not to reveal excessive information about how the API and its validation works.

#### Injection Prevention

When handling input meant to be passed to another interpreter (e.g. SQL/NoSQL/ORM, OS, LDAP, XML):

- Always prefer safe tools with support for parameterized statements
    - Ensure that you follow the documentation so you are properly using the tool
    - For SQL, using ORMs/ORDs is a good option but they must be used properly to avoid [ORM injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection).
- If such tools are not available, always escape/encode input data according to best practices of the target interpreter
    - Choose a well-documented and actively maintained escaping/encoding library. Many languages and frameworks have this functionality built-in.

For more information see the below pages:

- [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [NoSQL Injection Prevention](https://www.netsparker.com/blog/web-security/what-is-nosql-injection/)
- [LDAP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [OS Command Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [XML Security](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html) and [XXE Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

#### Process Validation

When using user input, even if sanitized and/or validated, it should not be used for certain purposes that would give a user control over data flow. For example, do not make an HTTP/resource request to a host that the user supplies (unless there is an absolute business need).

### DoS Prevention

DoS (denial of service) is an attack against the availability and stability of the API that can make it slow, unresponsive, or completely unavailable. This Cheat Sheet details several methods to limit the possibility of a denial of service attack at the application level and other layers of the tech stack. There is also a Cheat Sheet dedicated to topic of [denial of service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html).

Here are recommendations specific to GraphQL to limit the potential for DoS:

- Add depth limiting to incoming queries
- Add amount limiting to incoming queries
- Add [pagination](https://graphql.org/learn/pagination/) to limit the amount of data that can be returned in a single response
- Add reasonable timeouts at the application layer, infrastructure layer, or both
- Consider performing query cost analysis and enforcing a maximum allowed cost per query
- Enforce rate limiting on incoming requests per IP or user to prevent simple/classic DoS attacks where an attacker just spams requests
- Implement the [batching and caching technique](https://graphql.org/learn/best-practices/#server-side-batching-caching) on the server-side (Facebook's [DataLoader](https://github.com/facebook/dataloader) can be used for this)

#### Query Limiting (Depth & Amount)

In GraphQL each query has a depth (e.g. nested objects) and each object requested in a query can have an amount specified (e.g. 999999 of an object). By default these can both be unlimited which may lead to a DoS. You should set limits on depth and amount to prevent DoS, but this usually requires a small custom implementation as it is not natively supported by GraphQL. See [this](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) and [this](https://www.howtographql.com/advanced/4-security/) page for more information about these attacks and how to add depth and amount limiting. Adding [pagination](https://graphql.org/learn/pagination/) can also help performance.

APIs using graphql-java can utilize the built-in [MaxQueryDepthInstrumentation](https://github.com/graphql-java/graphql-java/blob/master/src/main/java/graphql/analysis/MaxQueryDepthInstrumentation.java) for depth limiting. APIs using JavaScript can use [graphql-depth-limit](https://github.com/stems/graphql-depth-limit) to implement depth limiting and [graphql-input-number](https://github.com/joonhocho/graphql-input-number) to implement amount limiting.

Here is an example of a GraphQL query with depth N:

```javascript
query evil {            # Depth: 0
  album(id: 42) {       # Depth: 1
    songs {             # Depth: 2
      album {           # Depth: 3
        ...             # Depth: ...
        album {id: N}   # Depth: N
      }
    }
  }
}
```

> We should have an example of someone taking advantage of no amount limiting and requesting N of an object. I'm not sure if a query can ask for N of an object directly or if the query has to use aliases and make N separate requests within the query for the same object.

#### Timeouts

Adding timeouts can be a simple way to limit how many resources any single request can consume. But timeouts are not always effective since they may not activate until a malicious query has already consumed excessive resources. Timeout requirements will differ by API and data fetching mechanism; there isn't one timeout value that will work across the board.

At the application level, timeouts can be added for queries and resolver functions. This option is usually more effective since the query/resolution can be stopped once the timeout is reached. GraphQL does not natively support query timeouts so custom code is required. See [this blog post](https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d) for more about using timeouts with GraphQL or the two examples below.

> I grabbed the JavaScript snippet from the medium blog post I linked above and the java snippet from [this SO answer](https://stackoverflow.com/a/53277955/1200388). I haven't tested the code to verify it works. Is that something we should do?

***JavaScript Timeout Example***

```javascript
request.incrementResolverCount =  function () {
    var runTime = Date.now() - startTime;
    if (runTime > 10) {  // a timeout of 10 seconds
      if (request.logTimeoutError) {
        logger('ERROR', 'Request ' + request.uuid + ' query execution timeout');
      }
      request.logTimeoutError = false;
      throw 'Query execution has timeout. Field resolution aborted';
    }
    this.resolverCount++;
  };
```

***Java Timeout Example using [Instrumentation](https://www.graphql-java.com/documentation/v11/instrumentation/)***

```java
public class TimeoutInstrumentation extends SimpleInstrumentation {
    @Override
    public DataFetcher<?> instrumentDataFetcher(
            DataFetcher<?> dataFetcher, InstrumentationFieldFetchParameters parameters
    ) {
        return environment ->
            Observable.fromCallable(() -> dataFetcher.get(environment))
                .subscribeOn(Schedulers.computation())
                .timeout(10, TimeUnit.SECONDS)  // timeout of 10 seconds
                .blockingFirst();
    }
}
```

***Infrastructure Timeout***

Another option to add a timeout that is usually easier but less effective is adding a timeout on an HTTP server ([Apache/httpd](https://httpd.apache.org/docs/2.4/mod/core.html#timeout), [nginx](http://nginx.org/en/docs/http/ngx_http_core_module.html#send_timeout)), reverse proxy, or load balancer.

#### Query Cost Analysis

Query cost analysis involves assigning costs to the resolution of fields or types in incoming queries so that the server can reject queries that cost too much to run or will consume too many resources. This is not easy to implement and may not always be necessary but it is the most thorough approach to preventing DoS. See "Query Cost Analysis" in [this blog post](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) for more details on implementing this control.

Apollo recommends:

> **Before you go ahead and spend a ton of time implementing query cost analysis be certain you need it.** Try to crash or slow down your staging API with a nasty query and see how far you get — maybe your API doesn’t have these kinds of nested relationships, or maybe it can handle fetching thousands of records at a time perfectly fine and doesn’t need query cost analysis!

APIs using graphql-java can utilize the built-in [MaxQueryComplexityInstrumentationto](https://github.com/graphql-java/graphql-java/blob/master/src/main/java/graphql/analysis/MaxQueryComplexityInstrumentation.java) to enforce max query complexity. APIs using JavaScript can utilize [graphql-cost-analysis](https://github.com/pa-bru/graphql-cost-analysis) or [graphql-validation-complexity](https://github.com/4Catalyzer/graphql-validation-complexity) to enforce max query cost.

#### Rate Limiting

Enforcing rate limiting on a per IP/user basis can help limit a single user's ability to spam requests to the service and impact performance. Ideally this can be done with a WAF, API gateway, or web server ([Nginx](https://www.nginx.com/blog/rate-limiting-nginx/), [Apache](https://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html/[HTTPD](https://github.com/jzdziarski/mod_evasive)) to reduce the effort of adding rate limiting.

Or you could get somewhat complex with throttling and implement it in your code (non-trivial). See "Throttling" [here](https://www.howtographql.com/advanced/4-security/) for more about GraphQL-specific rate limiting.

#### Server-side Batching and Caching

To increase efficiency of a GraphQL API and reduce its resource consumption, [the batching and caching technique](https://graphql.org/learn/best-practices/#server-side-batching-caching) can be used to prevent making duplicate requests for pieces of data within a small time frame. Facebook's [DataLoader](https://github.com/facebook/dataloader) tool is one way to implement this.

#### OS/Container Resource Management

> Should we remove this section since it's not specific to GraphQL?

Not properly limiting the amount of resources your API can use (e.g. CPU or memory), may compromise your API responsiveness and availability, leaving it vulnerable to DoS attacks. This can be done at the operating system level with blank and blank. However, containerization platforms tend to make this task much [easier](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts): see how to limit [memory](https://docs.docker.com/config/containers/resource_constraints/#memory), [CPU](https://docs.docker.com/config/containers/resource_constraints/#cpu), [number of restarts](https://docs.docker.com/engine/reference/commandline/run/#restart-policies---restart), [file descriptors, and processes](https://docs.docker.com/engine/reference/commandline/run/#set-ulimits-in-container---ulimit) using Docker.

#### Batching Attack

[GraphQL batching attack](https://lab.wallarm.com/graphql-batching-attack/)?

> This is an interesting attack that we should add. It seems like Amount Limiting will prevent it but I am not sure if that is the case. Needs some investigation. This may also belong in a different section since it's not DoS, it's brute force.

### Access Control

To ensure that a GraphQL API has proper access control, do the following:

- Always validate that the requester is authorized to view or mutate/modify the data they are requesting. This can be done with [RBAC](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Access_Control_Cheat_Sheet.md#role-based-access-control-rbac) or other access control mechanisms.
- Enforce authorization checks on both edges and nodes (see example [bug report](https://hackerone.com/reports/489146) where nodes did not have authorization checks but edges did).
- Use [Interfaces](https://graphql.org/learn/schema/#interfaces) and [Unions](https://graphql.org/learn/schema/#union-types) to create structured, hierarchical data types which can be used to return more or fewer object properties, according to requester permissions.
- Query and Mutation [Resolvers](https://graphql.org/learn/execution/#root-fields-resolvers) can be used to perform access control validation, possibly using some RBAC middleware.
- [Disable introspection queries](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/) system-wide in any production or publicly accessible environments.
- Disable [GraphiQL](https://github.com/graphql/graphiql) and other similar schema exploration tools in production or publicly accessible environments.

#### Query Access (Data Fetching)

As part of a GraphQL API there will be various data fields that can be returned. One thing to consider is if you want different levels of access around these fields. For example, you may only want certain consumers to be able to fetch certain data fields rather than allowing all consumers to be able to retrieve all available fields. This can be done by adding a check in the code to ensure that the requester should be able to read a field they are trying to fetch.

#### Mutation Access (Data Manipulation)

GraphQL supports mutation, or manipulation of data, in addition to its most common use case of data fetching. If an API implements/allows mutation then there may need to be access controls put in place to restrict which consumers, if any, can modify data through the API. Setups that require mutation access control would include APIs where only read access is intended for requesters or where only certain parties should be able to modify certain fields.

#### Introspection + GraphiQL

Many implementations of GraphQL have Introspection and GraphiQL enabled by default and leave them accessible without requiring authentication. This is problematic because introspection allows the requester to learn all about supported schema and queries (see a [real-world example](https://hackerone.com/reports/291531) abusing this). Introspection might be how the API owner wants to educate consumers about how to use the API. However, the preferred way to educate consumers about a service is through a separate documentation channel such as a wiki, Git Readme, or readthedocs.

The safest and usually easiest approach is to just disable introspection and GraphiQL system-wide. See [this page](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/) or consult your GraphQL implementation's documentation to learn how to disable introspection altogether. If your implementation does not natively support disabling introspection or if you would like to allow some consumers/roles to have this access you can build a filter in your service to only allow approved consumers to access the introspection system.

> This blurb is from nikitastupin. Would be great if we knew the name of this "hint" feature and link to documentation to disable it. I couldn't find anything from a quick Google.

Keep in mind that even if introspection is disabled you can still guess fields by brute forcing them. Furthermore, some GraphQL implementations give you a hint when a field name you provide is similar to an existing field (e.g. you provide `usr` and the response may ask if you meant the valid `user` field instead). You should consider disabling this feature.

***Disable Introspection - Java***

```Java
GraphQLSchema schema = GraphQLSchema.newSchema()
    .query(StarWarsSchema.queryType)
    .fieldVisibility( NoIntrospectionGraphqlFieldVisibility.NO_INTROSPECTION_FIELD_VISIBILITY )
    .build();
```

***Disable Introspection & GraphiQL - JavaScript***

```javascript
app.use('/graphql', graphqlHTTP({
  schema: MySessionAwareGraphQLSchema,
+ validationRules: [NoIntrospection]
  graphiql: process.env.NODE_ENV === 'development',
}));
```

### IDOR Protection

In general, proper access controls will prevent any IDOR attacks since IDOR merely represents 2 separate authorization issues: [Broken Object Level Authorization](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md) and [Broken Function Level Authorization](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa5-broken-function-level-authorization.md). See the [IDOR prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) for a comprehensive rundown of preventing IDOR.

> New section from nikitastupin. Not something I can personally verify with my limited GraphQL experience, so would be great if someone else can check this out.

Sometimes there are `node` or `nodes` or both fields in a query object. They can be used to access objects directly by `ID` which often introduces authorization vulnerabilities. You can check whether your schema has these fields by running this on the command line (assuming that `schema.json` contains your GraphQL schema): `cat schema.json | jq ".data.__schema.types[] | select(.name==\"Query\") | .fields[] | .name" | grep node`. To prevent such vulnerabilities either remove these fields or apply proper authorization checks when objects accessed directly by `ID` as discussed earlier in the "Access Control" section.

## Other Resources

### Tools

- [InQL Scanner](https://github.com/doyensec/inql) - Security scanner for GraphQL. Particularly useful for generating queries and mutations automatically from given schema and them feeding them to scanner.
- [GraphiQL](https://github.com/graphql/graphiql) - Schema/object exploration
- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) - Schema/object exploration

### GraphQL Security Best Practices + Documentation

- [GraphQL security best practices](https://leapgraph.com/graphql-api-security)
- [Protecting GraphQL APIs from security threats - blog post](https://medium.com/swlh/protecting-your-graphql-api-from-security-vulnerabilities-e8afdfa6fbe4)
- [https://nordicapis.com/security-points-to-consider-before-implementing-graphql/](https://nordicapis.com/security-points-to-consider-before-implementing-graphql/)
- [Limiting resource usage to prevent DoS (timeouts, throttling, complexity management, depth limiting, etc.)](https://developer.github.com/v4/guides/resource-limitations/)
- [GraphQL Security Perspectives](https://www.abhaybhargav.com/from-the-trenches-diy-security-perspectives-of-graphql/)
- [A developer's security perspective of GraphQL](https://medium.com/planes-agency/how-to-survive-a-penetration-test-as-a-graphql-developer-2759cababf8e)

### More on GraphQL Attacks

- [Some common GraphQL attacks + attacker mindset](https://blog.doyensec.com/2018/05/17/graphql-security-overview.html)
- [Bypassing permissions by smuggling parameters](https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [Bug bounty writeup about GraphQL](https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9)
- [Security talk about Abusing GraphQL](https://www.youtube.com/watch?v=NPDp7GHmMa0)
- [Real](https://vulners.com/myhack58/MYHACK58:62201994269) [world](https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/) [attacks](https://hackerone.com/reports/419883) [against](https://vulners.com/hackerone/H1:435066) [GraphQL](https://www.jonbottarini.com/2018/01/02/abusing-internal-api-to-achieve-idor-in-new-relic/) [in the](https://about.gitlab.com/blog/2019/07/03/security-release-gitlab-12-dot-0-dot-3-released/#authorization-issues-in-graphql) past
- [Attack examples against GraphQL](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
