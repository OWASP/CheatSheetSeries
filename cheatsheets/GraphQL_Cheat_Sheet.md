# GraphQL Cheat Sheet

## Introduction

[GraphQL](https://graphql.org) is an open source query language originally developed by Facebook that can be used to build APIs as an alternative to REST and SOAP. It has gained popularity since its inception in 2012 because of the native flexibility it offers to those building and calling the API. There are GraphQL servers and clients implemented in various languages. [Many companies](https://foundation.graphql.org/) use GraphQL including GitHub, Credit Karma, Intuit, and PayPal.

This Cheat Sheet provides guidance on the various areas that need to be considered when working with GraphQL:

- Apply proper [input validation](Input_Validation_Cheat_Sheet.md) checks on all incoming data.
- Expensive queries will lead to [Denial of Service (DoS)](Denial_of_Service_Cheat_Sheet.md), so add checks to limit or prevent queries that are too expensive.
- Ensure that the API has proper [access control](Access_Control_Cheat_Sheet.md) checks.
- Disable insecure default configurations (_e.g._ excessive errors, introspection, GraphiQL, etc.).

## Common Attacks

- [Injection](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa8-injection.md) - this usually includes but is not limited to:
    - [SQL](https://owasp.org/www-community/attacks/SQL_Injection) and [NoSQL](https://www.netsparker.com/blog/web-security/what-is-nosql-injection/) injection
    - [OS Command injection](https://owasp.org/www-community/attacks/Command_Injection)
    - [SSRF](https://portswigger.net/web-security/ssrf) and [CRLF](https://owasp.org/www-community/vulnerabilities/CRLF_Injection) [injection](https://www.acunetix.com/websitesecurity/crlf-injection/)/[Request](https://portswigger.net/web-security/request-smuggling) [Smuggling](https://www.pentestpartners.com/security-blog/http-request-smuggling-a-how-to/)
- [DoS](https://owasp.org/www-community/attacks/Denial_of_Service) ([Denial of Service](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/))
- Abuse of broken authorization: either [improper](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md) or [excessive](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md) access, including [IDOR](https://portswigger.net/web-security/access-control/idor)
- Batching Attacks, a GraphQL-specific method of brute force attack
- Abuse of insecure default configurations

## Best Practices and Recommendations

### Input Validation

Adding strict input validation can help prevent against injection and DoS. The main design for GraphQL is that the user supplies one or more identifiers and the backend has a number of data fetchers making HTTP, DB, or other calls using the given identifiers. This means that user input will be included in HTTP requests, DB queries, or other requests/calls which provides opportunity for injection that could lead to various injection attacks or DoS.

See the OWASP Cheat Sheets on [Input Validation](Input_Validation_Cheat_Sheet.md) and general [injection prevention](Injection_Prevention_Cheat_Sheet.md) for full details to best perform input validation and prevent injection.

#### General Practices

Validate all incoming data to only allow valid values (i.e. allowlist).

- Use specific GraphQL [data types](https://graphql.org/learn/schema/#type-language) such as [scalars](https://graphql.org/learn/schema/#scalar-types) or [enums](https://graphql.org/learn/schema/#enumeration-types). Write custom GraphQL [validators](https://graphql.org/learn/validation/) for more complex validations. [Custom scalars](https://itnext.io/custom-scalars-in-graphql-9c26f43133f3) may also come in handy.
- Define [schemas for mutations input](https://graphql.org/learn/schema/#input-types).
- [List allowed characters](Input_Validation_Cheat_Sheet.md#allow-list-vs-block-list) - don't use a denylist
    - The stricter the list of allowed characters the better. A lot of times a good starting point is only allowing alphanumeric, non-unicode characters because it will disallow many attacks.
- To properly handle unicode input, use a [single internal character encoding](Input_Validation_Cheat_Sheet.md#validating-free-form-unicode-text)
- Gracefully [reject invalid input](Error_Handling_Cheat_Sheet.md), being careful not to reveal excessive information about how the API and its validation works.

#### Injection Prevention

When handling input meant to be passed to another interpreter (_e.g._ SQL/NoSQL/ORM, OS, LDAP, XML):

- Always choose libraries/modules/packages offering safe APIs, such as parameterized statements.
    - Ensure that you follow the documentation so you are properly using the tool
    - Using ORMs and ODMs are a good option but they must be used properly to avoid flaws such as [ORM injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection).
- If such tools are not available, always escape/encode input data according to best practices of the target interpreter
    - Choose a well-documented and actively maintained escaping/encoding library. Many languages and frameworks have this functionality built-in.

For more information see the below pages:

- [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md)
- [NoSQL Injection Prevention](https://www.netsparker.com/blog/web-security/what-is-nosql-injection/)
- [LDAP Injection Prevention](LDAP_Injection_Prevention_Cheat_Sheet.md)
- [OS Command Injection Prevention](OS_Command_Injection_Defense_Cheat_Sheet.md)
- [XML Security](XML_Security_Cheat_Sheet.md) and [XXE Injection Prevention](XML_External_Entity_Prevention_Cheat_Sheet.md)

#### Process Validation

When using user input, even if sanitized and/or validated, it should not be used for certain purposes that would give a user control over data flow. For example, do not make an HTTP/resource request to a host that the user supplies (unless there is an absolute business need).

### DoS Prevention

DoS is an attack against the availability and stability of the API that can make it slow, unresponsive, or completely unavailable. This CS details several methods to limit the possibility of a DoS attack at the application level and other layers of the tech stack. There is also a CS dedicated to the topic of [DoS](Denial_of_Service_Cheat_Sheet.md).

Here are recommendations specific to GraphQL to limit the potential for DoS:

- Add depth limiting to incoming queries
- Add amount limiting to incoming queries
- Add [pagination](https://graphql.org/learn/pagination/) to limit the amount of data that can be returned in a single response
- Add reasonable timeouts at the application layer, infrastructure layer, or both
- Consider performing query cost analysis and enforcing a maximum allowed cost per query
- Enforce rate limiting on incoming requests per IP or user (or both) to prevent basic DoS attacks
- Implement the [batching and caching technique](https://graphql.org/learn/best-practices/#server-side-batching-caching) on the server-side (Facebook's [DataLoader](https://github.com/facebook/dataloader) can be used for this)

#### Query Limiting (Depth & Amount)

In GraphQL each query has a depth (_e.g._ nested objects) and each object requested in a query can have an amount specified (_e.g._ 99999999 of an object). By default these can both be unlimited which may lead to a DoS. You should set limits on depth and amount to prevent DoS, but this usually requires a small custom implementation as it is not natively supported by GraphQL. See [this](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) and [this](https://www.howtographql.com/advanced/4-security/) page for more information about these attacks and how to add depth and amount limiting. Adding [pagination](https://graphql.org/learn/pagination/) can also help performance.

APIs using graphql-java can utilize the built-in [MaxQueryDepthInstrumentation](https://github.com/graphql-java/graphql-java/blob/master/src/main/java/graphql/analysis/MaxQueryDepthInstrumentation.java) for depth limiting. APIs using JavaScript can use [graphql-depth-limit](https://www.npmjs.com/package/graphql-depth-limit) to implement depth limiting and [graphql-input-number](https://github.com/joonhocho/graphql-input-number) to implement amount limiting.

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

Here is an example of a GraphQL query requesting 99999999 of an object:

```javascript
query {
  author(id: "abc") {
    posts(first: 99999999) {
      title
    }
  }
}
```

#### Timeouts

Adding timeouts can be a simple way to limit how many resources any single request can consume. But timeouts are not always effective since they may not activate until a malicious query has already consumed excessive resources. Timeout requirements will differ by API and data fetching mechanism; there isn't one timeout value that will work across the board.

At the application level, timeouts can be added for queries and resolver functions. This option is usually more effective since the query/resolution can be stopped once the timeout is reached. GraphQL does not natively support query timeouts so custom code is required. See [this blog post](https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d) for more about using timeouts with GraphQL or the two examples below.

***JavaScript Timeout Example***

Code snippet from [this SO answer](https://stackoverflow.com/a/53277955/1200388):

```javascript
request.incrementResolverCount =  function () {
    var runTime = Date.now() - startTime;
    if (runTime > 10000) {  // a timeout of 10 seconds
      if (request.logTimeoutError) {
        logger('ERROR', `Request ${request.uuid} query execution timeout`);
      }
      request.logTimeoutError = false;
      throw 'Query execution has timeout. Field resolution aborted';
    }
    this.resolverCount++;
  };
```

***Java Timeout Example using [Instrumentation](https://www.graphql-java.com/documentation/instrumentation)***

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

Another option to add a timeout that is usually easier is adding a timeout on an HTTP server ([Apache/httpd](https://httpd.apache.org/docs/2.4/mod/core.html#timeout), [nginx](http://nginx.org/en/docs/http/ngx_http_core_module.html#send_timeout)), reverse proxy, or load balancer. However, infrastructure timeouts are often inaccurate and can be bypassed more easily than application-level ones.

#### Query Cost Analysis

Query cost analysis involves assigning costs to the resolution of fields or types in incoming queries so that the server can reject queries that cost too much to run or will consume too many resources. This is not easy to implement and may not always be necessary but it is the most thorough approach to preventing DoS. See "Query Cost Analysis" in [this blog post](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b) for more details on implementing this control.

Apollo recommends:

> **Before you go ahead and spend a ton of time implementing query cost analysis be certain you need it.** Try to crash or slow down your staging API with a nasty query and see how far you get — maybe your API doesn’t have these kinds of nested relationships, or maybe it can handle fetching thousands of records at a time perfectly fine and doesn’t need query cost analysis!

APIs using graphql-java can utilize the built-in [MaxQueryComplexityInstrumentationto](https://github.com/graphql-java/graphql-java/blob/master/src/main/java/graphql/analysis/MaxQueryComplexityInstrumentation.java) to enforce max query complexity. APIs using JavaScript can utilize [graphql-cost-analysis](https://github.com/pa-bru/graphql-cost-analysis) or [graphql-validation-complexity](https://github.com/4Catalyzer/graphql-validation-complexity) to enforce max query cost.

#### Rate Limiting

Enforcing rate limiting on a per IP or user (for anonymous and unauthorized access) basis can help limit a single user's ability to spam requests to the service and impact performance. Ideally this can be done with a WAF, API gateway, or web server ([Nginx](https://www.nginx.com/blog/rate-limiting-nginx/), [Apache](https://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html)/[HTTPD](https://github.com/jzdziarski/mod_evasive)) to reduce the effort of adding rate limiting.

Or you could get somewhat complex with throttling and implement it in your code (non-trivial). See "Throttling" [here](https://www.howtographql.com/advanced/4-security/) for more about GraphQL-specific rate limiting.

#### Server-side Batching and Caching

To increase efficiency of a GraphQL API and reduce its resource consumption, [the batching and caching technique](https://graphql.org/learn/best-practices/#server-side-batching-caching) can be used to prevent making duplicate requests for pieces of data within a small time frame. Facebook's [DataLoader](https://github.com/facebook/dataloader) tool is one way to implement this.

#### System Resource Management

Not properly limiting the amount of resources your API can use (_e.g._ CPU or memory), may compromise your API responsiveness and availability, leaving it vulnerable to DoS attacks. Some limiting can be done at the operating system level.

On Linux, a combination of [Control Groups(cgroups)](https://en.wikipedia.org/wiki/Cgroups), [User Limits (ulimits)](https://linuxhint.com/linux_ulimit_command/), and [Linux Containers (LXC)](https://linuxcontainers.org/lxc/security/) can be used.

However, containerization platforms tend to make this task much easier. See the resource limiting section in the [Docker Security Cheat Sheet](Docker_Security_Cheat_Sheet.md#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts) for how to prevent DoS when using containers.

### Access Control

To ensure that a GraphQL API has proper access control, do the following:

- Always validate that the requester is authorized to view or mutate/modify the data they are requesting. This can be done with [RBAC](Access_Control_Cheat_Sheet.md#role-based-access-control-rbac) or other access control mechanisms.
    - This will prevent [IDOR](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md) issues, including both [BOLA](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md) and [BFLA](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa5-broken-function-level-authorization.md).
- Enforce authorization checks on both edges and nodes (see example [bug report](https://hackerone.com/reports/489146) where nodes did not have authorization checks but edges did).
- Use [Interfaces](https://graphql.org/learn/schema/#interfaces) and [Unions](https://graphql.org/learn/schema/#union-types) to create structured, hierarchical data types which can be used to return more or fewer object properties, according to requester permissions.
- Query and Mutation [Resolvers](https://graphql.org/learn/execution/#root-fields-resolvers) can be used to perform access control validation, possibly using some RBAC middleware.
- [Disable introspection queries](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/) system-wide in any production or publicly accessible environments.
- Disable [GraphiQL](https://github.com/graphql/graphiql) and other similar schema exploration tools in production or publicly accessible environments.

#### General Data Access

It's commonplace for GraphQL requests to include one or more direct IDs of objects in order to fetch or modify them. For example, a request for a certain picture may include the ID that is actually the primary key in the database for that picture. As with any request, the server must verify that the caller has access to the object they are requesting. But sometimes developers make the mistake of assuming that possession of the object's ID means the caller should have access. Failure to verify the requester's access in this case is called [Broken Object Level Authentication](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md), also known as [IDOR](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md).

It's possible for a GraphQL API to support access to objects using their ID even if that is not intended. Sometimes there are `node` or `nodes` or both fields in a query object, and these can be used to access objects directly by `ID`. You can check whether your schema has these fields by running this on the command-line (assuming that `schema.json` contains your GraphQL schema): `cat schema.json | jq ".data.__schema.types[] | select(.name==\"Query\") | .fields[] | .name" | grep node`. Removing these fields from the schema should disable the functionality, but you should always apply proper authorization checks to verify the caller has access to the object they are requesting.

#### Query Access (Data Fetching)

As part of a GraphQL API there will be various data fields that can be returned. One thing to consider is if you want different levels of access around these fields. For example, you may only want certain consumers to be able to fetch certain data fields rather than allowing all consumers to be able to retrieve all available fields. This can be done by adding a check in the code to ensure that the requester should be able to read a field they are trying to fetch.

#### Mutation Access (Data Manipulation)

GraphQL supports mutation, or manipulation of data, in addition to its most common use case of data fetching. If an API implements/allows mutation then there may need to be access controls put in place to restrict which consumers, if any, can modify data through the API. Setups that require mutation access control would include APIs where only read access is intended for requesters or where only certain parties should be able to modify certain fields.

### Batching Attacks

GraphQL supports batching requests, also known as [query batching](https://www.apollographql.com/blog/query-batching-in-apollo-63acfd859862/). This lets callers to either batch multiple queries or batch requests for multiple object instances in a single network call, which allows for what is called a [batching attack](https://lab.wallarm.com/graphql-batching-attack/). This is a form of brute force attack, specific to GraphQL, that usually allows for faster and less detectable exploits. Here is the most common way to do query batching:

```javascript
[
  {
    query: < query 0 >,
    variables: < variables for query 0 >,
  },
  {
    query: < query 1 >,
    variables: < variables for query 1 >,
  },
  {
    query: < query n >
    variables: < variables for query n >,
  }
]
```

And here is an example query of a single batched GraphQL call requesting multiple different instances of the `droid` object:

```javascript
query {
  droid(id: "2000") {
    name
  }
  second:droid(id: "2001") {
    name
  }
  third:droid(id: "2002") {
    name
  }
}
```

In this case it could be used to enumerate every possible `droid` object that is stored on the server in very few network requests as opposed to a standard REST API where the requester would need to submit a different network request for every different `droid` ID they want to request. This type of attack can lead to the following issues:

- Application-level DoS attacks - A high number of queries or object requests in a single network call could cause a database to hang or exhaust other available resources (_e.g._ memory, CPU, downstream services).
- Enumeration of objects on the server, such as users, emails, and user IDs.
- Brute forcing passwords, 2 factor authentication codes (OTPs), session tokens, or other sensitive values.
- WAFs, RASPs, IDS/IPS, SIEMs, or other security tooling will likely not detect these attacks since they only appear to be one single request rather than an a massive amount of network traffic.
- This attack will likely bypass existing rate limits in tools like Nginx or other proxies/gateways since they rely on looking at the raw number of requests.

#### Mitigating Batching Attacks

In order to mitigate this type of attack you should put limits on incoming requests at the code level so that they can be applied per request. There are 3 main options:

- Add object request rate limiting in code
- Prevent batching for sensitive objects
- Limit the number of queries that can run at one time

One option is to create a code-level rate limit on how many objects that callers can request. This means the backend would track how many different object instances the caller has requested, so that they will be blocked after requesting too many objects even if they batch the object requests in a single network call. This replicates a network-level rate limit that a WAF or other tool would do.

Another option is to prevent batching for sensitive objects that you don't want to be brute forced, such as usernames, emails, passwords, OTPs, session tokens, etc. This way an attacker is forced to attack the API like a REST API and make a different network call per object instance. This is not supported natively so it will require a custom solution. However once this control is put in place other standard controls will function normally to help prevent any brute forcing.

Limiting the number of operations that can be batched and run at once is another option to mitigate GraphQL batching attacks leading to DoS. This is not a silver bullet though and should be used in conjunction with other methods.

### Secure Configurations

By default, most GraphQL implementations have some insecure default configurations which should be changed:

- Don't return excessive error messages (_e.g._ disable stack traces and debug mode).
- Disable or restrict Introspection and GraphiQL based on your needs.
- Suggestion of mis-typed fields if the introspection is disabled

#### Introspection + GraphiQL

GraphQL Often comes by default with introspection and/or GraphiQL enabled and not requiring authentication. This allows the consumer of your API to learn everything about your API, schemas, mutations, deprecated fields and sometimes unwanted "private fields".

This might be an intended configuration if your API is designed to be consumed by external clients, but can also be an issue if the API was designed to be used internally only. Although security by obscurity is not recommended, it might be a good idea to consider removing the Introspection to avoid any leak.
If your API is publicly consumed, you might want to consider disabling it for not authenticated or unauthorized users.

For internal API, the easiest approach is to just disable introspection system-wide. See [this page](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/) or consult your GraphQL implementation's documentation to learn how to disable introspection altogether. If your implementation does not natively support disabling introspection or if you would like to allow some consumers/roles to have this access, you can build a filter in your service to only allow approved consumers to access the introspection system.

Keep in mind that even if introspection is disabled, attackers can still guess fields by brute forcing them. Furthermore, GraphQL has a built-in feature to return a hint when a field name that the requester provides is similar (but incorrect) to an existing field (_e.g._ request has `usr` and the response will ask `Did you mean "user?"`). You should consider disabling this feature if you have disabled the introspection, to decrease the exposure, but not all implementations of GraphQL support doing so. [Shapeshifter](https://github.com/szski/shapeshifter) is one tool that [should be able to do this](https://www.youtube.com/watch?v=NPDp7GHmMa0&t=2580).

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

#### Don't Return Excessive Errors

GraphQL APIs in production shouldn't return stack traces or be in debug mode. Doing this is implementation specific, but using middleware is one popular way to have better control over errors the server returns. To [disable excessive errors](https://www.apollographql.com/docs/apollo-server/data/errors/) with Apollo Server, either pass `debug: false` to the Apollo Server constructor or set the `NODE_ENV` environment variable to 'production' or 'test'. However, if you would like to log the stack trace internally without returning it to the user see [here](https://www.apollographql.com/docs/apollo-server/data/errors/#masking-and-logging-errors) for how to mask and log errors so they are available to the developers but not callers of the API.

## Other Resources

### Tools

- [InQL Scanner](https://github.com/doyensec/inql) - Security scanner for GraphQL. Particularly useful for generating queries and mutations automatically from given schema and them feeding them to scanner.
- [GraphiQL](https://github.com/graphql/graphiql) - Schema/object exploration
- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) - Schema/object exploration

### GraphQL Security Best Practices + Documentation

- [Protecting GraphQL APIs from security threats - blog post](https://medium.com/swlh/protecting-your-graphql-api-from-security-vulnerabilities-e8afdfa6fbe4)
- [https://nordicapis.com/security-points-to-consider-before-implementing-graphql/](https://nordicapis.com/security-points-to-consider-before-implementing-graphql/)
- [Limiting resource usage to prevent DoS (timeouts, throttling, complexity management, depth limiting, etc.)](https://developer.github.com/v4/guides/resource-limitations/)
- [GraphQL Security Perspectives](https://www.abhaybhargav.com/from-the-trenches-diy-security-perspectives-of-graphql/)
- [A developer's security perspective of GraphQL](https://planes.studio/blog/how-to-survive-a-penetration-test-as-a-graph-ql-developer)

### More on GraphQL Attacks

- [Some common GraphQL attacks + attacker mindset](https://blog.doyensec.com/2018/05/17/graphql-security-overview.html)
- [Bypassing permissions by smuggling parameters](https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [Bug bounty writeup about GraphQL](https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9)
- [Security talk about Abusing GraphQL](https://www.youtube.com/watch?v=NPDp7GHmMa0)
- [Real](https://vulners.com/myhack58/MYHACK58:62201994269) [world](https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/) [attacks](https://hackerone.com/reports/419883) [against](https://vulners.com/hackerone/H1:435066) [GraphQL](https://www.jonbottarini.com/2018/01/02/abusing-internal-api-to-achieve-idor-in-new-relic/) [in the](https://about.gitlab.com/blog/2019/07/03/security-release-gitlab-12-dot-0-dot-3-released/#authorization-issues-in-graphql) past
- [Attack examples against GraphQL](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
