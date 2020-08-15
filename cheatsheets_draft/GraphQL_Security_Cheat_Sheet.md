# GraphQL Security Cheat Sheet

## Attack

### Common vulnerability types

Though almost any vulnerability type can appear in GraphQL APIs there is list of most common ones.

- Authorization vulnerabilities. Among them most common are:
    - API1:2019 Broken Object Level Authorization
    - API3:2019 Excessive Data Exposure
- API8:2019 Injection. Among them most common are:
    - SQL injections
    - NoSQL injections
- API4:2019 Lack of Resources & Rate Limiting

### GraphQL specific vulnerabilities and weaknesses

- Sometimes there are `node` and `nodes` fields in Query object. They can be used to access objects directly by `ID` which often introduces authorization vulnerabilities. You can check whether your schema has these fields by `cat schema.json | jq ".data.__schema.types[] | select(.name==\"Query\") | .fields[] | .name" | grep node` (assuming that `schema.json` contains your GraphQL schema). To prevent such vulnerabilities either remove this fields or apply proper authorization checks when objects accessed directly by `ID`.
- Even if introspection is disabled you still can brute force fields. Furthermore some GraphQL implementations give you a hint when field name you provide is similar to existing field (e.g. you provide `usr` and in response you'll see error message kindly suggesting you valid `user` field).
- GraphQL batching feature can be used to brute force password / OTP. You may find more information about it in [GraphQL Batching Attack](https://lab.wallarm.com/graphql-batching-attack/) article.

## Defence

### Protecting from authorization vulnerabilities

- Edges can expose sensitive data as well as nodes so we should pay attention to authorization checks on edges too! Good example of such vulnerability is [Confidential data of users and limited metadata of programs and reports accessible via GraphQL](https://hackerone.com/reports/489146).

## Tools

- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) is good tool to get an overview of what particular GraphQL API exposes. You may find more information about it in [GraphQL Voyager as a tool for API security testing](https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9).
- [GraphiQL](https://github.com/graphql/graphiql) is convenient tool to interact with GraphQL API. [GraphiQL.app](https://github.com/skevy/graphiql-app) is desktop Electron-based wrapper around GraphiQL. It's useful because Burp Suite and other intercepting proxies don't natively support GraphQL query parsing (though some plugins can be used to remediate this) so it's hard to play with them.
- [InQL Scanner](https://github.com/doyensec/inql) particularly useful for generating queries and mutations automatically from given schema. Though it has other features too (e.g. generating documentation).
