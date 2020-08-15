# GraphQL Security Cheat Sheet

Though almost any vulnerability type can appear in GraphQL APIs there is list of most common ones.

- Authorization vulnerabilities. Among them most common are:
    - Broken Object Level Authorization (API1:2019)
    - Excessive Data Exposure (API3:2019)
- Injection (API8:2019 ). Among them most common are:
    - SQL injections
    - NoSQL injections
- Lack of Resources & Rate Limiting (API4:2019)

## Authorization vulnerabilities

### GraphQL specific vulnerabilities

#### Introspection

By itself enabled introspection isn't a vulnerability. However it gives an attacker better understanding of your API which may lead to faster vulnerability discovery thus you may want to disable introspection.

Keep in mind that even if introspection is disabled you still can guess fields by brute forcing them. Furthermore some GraphQL implementations give you a hint when field name you provide is similar to existing field (e.g. you provide `usr` and in response you'll see error message kindly suggesting you valid `user` field).

#### Exposed `node` and `nodes` fields

Sometimes there are `node` or `nodes` or both fields in Query object. They can be used to access objects directly by `ID` which often introduces authorization vulnerabilities. You can check whether your schema has these fields by running `cat schema.json | jq ".data.__schema.types[] | select(.name==\"Query\") | .fields[] | .name" | grep node` (assuming that `schema.json` contains your GraphQL schema). To prevent such vulnerabilities either remove this fields or apply proper authorization checks when objects accessed directly by `ID`.

### Protecting from authorization vulnerabilities

- Edges can expose sensitive data as well as nodes so we should pay attention to authorization checks on edges too! Good example of such vulnerability is [Confidential data of users and limited metadata of programs and reports accessible via GraphQL](https://hackerone.com/reports/489146).

## Lack of Resources & Rate Limiting

GraphQL batching queries feature can be used to brute force password / OTP. You may find more information about it in [GraphQL Batching Attack](https://lab.wallarm.com/graphql-batching-attack/) article.

## Tools

- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) is good tool to get an overview of what object and functions particular GraphQL API exposes. You may find more information about its usage in [GraphQL Voyager as a tool for API security testing](https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9).
- [GraphiQL](https://github.com/graphql/graphiql) is convenient tool to interact with GraphQL API. [GraphiQL.app](https://github.com/skevy/graphiql-app) is desktop Electron-based wrapper around GraphiQL. It's useful because Burp Suite and other intercepting proxies don't natively support GraphQL query parsing (though some plugins can be used to fill this gap).
- [InQL Scanner](https://github.com/doyensec/inql) particularly useful for generating queries and mutations automatically from given schema and them feeding them to scanner. Though it has other features too (e.g. generating documentation from schema).
