# NoSQL Security Cheat Sheet

## Introduction

NoSQL databases (MongoDB, CouchDB, Cassandra etc.) power many modern applications with flexible schemas and horizontal scale. But their different query models and deployment patterns create **more security risks** compared with relational databases.
This cheat sheet summarizes guidance to reduce risk when using NoSQL systems.

## Threats & Common Failure Modes

- **NoSQL Injection** — Unsafe construction of query objects or query strings from untrusted input.
- **Exposed Management Interfaces** — Admin GUIs, database ports or REST endpoints exposed to the internet.
- **Weak/No Authentication & Authorization** — Default open access or excessive privileges for clients.
- **Insecure Network Exposure** — No TLS, open ports, insufficient network segmentation.
- **Insecure Defaults** — Default admin accounts, default passwords, unsecured configs.
- **Poor Access Control Models** — Coarse roles allowing lateral abuse.
- **Insecure Serialization / Deserialization** — Remote code execution via unsafe object deserialization.
- **Misconfigured CORS / Public APIs** — APIs accidentally allow cross-origin requests or wide access.
- **Credential & Secret Leaks** — Hardcoded DB credentials in code, images, CI logs.
- **Unsafe Backup Exposure** — Backups left unencrypted or publicly accessible.
- **Supply-chain / Dependency Risks** — Vulnerable drivers, ORMs/ODMs, or plugins.

## Secure-by-Design Principles

- **Treat all input as untrusted** — validate, sanitize, and normalize.
- **Use least privilege** — narrow roles for users, services, and operators.
- **Defense in depth** — combine network controls, auth, input validation, and monitoring.
- **Secure defaults** — change default ports/accounts, enable auth and TLS by default.
- **Automate secrets & rotation** — vaults and short-lived credentials.
- **Monitor & audit** — log access and detect anomalies.

## Practical Defenses & Examples

### Prevent NoSQL Injection

**Unsafe (string-based filter building — Node.js / MongoDB):**

```js
// DANGEROUS: building query from untrusted input
const q = "{ name: '" + req.query.name + "' }";
const filter = eval("(" + q + ")"); // NEVER do this
db.collection('users').find(filter)
```

**Safe (use driver query objects / parameterization):**

```js
// SAFE: let driver handle query structure
const filter = { name: req.query.name };
db.collection('users').find(filter)
```

**Safe (whitelisting for operators):**

```js
// Reject operator injection by disallowing $ in keys or operator values
if (JSON.stringify(req.body).includes('"$')) throw Error("Invalid input");
```

Notes:

- Do **not** accept raw JSON fragments from the client to execute as queries.
- Disallow client-controlled query operators (like `$where`, `$regex`, or `$expr`) unless strictly required and validated.
- For text-based search parameters, use safe driver APIs (e.g., `$text` with controlled input).

### Use Secure Driver / ODM Patterns

- Prefer high-level APIs (ODM/ORM) that build queries safely (e.g., Mongoose, Spring Data, Datastax driver patterns).
- Avoid `.eval()`-like functionality and raw query execution from untrusted data.
- Sanitize and validate any raw expressions before passing to the DB.

#### Example — PyMongo safe usage

```python
from pymongo import MongoClient
client = MongoClient(uri, tls=True)
collection = client.mydb.users
user = collection.find_one({"email": email_input})
```

### Authentication & Authorization

- **Enable authentication** (do not run databases unauthenticated).
- Use **role-based access control (RBAC)**, least privilege for service accounts.
- Use **separate users** for admin/backup/readonly/application.
- Use identity federation or short-lived credentials when supported (e.g., AWS IAM -> DynamoDB).

For more information please check following cheat sheets:

[Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

[Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

### Network & Transport Security

- **Bind services to internal interfaces**, not `0.0.0.0`.
- Use **network segmentation / private subnets** and security groups.
- **Enforce TLS** (in transit encryption) for driver connections and admin consoles.
- Turn off remote management or restrict it to admin networks/VPNs.

### Configuration Hardening

- Change default ports and disable sample/demo users.
- Turn off or restrict features that execute code on the server (e.g., MongoDB `db.eval`, server-side scripting).
- Require TLS for internal replication links where supported.

### Secrets Management

- Do **not** hardcode DB credentials — use a secret manager (Vault, AWS Secrets Manager, Azure Key Vault).
- Avoid baking credentials into container images or environment variables in CI logs.
- Rotate credentials regularly and use ephemeral tokens when possible.

### Logging, Monitoring & Auditing

- Enable audit logging (connection attempts, admin actions, failed auth).
- Send logs to a tamper-evident SIEM.
- Alert on anomalous patterns (spike in queries, slow queries, large data exports).
- Monitor for suspicious commands (e.g., admin actions, `$where`, map-reduce jobs).

### Backups & Snapshots

- Encrypt backups at rest and during transfer.
- Restrict access to backup storage.
- Sanitize backups for PII as required by policy.
- Validate restore procedures regularly.

## Quick NoSQL Security Checklist

- Enable authentication & RBAC
- Enforce TLS for client and node communication
- Bind DB to internal IPs / use private networks
- Use least privilege service accounts
- Disallow client-controlled query operators unless validated
- Avoid raw query execution / eval on server
- Store credentials in secret manager & rotate them
- Harden configs (disable unsafe defaults)
- Encrypt and secure backups
- Monitor/audit DB access and admin actions
- Keep DB and drivers patched

## Do’s and Don’ts

**Do**:

- Use driver query objects rather than building query strings.
- Validate and whitelist user-supplied fields (columns/keys).
- Restrict management interfaces and require MFA for admin access.
- Automate security testing in CI/CD pipelines.

**Don’t**:

- Expose DB ports/admin consoles to the public Internet.
- Accept raw JSON queries from clients or eval untrusted strings.
- Use root/admin DB accounts for application connections.
- Rely only on network controls to protect badly written queries.

## Examples of Dangerous Patterns (brief)

- Allowing client to submit `{ "$where": "this.balance > 0" }` → remote code execution or heavy CPU.
- Concatenating user input into query language strings or shell commands for DB tools.
- Leaving MongoDB unsecured (no auth) listening on public IP.

## References

- [MongoDB Security Official Document](https://www.mongodb.com/docs/manual/security/)
- [Security best practices for Amazon DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices-security.html)
- [WSTG - Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
