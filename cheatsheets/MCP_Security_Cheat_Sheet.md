# MCP (Model Context Protocol) Security Cheat Sheet

## Introduction

The Model Context Protocol (MCP), introduced by Anthropic in November 2024, standardizes how AI applications (LLM clients) connect to external tools, data sources, and services. Think of it as a universal interface layer, a "USB-C port for AI", replacing fragmented, custom integrations with a single protocol.

However, MCP introduces a fundamentally new attack surface: AI agents dynamically executing tools based on natural language, with access to sensitive systems. Unlike traditional APIs where developers control every call, MCP lets LLMs decide which tools to invoke, when, and with what parameters. This is creating unique security risks that combine prompt injection, supply chain attacks, and confused deputy problems.

This cheat sheet provides best practices to secure MCP deployments and minimize attack surfaces across clients, servers, and the connections between them.

## Architecture Overview

```
User ↔ MCP Host (AI App) ↔ MCP Client ↔ MCP Server(s) ↔ Tools / Data / APIs
```

- **MCP Host**: The AI application (e.g., Claude Desktop, Cursor, IDE plugins).
- **MCP Client**: Connects to one or more MCP servers, passes tool definitions to the LLM.
- **MCP Server**: Lightweight program exposing tools, resources, and prompts via the protocol.
- **Transports**: `stdio` (local) or HTTP/SSE (remote).

The LLM sees all tool descriptions from all connected servers in its context — this is critical to understanding cross-server attacks.

## Key Risks

- **Tool Poisoning**: Malicious instructions hidden in tool descriptions, parameter schemas, or return values that manipulate the LLM's behavior.
- **Rug Pull Attacks**: A server changes its tool definitions after initial user approval, turning a trusted tool malicious.
- **Tool Shadowing / Cross-Origin Escalation**: A malicious server's tool description manipulates how the agent behaves with tools from *other* trusted servers.
- **Confused Deputy Problem**: The MCP server executes actions with its own (often broad) privileges, not the requesting user's permissions.
- **Data Exfiltration via Legitimate Channels**: Attackers use prompt injection to encode sensitive data into seemingly normal tool calls (e.g., search queries, email subjects).
- **Excessive Permissions / Over-Scoped Tokens**: MCP servers request broad OAuth scopes (full Gmail access vs. read-only), creating aggregation risk.
- **Supply Chain Attacks**: Untrusted or compromised MCP server packages installed from public registries without review.
- **Message Tampering and Replay**: JSON-RPC payloads modified after TLS termination by compromised proxies or middleware, or captured and re-sent to duplicate actions.
- **Sandbox Escapes**: Local MCP servers running with full host access, enabling file system traversal, credential theft, or arbitrary code execution.

## Best Practices

### 1. Principle of Least Privilege

- Grant each MCP server the minimum permissions needed for its function.
- Use scoped, per-server credentials — never share tokens across servers.
- Request narrow OAuth scopes (e.g., `mail.readonly` instead of `mail.modify` or `mail.full_access`).
- Prefer ephemeral, short-lived tokens over long-lived PATs.

### 2. Tool Description & Schema Integrity

- Inspect all tool descriptions, parameter names, types, and return schemas before approval.
- Treat the *entire* tool schema as a potential injection surface — not just the `description` field.
- Pin tool definitions using cryptographic hashes and alert on any changes (prevents rug pulls).
- Use tools like `mcp-scan` to automatically detect poisoned descriptions and cross-server shadowing.
- Use strict JSON Schema for tool parameters: set `additionalProperties: false` and use `pattern` (or similar) on string fields so only declared parameters and valid formats are accepted.

### 3. Sandbox and Isolate MCP Servers

- Run local MCP servers in sandboxed environments (containers, chroot, application sandboxes).
- Restrict file system access to only required directories.
- Disable network access unless explicitly needed.
- Use `stdio` transport for local servers to limit access to only the MCP client.
- Separate sensitive servers (payment, auth, PII) from general-purpose ones.

### 4. Human-in-the-Loop for Sensitive Actions

- Require explicit user confirmation for destructive, financial, or data-sharing operations.
- Display full tool call parameters to the user — not just a summary name.
- Never auto-approve tool calls, especially in multi-server setups.
- Ensure the confirmation UI cannot be bypassed by LLM-crafted responses.

### 5. Input and Output Validation

- Validate all inputs to MCP server tools — treat them as untrusted (they originate from LLM output influenced by potentially malicious context).
- Sanitize inputs against injection attacks (SQL, OS command, path traversal).
- Validate and sanitize tool outputs before returning them to the LLM context — output is often used as input by other tools and can cause downstream SSRF or command injection if unsanitized.
- Never pass raw shell commands or unsanitized file paths.
- Protect against SSRF: MCP tools that fetch URLs based on LLM-generated parameters can be manipulated via prompt injection to access internal services (e.g., cloud metadata endpoints). Never fetch arbitrary URLs provided by the LLM without strict allowlist validation.

### 6. Authentication, Authorization & Transport Security

- Enforce authentication on all remote MCP server endpoints.
- Use OAuth 2.0 with PKCE for remote server authorization flows.
- Bind session IDs to user-specific context (e.g., `<user_id>:<session_id>`) to prevent session hijacking.
- Validate on each request that the session or token belongs to the current requester; reject the call if it does not (prevents confused deputy).
- Use secure, non-deterministic session IDs (cryptographic random, not sequential).
- Always use TLS for remote (HTTP/SSE) transports.
- Verify server identity via certificate pinning or cryptographic server verification for remote servers.
- Apply resource controls (rate limits, quotas, timeouts) per session or tenant to resist DoS and limit impact of abuse; combine with sandboxing to contain local escape impact.
- Use OS-native secure credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service) for OAuth access and refresh tokens.
- Never store OAuth tokens in plaintext in MCP config files or application settings.
- Bind MCP HTTP/SSE servers to specific interfaces (e.g., 127.0.0.1), never 0.0.0.0 unless explicitly required.
- Validate the Host header on every incoming request; reject requests with unexpected hostnames.

### 7. Message-Level Integrity and Replay Protection

Transport-layer security (TLS) protects data in transit but does not guarantee message integrity at the application layer. A compromised proxy, middleware, or host-level agent can modify JSON-RPC payloads after TLS termination. Message-level signing ensures that tool calls and responses have not been tampered with between client and server.

- Sign each MCP message (JSON-RPC request body) with an asymmetric key (e.g., ECDSA P-256) bound to the sender's identity. The signature should cover the full serialized payload, not just selected fields.
- Include a unique nonce and timestamp in every signed message. Reject messages with duplicate nonces or timestamps outside an acceptable window (e.g., 5 minutes) to prevent replay attacks.
- Pin tool definitions at discovery time using cryptographic hashes (e.g., SHA-256 over the canonical JSON of the tool name, description, and input schema). Before each tool execution, re-hash the current definition and compare against the pinned value. A mismatch indicates post-deployment mutation (rug pull).
- Require mutual signing where both client and server sign their messages. Clients should verify server response signatures before processing results. Accept server public keys only from authenticated channels, not from unverified first-contact responses.
- Bind signatures to agent or user identity. Each signed message should include the signer's identity reference (e.g., a certificate fingerprint or public key hash) so the receiver can attribute and audit the request cryptographically.
- Fail closed when verification fails. If a signature is missing, invalid, or the nonce has been seen before, reject the message entirely. Never silently fall back to unsigned processing when signing is enabled.

### 8. Multi-Server Isolation & Cross-Origin Protection

- Treat each MCP server as an untrusted, independent security domain.
- Prevent tool descriptions from one server from referencing or modifying the behavior of tools from another server.
- Monitor for cross-server data flows (e.g., credentials from server A appearing in calls to server B).
- Use an MCP proxy or gateway to enforce isolation policies between servers.

### 9. Supply Chain Security

- Only install MCP servers from trusted, verified sources.
- Review server source code and tool definitions before installation.
- Verify package integrity with checksums or code signing.
- Scan MCP server dependencies for known vulnerabilities.
- Monitor for changes to tool descriptions post-installation (rug pull detection).
- Carefully verify package names before installation — typosquatting (e.g., mcp-server-filesystem vs mcp-server-filesytem) is a common attack vector.
- Use tools like `mcp-scan` to automatically analyze and monitor installed servers for malicious behavior or changes.

### 10. Monitoring, Logging & Auditing

- Log all MCP tool invocations with full parameters, user context, and timestamps.
- Feed MCP logs into SIEM for anomaly detection.
- Alert on unusual patterns: new tools being called, admin-level queries, abnormal call frequency.
- Redact secrets and PII from logs.
- Conduct regular security audits and simulated attacks against MCP setups.

### 11. Consent & Installation Security

- Display a clear consent dialog before connecting any new MCP server.
- Show the exact command that will be executed (for local servers), without truncation.
- Clearly identify the source and publisher of the MCP server.
- Re-prompt for consent when tool definitions change.
- Never allow web content or untrusted data to trigger MCP server installation.

### 12. Prompt Injection via Tool Return Values

- Treat every tool response as **untrusted user input** — sanitize before feeding back into the LLM context.
- Instruct the model explicitly (in system prompt) that tool return values are data, not instructions.
- Strip or escape HTML-like tags (`<IMPORTANT>`, `<system>`, `<instructions>`) from tool outputs before context injection.
- Log and alert on tool responses that contain instruction-like patterns (imperative verbs, "ignore", "forget", "send to", etc.).
- For web-scraping / retrieval tools, use a content extraction layer that returns structured data (title, body text) rather than raw HTML.

## Do's and Don'ts

**Do**:

- Enforce least privilege per MCP server and per tool.
- Inspect and pin all tool descriptions and schemas.
- Sandbox local MCP servers in containers or restricted environments.
- Require human approval for sensitive or destructive tool calls.
- Validate all inputs and outputs at the MCP server layer.
- Use `mcp-scan` or equivalent tooling to detect poisoned tools.
- Log and monitor all tool invocations centrally.
- Verify MCP server sources and scan dependencies.
- Sign MCP messages at the application layer — do not rely solely on transport-layer (TLS) security.
- Pin tool definitions with cryptographic hashes and verify before each execution.

**Don't**:

- Auto-approve tool calls without showing full parameters to the user.
- Trust tool descriptions blindly — they are a prompt injection vector.
- Share OAuth tokens or credentials across MCP servers.
- Run MCP servers with full host access or `*` permissions.
- Install MCP servers from unverified public registries without review.
- Assume a tool approved yesterday is the same tool today (rug pulls).
- Ignore cross-server interactions — shadowing attacks are real.
- Store secrets in MCP server code, configs, or environment variables.
- Silently fall back to unsigned message processing when signing is configured.
- Accept server public keys from unverified first-contact responses (TOFU without pinning).

## References

- [MCP Specification — Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [mcp-scan — Security Scanner for MCP Servers](https://github.com/invariantlabs-ai/mcp-scan)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [IETF Internet-Draft: Secure MCP — Message Signing and Tool Integrity](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/)
