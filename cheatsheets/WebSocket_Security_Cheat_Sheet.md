# WebSocket Security Cheat Sheet

## Introduction

WebSockets enable real-time, bidirectional communication between clients and servers, powering applications like chat systems, live trading platforms, and collaborative tools. Unlike traditional HTTP requests, WebSocket connections remain open and allow continuous data exchange.

However, WebSockets introduce security challenges that differ from standard web application security:

- **Cross-Site WebSocket Hijacking (CSWSH)**: Attackers hijack authenticated connections from malicious websites
- **Authentication bypass**: No built-in authentication makes access control easy to forget
- **Injection attacks**: WebSocket messages can carry XSS, SQL injection, and other malicious payloads
- **Denial-of-service**: Persistent connections enable new DoS attack vectors like connection exhaustion
- **Monitoring gaps**: Traditional HTTP logs only capture the initial upgrade request, missing all message traffic

**Real-world vulnerabilities:**

- **Gitpod CSWSH (2023)**: [Insufficient origin validation](https://github.com/advisories/GHSA-f53g-frr2-jhpf) allowed full account takeover via hijacked WebSocket connections
- **Spring RCE vulnerability**: [CVE-2018-1270](https://spring.io/security/cve-2018-1270) let attackers execute code through crafted STOMP messages

## Primary Defenses

### Transport Security

#### Always Use WSS (WebSocket Secure)

Never use unencrypted `ws://` connections in production. Unencrypted `ws://` connections allow eavesdropping and tampering.

```javascript
// Secure - always use this
const socket = new WebSocket('wss://app.example.com/socket');

// Insecure - never use in production
// const socket = new WebSocket('ws://app.example.com/socket');
```

See the [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md) for more details.

#### WebSocket Protocol Configuration

**Use modern protocol versions:**

Only support [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455) (the current WebSocket standard). Drop backward compatibility for outdated versions like [Hixie-76](https://datatracker.ietf.org/doc/html/draft-hixie-thewebsocketprotocol-76) and [hybi-00](https://datatracker.ietf.org/doc/html/draft-ietf-hybi-thewebsocketprotocol-00) which have known security vulnerabilities.

**Compression security:**

Disable `permessage-deflate` compression unless specifically needed. Compression can introduce security vulnerabilities similar to CRIME/BREACH attacks where compression combined with secret data can leak information.

```javascript
// Node.js - disable compression for security
const wss = new WebSocket.Server({
  perMessageDeflate: false
});
```

#### Infrastructure Configuration

**Proxy and load balancer support:**

Ensure reverse proxies, load balancers, and CDNs are configured to handle WebSocket upgrades:

- Configure proxy to support HTTP/1.1 upgrade mechanism  
- Pass `Upgrade` and `Connection: upgrade` headers correctly
- Set proper read timeouts for long-lived connections
- Ensure WebSocket traffic isn't blocked by security policies

**WAF support:**

Check that your WAF supports WebSocket traffic inspection beyond the initial handshake. If not, rely on server-side validation and application logging.

### Authentication and Authorization

WebSockets don't have built-in authentication. Browsers include cookies in WebSocket handshake requests, making WebSocket applications vulnerable to Cross-Site WebSocket Hijacking (CSWSH).

CSWSH allows attackers to hijack authenticated WebSocket connections from malicious websites:

1. User logs into your application (session cookie established)
2. User later visits a malicious website
3. Malicious site opens WebSocket to your application, browser sends cookies automatically
4. Server accepts the connection → attacker gets live, authenticated WebSocket access

#### Origin Header Validation

Validate the `Origin` header on every handshake. Always use an explicit allowlist of trusted origins. Browsers include this header and malicious JavaScript cannot override it.

```javascript
const wss = new WebSocket.Server({
  verifyClient: (info) => {
    const allowedOrigins = ['https://app.example.com'];
    if (!allowedOrigins.includes(info.origin)) {
      console.log(`Rejected unauthorized origin: ${info.origin}`);
      return false;
    }
    return true;
  }
});
```

**Important:** Use an allowlist, not a denylist. Avoid wildcards or substring matching which are error-prone.

#### Additional CSWSH Protections

For applications already using CSRF protection, include **CSRF tokens** in WebSocket handshakes.

#### Session Management

WebSocket connections often outlive normal sessions, requiring special handling.

**Use SameSite cookies** (`SameSite=Lax` or `Strict`) to prevent cross-site cookie transmission and strengthen CSWSH defenses.

**Handle session expiration** by implementing server-side validation for long-running connections. Close WebSocket connections when sessions expire. Re-validate user sessions periodically (every 30 minutes is common) to ensure they remain valid.

```javascript
// Example: Close WebSocket on session expiry
function validateSession(ws, sessionId) {
  if (!isSessionValid(sessionId)) {
    ws.close(1008, 'Session expired');
    return false;
  }
  return true;
}
```

**When users log out**, close all their WebSocket connections immediately. Maintain a mapping of sessions to active connections so you can invalidate WebSocket access the moment logout occurs.

**Token-based authentication:**

For enhanced security, use token-based authentication instead of relying solely on cookies. Tokens can be passed in query strings (note: tokens will appear in access logs and should be redacted) or as part of WebSocket messages after connection establishment. Message-based token passing avoids log exposure but requires protocol design considerations.

**Token refresh:**

Rotate tokens in long-lived connections to prevent hijacked sessions from persisting.

#### Message-Level Authorization

Don't assume WebSocket connection equals unlimited access. Check authorization for each action:

```javascript
ws.on('message', (data) => {
  const message = JSON.parse(data);
  
  // Check authorization for each action
  if (message.action === 'delete_user' && !user.hasRole('admin')) {
    ws.send(JSON.stringify({type: 'error', message: 'Access denied'}));
    return;
  }
  
  handleAuthorizedMessage(ws, user, message);
});
```

### Input Validation

Treat all WebSocket messages as untrusted input. WebSocket messages can carry injection payloads such as SQLi, XSS, and command injection.

**Validate message structure and content** using JSON schemas and allow-lists. Set reasonable size limits (typically 64KB or less) and implement rate limiting to prevent message flooding.

**For binary data**, verify file types using magic numbers rather than trusting content-type headers. Scan uploads for malware when appropriate, and use safe deserialization for protocols like protobuf or MessagePack.

```javascript
ws.on('message', (data, isBinary) => {
  if (isBinary) {
    // Validate binary data
    if (data.length > MAX_BINARY_SIZE) {
      ws.close(1009, 'Message too large');
      return;
    }
    
    // Check file type by magic numbers
    if (!isValidFileType(data)) {
      ws.close(1008, 'Invalid file type');
      return;
    }
  }
  
  processBinaryData(data);
});
```

**Always use `JSON.parse()` instead of `eval()`** for JSON processing - `eval()` enables code execution from untrusted input.

```javascript
// Safe
const message = JSON.parse(data);

// Dangerous - enables code execution
// const message = eval('(' + data + ')');
```

See the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md) for more details.

### Service Tunneling Risks

While WebSockets can tunnel TCP services (VNC, FTP, SSH), this creates security risks. If your application has XSS vulnerabilities, attackers could access these services directly from victims' browsers. If tunneling is necessary, implement additional authentication and access controls beyond the WebSocket layer.

### Denial-of-Service Protection

Persistent WebSocket connections increase DoS risk.

**Limit connections and resources** by restricting total connections and implementing per-user limits (preferred) or per-IP limits where user identification isn't available. Set **message size limits** (typically 64KB or less) and implement **rate limiting** to prevent message flooding - 100 messages per minute is a common starting point.

**Handle idle and dead connections** by implementing idle timeouts to close inactive connections. Use **heartbeat monitoring** with ping/pong frames to detect and clean up dead connections.

**Implement backpressure controls** to prevent memory exhaustion from fast message producers. Many WebSocket implementations lack proper flow control, allowing attackers to overwhelm server memory by sending messages faster than they can be processed.

```javascript
const wss = new WebSocket.Server({
  maxPayload: 64 * 1024
});
```

### Security Monitoring and Logging

Traditional HTTP access logs only capture the initial WebSocket upgrade request, not subsequent message traffic. You'll miss auth failures, injection attempts, rate-limit violations, and abuse.

**Log WebSocket events** including connection establishment and termination (with user identity, IP, and origin), authentication and authorization events during handshake and message processing, security violations like rate limiting triggers and message validation failures, and abnormal disconnections and protocol errors.

**Avoid logging sensitive data** - never log complete message contents, authentication tokens, session IDs, or personal information that could violate privacy regulations.

See the [Logging Cheat Sheet](Logging_Cheat_Sheet.md) for more details.

### Testing WebSocket Security

**Key security tests:**

- **Origin validation**: Connect from unauthorized domains
- **Authentication bypass**: Attempt connections without proper credentials
- **Message injection**: Send XSS, SQL injection, and command injection payloads
- **DoS resistance**: Test connection limits, message flooding, and oversized messages
- **Session management**: Test session expiration and logout handling

**Testing tools:**

- Browser developer tools for manual testing
- [wscat](https://github.com/websockets/wscat) for command-line WebSocket connections
- Custom scripts for automated vulnerability testing
- OWASP ZAP (includes WebSocket security testing features)

### Framework-Specific Best Practices

**Node.js:** Use the `verifyClient` callback for origin and authentication checks, set `maxPayload` limits, and disable `perMessageDeflate` compression to prevent security issues.

**Python:** With Django Channels, implement authentication middleware and origin validation. Use async exception handling to prevent application crashes from malformed WebSocket messages.

**Java Spring:** Configure allowed origins explicitly and integrate Spring Security for authorization. Set message size limits in your WebSocket container configuration to prevent resource exhaustion.

**Go:** When using Gorilla WebSocket, implement validation in your `CheckOrigin` function - don't just return `true`. Set read limits, implement timeouts, and use context cancellation for graceful connection cleanup.

#### Keep Dependencies Updated

Regularly update WebSocket libraries and monitor security advisories. Past versions of popular libraries (`ws`, Spring STOMP, Python `websockets`) have had critical security vulnerabilities including DoS and RCE issues.

## References

- [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md)
- [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md)
- [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md)
- [CWE-1385: Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html)
