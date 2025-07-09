# gRPC Security Cheat Sheet

## Introduction

gRPC (gRPC Remote Procedure Call) is a high-performance, language-neutral RPC framework that uses HTTP/2 for transport and Protocol Buffers for serialization. While gRPC offers significant performance advantages for microservices and distributed systems, it introduces unique security challenges that differ from traditional REST APIs.

The following sections cover essential security controls for protecting gRPC services from common attack vectors.

## Transport Security

### Always Use TLS in Production

Production deployments need TLS encryption to protect against eavesdropping and man-in-the-middle attacks.

```go
// Go - Secure server with TLS
creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
if err != nil {
    log.Fatalf("Failed to load TLS credentials: %v", err)
}
s := grpc.NewServer(grpc.Creds(creds))
```

Configure TLS 1.2 or higher with strong cipher suites, and disable weak protocols and ciphers.

### Implement Mutual TLS (mTLS) for Service-to-Service Communication

mTLS provides mutual authentication where both client and server verify each other's certificates, enabling zero-trust communication.

```go
// Go - mTLS client configuration
cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
caCert, err := ioutil.ReadFile(caCertFile)
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

creds := credentials.NewTLS(&tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      caCertPool,
})
conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
```

Use short-lived certificates (90 days or less) with automated rotation to limit the impact of compromised keys.

## Authentication and Authorization

### Implement Strong Authentication

Implement authentication checks for each protected service method.

#### Token-Based Authentication

```go
// Go - JWT token validation interceptor
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
    }
    
    tokens := md["authorization"]
    if len(tokens) == 0 {
        return nil, status.Errorf(codes.Unauthenticated, "missing authorization token")
    }
    
    token := strings.TrimPrefix(tokens[0], "Bearer ")
    if !validateJWT(token) {
        return nil, status.Errorf(codes.Unauthenticated, "invalid token")
    }
    
    return handler(ctx, req)
}
```

#### API Key Authentication

```go
// Go - API key validation
func validateAPIKey(ctx context.Context) error {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return status.Error(codes.Unauthenticated, "missing metadata")
    }
    
    keys := md["x-api-key"]
    if len(keys) == 0 || !isValidAPIKey(keys[0]) {
        return status.Error(codes.Unauthenticated, "invalid API key")
    }
    return nil
}
```

Implement token expiration and refresh mechanisms with short-lived tokens (15-60 minutes). Avoid embedding credentials in gRPC method parameters - use metadata headers.

### Enforce Granular Authorization

Implement method-level authorization checks based on the principle of least privilege.

```go
// Go - Role-based authorization
func authorizeMethod(ctx context.Context, methodName string, userRoles []string) error {
    requiredRole, exists := methodPermissions[methodName]
    if !exists {
        return status.Errorf(codes.PermissionDenied, "method not found")
    }
    
    for _, role := range userRoles {
        if role == requiredRole {
            return nil
        }
    }
    
    return status.Errorf(codes.PermissionDenied, "insufficient permissions")
}
```

Log all authorization failures to detect potential attacks and compliance violations.

## Input Validation and Data Security

### Validate All Protocol Buffer Messages

Protocol Buffers provide type safety but not business logic validation. Always perform thorough server-side validation.

```protobuf
// Use protoc-gen-validate for automatic validation
syntax = "proto3";
import "validate/validate.proto";

message CreateUserRequest {
  string email = 1 [(validate.rules).string.email = true];
  string name = 2 [(validate.rules).string = {min_len: 1, max_len: 100}];
  int32 age = 3 [(validate.rules).int32 = {gte: 0, lte: 150}];
}
```

Use allowlist validation for string inputs to prevent unexpected characters and injection attempts.

### Prevent Injection Attacks

Validate user input carefully when used in database queries or system operations.

```go
// Go - Safe database query with parameterization
func getUserByEmail(email string) (*User, error) {
    if !isValidEmail(email) {
        return nil, errors.New("invalid email format")
    }
    
    query := "SELECT id, name, email FROM users WHERE email = ?"
    row := db.QueryRow(query, email)
    
    var user User
    err := row.Scan(&user.ID, &user.Name, &user.Email)
    return &user, err
}
```

Always use prepared statements for database operations to prevent [SQL injection](SQL_Injection_Prevention_Cheat_Sheet.md).

### Implement Message Size Limits

gRPC's streaming capabilities allow clients to send arbitrarily large messages, potentially exhausting server memory and triggering denial-of-service conditions. Set clear limits on message sizes.

```go
// Go - Set message size limits
s := grpc.NewServer(
    grpc.MaxRecvMsgSize(4*1024*1024), // 4MB max receive
    grpc.MaxSendMsgSize(4*1024*1024), // 4MB max send
)
```

## Rate Limiting and Resource Protection

### Implement Request Rate Limiting

Protect services from request flooding and resource exhaustion.

```go
// Go - Rate limiting with memory management
import (
    "golang.org/x/time/rate"
    "sync"
    "time"
)

type RateLimiterStore struct {
    limiters map[string]*rateLimiterEntry
    mu       sync.RWMutex
}

type rateLimiterEntry struct {
    limiter  *rate.Limiter
    lastSeen time.Time
}

var store = &RateLimiterStore{
    limiters: make(map[string]*rateLimiterEntry),
}

func rateLimitInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    clientIP := getClientIP(ctx)
    
    store.mu.Lock()
    entry, exists := store.limiters[clientIP]
    if !exists {
        entry = &rateLimiterEntry{
            limiter:  rate.NewLimiter(rate.Limit(10), 20), // 10 req/sec, burst 20
            lastSeen: time.Now(),
        }
        store.limiters[clientIP] = entry
    }
    entry.lastSeen = time.Now()
    store.mu.Unlock()
    
    if !entry.limiter.Allow() {
        return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
    }
    
    return handler(ctx, req)
}

// Cleanup old limiters periodically
func cleanupOldLimiters() {
    store.mu.Lock()
    defer store.mu.Unlock()
    
    cutoff := time.Now().Add(-time.Hour)
    for ip, entry := range store.limiters {
        if entry.lastSeen.Before(cutoff) {
            delete(store.limiters, ip)
        }
    }
}
```

For production environments, use external rate limiting solutions like Redis or dedicated services.

### Set Appropriate Timeouts

Configure timeouts to prevent resource exhaustion from long-running requests.

```go
// Go - Server-side timeout for resource protection
func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
    // Check if client already set a deadline
    if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 5*time.Second {
        return processGetUser(ctx, req)
    }
    
    // Set defensive timeout to prevent resource exhaustion
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    
    return processGetUser(ctx, req)
}
```

Configure both client-side and server-side timeouts appropriately for your use case.

## Error Handling and Information Disclosure

### Secure Error Responses

Detailed error messages can reveal system internals to attackers. Return generic error messages while logging detailed information server-side.

```go
// Go - Secure error handling
func (s *server) ProcessPayment(ctx context.Context, req *pb.PaymentRequest) (*pb.PaymentResponse, error) {
    if err := validatePayment(req); err != nil {
        // Log detailed error server-side
        log.Printf("Payment validation failed for user %s: %v", getUserID(ctx), err)
        // Return generic error to client
        return nil, status.Error(codes.InvalidArgument, "invalid payment request")
    }
    
    // Continue processing...
}
```

Use appropriate gRPC status codes: `UNAUTHENTICATED` for auth failures, `PERMISSION_DENIED` for authorization failures, `INVALID_ARGUMENT` for validation errors.

### Implement Structured Logging

Log security events to help detect attacks and investigate incidents. Include authentication attempts, authorization failures, and suspicious activities.

```go
// Go - Security event logging
func logSecurityEvent(event string, userID string, clientIP string, success bool) {
    log.Printf("SECURITY_EVENT: %s | User: %s | IP: %s | Success: %t | Time: %s",
        event, userID, clientIP, success, time.Now().UTC().Format(time.RFC3339))
}
```

Include correlation IDs to track requests across distributed services and ensure logs don't contain sensitive data like passwords or tokens.

## Service Discovery and Reflection

### Disable gRPC Reflection in Production

gRPC reflection allows clients to discover service methods and message schemas at runtime, which is invaluable for development and debugging. However, this same capability gives attackers detailed information about your service's API surface, making it easier to craft targeted attacks.

```go
// Go - Conditional reflection (development only)
if os.Getenv("ENVIRONMENT") != "production" {
    reflection.Register(s)
}
```

### Secure Service Discovery

Service discovery mechanisms require protection to prevent attackers from injecting malicious service endpoints or intercepting service information.

**Consul with mTLS:**

```go
consulConfig := &api.Config{
    Address:    "consul.example.com:8500",
    Scheme:     "https",
    TLSConfig: &api.TLSConfig{
        CertFile: "/path/to/client.crt",
        KeyFile:  "/path/to/client.key",
        CAFile:   "/path/to/ca.crt",
    },
}
```

**Kubernetes RBAC:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: grpc-service-discovery
rules:
- apiGroups: [""]
  resources: ["services", "endpoints"]
  verbs: ["get", "list", "watch"]
```

Use service mesh solutions like Istio or Linkerd for automatic mTLS and centralized security policies.

## Monitoring and Incident Response

### Implement Security Monitoring

Monitor gRPC services for security events and potential attacks.

Key metrics to monitor:

- Request rates per method and client
- Authentication and authorization failure rates
- Error rates and types
- Unusual traffic patterns

Set up alerts for:

- High authentication failure rates
- Attempts to access non-existent methods
- Resource exhaustion patterns

### Enable Distributed Tracing

Track requests across microservices for security analysis.

```go
// Go - OpenTelemetry tracing with security context
tracer := otel.Tracer("grpc-service")
ctx, span := tracer.Start(ctx, "grpc.method.call")
defer span.End()

span.SetAttributes(
    attribute.String("grpc.method", info.FullMethod),
    attribute.String("client.ip", getClientIP(ctx)),
)
```

## Testing and Validation

### Perform gRPC Security Testing

Include gRPC-specific security tests in your development pipeline.

Test categories:

- Authentication bypass attempts
- Authorization boundary testing
- Input validation and injection testing
- Rate limiting effectiveness
- Message size limit enforcement

Use tools like `grpcurl` and custom test clients to verify security controls.

```bash
# Test authentication requirement
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 myservice.MyService/GetUser

# Test with invalid tokens
grpcurl -plaintext -H "authorization: Bearer invalid_token" \
  localhost:50051 myservice.MyService/GetUser
```

### Security Assessment Guidelines

- Test all gRPC methods for proper authentication and authorization
- Verify input validation on all message fields
- Test rate limiting and resource exhaustion protections
- Validate TLS configuration and certificate handling
- Check for information disclosure in error messages

## Language-Specific Considerations

### Go

- Use interceptors for cross-cutting security concerns
- Leverage the `context` package for request-scoped security information
- Explicitly configure TLS - Go's gRPC requires manual TLS setup

### Java

- Use Java's rich security ecosystem (Spring Security, etc.)
- Configure Netty properly for TLS settings
- Ensure ALPN support for HTTP/2

### Python

- Validate all inputs as Python's dynamic typing can hide type issues
- Use secure credential management for certificate storage
- Be aware of GIL limitations for high-concurrency scenarios

### C# (.NET)

- Leverage ASP.NET Core's built-in security features
- Use the `[Authorize]` attribute on service methods
- Configure HTTPS properly in production environments

## References

- [gRPC Authentication Documentation](https://grpc.io/docs/guides/auth/)
