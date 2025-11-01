# API Security Cheat Sheet

## Introduction

APIs (Application Programming Interfaces) have become the backbone of modern applications, enabling communication between different systems, services, and applications. As organizations increasingly adopt microservices architectures and API-first approaches, securing these interfaces becomes critical to protecting sensitive data and maintaining system integrity.

This cheat sheet provides technology-agnostic security guidance applicable to all API types including REST, GraphQL, gRPC, WebSocket, SOAP, and emerging API patterns. It consolidates the [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) vulnerabilities with practical security controls and serves as a unified entry point for API security guidance.

For technology-specific implementations, refer to the dedicated cheat sheets: [REST Security](REST_Security_Cheat_Sheet.md), [GraphQL](GraphQL_Cheat_Sheet.md), [gRPC Security](gRPC_Security_Cheat_Sheet.md), and [Web Service Security](Web_Service_Security_Cheat_Sheet.md).

## OWASP API Security Top 10

### API1:2023 Broken Object Level Authorization (BOLA)

**Risk**: Attackers can access objects they shouldn't by manipulating object identifiers in API calls.

**Prevention**:

- Implement proper authorization checks for every object access
- Use user-specific object references instead of direct database IDs
- Validate user permissions for each requested object
- Implement consistent authorization mechanisms across all endpoints

```javascript
// Secure - User context validation
function getOrder(userId, orderId) {
    if (!orderBelongsToUser(orderId, userId)) {
        throw new Error('Unauthorized');
    }
    return getOrderById(orderId);
}
```

### API2:2023 Broken Authentication

**Risk**: Poorly implemented authentication allows attackers to compromise authentication tokens or exploit implementation flaws.

**Prevention**:

- Use established authentication standards (OAuth 2.0, OpenID Connect)
- Implement proper session management
- Use strong password policies and multi-factor authentication
- Secure credential storage and transmission
- Implement account lockout mechanisms

**Key Controls**:

- Always use HTTPS for authentication endpoints
- Implement proper token expiration and refresh mechanisms
- Use secure, random session identifiers
- Validate authentication tokens on every request

For more information, see [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) and [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md).

### API3:2023 Broken Object Property Level Authorization

**Risk**: Lack of proper authorization validation for object properties leads to information disclosure or unauthorized modifications.

**Prevention**:

- Implement field-level authorization controls
- Use data transfer objects (DTOs) to control exposed properties
- Validate user permissions for each property access
- Implement consistent property-level security across endpoints

```java
// Secure property filtering based on user role
public UserDTO serializeUser(User user, String userRole) {
    UserDTO dto = new UserDTO(user.getId(), user.getName(), user.getEmail());
    
    if ("admin".equals(userRole)) {
        dto.setSsn(user.getSsn());
        dto.setSalary(user.getSalary());
    }
    return dto;
}
```

### API4:2023 Unrestricted Resource Consumption

**Risk**: APIs without proper resource limits can be overwhelmed, leading to denial of service.

**Prevention**:

- Implement rate limiting per user/IP/API key
- Set maximum request size limits
- Implement timeout controls
- Use pagination for large data sets
- Monitor and alert on unusual resource consumption

**Implementation Examples**:

```yaml
# Rate limiting configuration
rate_limits:
  per_user: 1000/hour
  per_ip: 100/minute
  per_endpoint: 10/second
  
resource_limits:
  max_request_size: 10MB
  max_response_size: 50MB
  request_timeout: 30s
```

### API5:2023 Broken Function Level Authorization

**Risk**: Complex access control policies with different hierarchies and groups can lead to authorization flaws.

**Prevention**:

- Implement role-based access control (RBAC)
- Use principle of least privilege
- Regularly audit and test authorization logic
- Implement consistent authorization checks across all functions

```java
// Secure function-level authorization
@PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and #userId == authentication.principal.id)")
public User updateUser(@PathVariable Long userId, @RequestBody User user) {
    return userService.updateUser(userId, user);
}
```

For more information, see [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md).

### API6:2023 Unrestricted Access to Sensitive Business Flows

**Risk**: Lack of understanding of business flows can lead to abuse of legitimate functionality.

**Prevention**:

- Identify and protect sensitive business flows
- Implement business logic validation
- Use CAPTCHA or similar mechanisms for sensitive operations
- Monitor for unusual patterns in business flow usage
- Implement transaction limits and approval workflows

For more information on preventing abuse, see [Denial of Service Cheat Sheet](Denial_of_Service_Cheat_Sheet.md).

### API7:2023 Server Side Request Forgery (SSRF)

**Risk**: APIs that fetch remote resources without validating user-supplied URLs can be exploited to access internal systems.

**Prevention**:

- Validate and sanitize all user-supplied URLs
- Use allowlists for permitted domains/IPs
- Implement network segmentation
- Disable unused URL schemas (file://, gopher://, etc.)
- Use dedicated services for external requests

```javascript
// Secure URL validation
function isSafeUrl(url) {
    const parsed = new URL(url);
    
    // Only allow HTTP/HTTPS
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        return false;
    }
    
    // Check against allowlist
    return ALLOWED_DOMAINS.includes(parsed.hostname);
}
```

For more information, see [Server Side Request Forgery Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md).

### API8:2023 Security Misconfiguration

**Risk**: Insecure default configurations, incomplete configurations, or misconfigured HTTP headers.

**Prevention**:

- Use security-focused configuration templates
- Regularly update and patch all components
- Implement proper error handling without information disclosure
- Configure security headers appropriately
- Disable unnecessary features and endpoints

**Security Headers for APIs**:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'
Cache-Control: no-store
```

For more information, see [HTTP Headers Cheat Sheet](HTTP_Headers_Cheat_Sheet.md).

### API9:2023 Improper Inventory Management

**Risk**: Outdated API versions, missing patches, or unprotected debug endpoints.

**Prevention**:

- Maintain comprehensive API inventory
- Implement proper API versioning strategy
- Regularly audit and decommission unused APIs
- Monitor all API endpoints and versions
- Implement consistent security controls across all API versions

### API10:2023 Unsafe Consumption of APIs

**Risk**: Trusting data received from third-party APIs without proper validation.

**Prevention**:

- Validate all data received from external APIs
- Implement proper error handling for third-party API failures
- Use secure communication channels (TLS)
- Implement timeout and retry mechanisms
- Monitor third-party API dependencies

For more information on secure integrations, see [Third Party Javascript Management Cheat Sheet](Third_Party_Javascript_Management_Cheat_Sheet.md).

## Core Security Controls

### Transport Security

**Always Use HTTPS**:

- Enforce TLS 1.2 or higher for all API communications
- Use strong cipher suites and disable weak protocols
- Implement HTTP Strict Transport Security (HSTS)
- Consider mutual TLS (mTLS) for service-to-service communication

### Authentication and Authorization

**Token-Based Authentication**:

- Use industry-standard tokens (JWT, OAuth 2.0)
- Implement proper token validation and expiration
- Use secure token storage mechanisms
- Implement token refresh strategies

For more information, see [JSON Web Token for Java Cheat Sheet](JSON_Web_Token_for_Java_Cheat_Sheet.md).

**API Key Management**:

- Generate cryptographically strong API keys
- Implement key rotation policies
- Monitor API key usage patterns
- Revoke compromised keys immediately

For more information on key management, see [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md).

### Input Validation and Data Security

**Comprehensive Input Validation**:

- Validate all input parameters (headers, query parameters, body)
- Use strong typing and schema validation
- Implement allowlist validation where possible
- Sanitize data before processing

For more information on detailed validation techniques, see [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md).

**Output Encoding**:

- Encode output data appropriately for the context
- Prevent injection attacks through proper encoding
- Use content-type headers correctly

For more information on injection prevention techniques, see [Injection Prevention Cheat Sheet](Injection_Prevention_Cheat_Sheet.md), [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md), and [OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md).

### Error Handling and Logging

**Secure Error Responses**:

- Return generic error messages to clients
- Log detailed errors server-side for debugging
- Use appropriate HTTP status codes
- Avoid exposing system internals in error messages

**Security Logging**:

- Log all authentication and authorization events
- Monitor for suspicious patterns and anomalies
- Implement centralized logging for distributed systems
- Ensure logs don't contain sensitive data

For more information, see [Logging Cheat Sheet](Logging_Cheat_Sheet.md) and [Error Handling Cheat Sheet](Error_Handling_Cheat_Sheet.md).

## API Gateway Security

### Centralized Security Controls

API gateways provide a centralized point for implementing security controls:

- **Authentication and Authorization**: Centralized token validation
- **Rate Limiting**: Consistent rate limiting across all APIs
- **Request/Response Filtering**: Content validation and sanitization
- **Monitoring and Analytics**: Centralized logging and monitoring

### Gateway Configuration Best Practices

```yaml
# Example API Gateway Security Configuration
security:
  authentication:
    - jwt_validation
    - api_key_validation
  
  rate_limiting:
    default: 1000/hour
    premium: 10000/hour
  
  request_filtering:
    max_size: 10MB
    content_types: ['application/json', 'application/xml']
  
  response_filtering:
    remove_headers: ['Server', 'X-Powered-By']
    add_headers:
      'X-Content-Type-Options': 'nosniff'
      'X-Frame-Options': 'DENY'
```

## Microservices API Security

### Service-to-Service Communication

- Implement mutual TLS (mTLS) for service authentication
- Use service mesh for consistent security policies
- Implement circuit breakers for resilience
- Use secure service discovery mechanisms

For comprehensive microservices security guidance, see [Microservices Security Cheat Sheet](Microservices_Security_Cheat_Sheet.md).

### Zero Trust Architecture

- Verify every request regardless of source
- Implement least privilege access controls
- Use identity-based security policies
- Monitor all service communications

For more information on zero trust architecture, see [Zero Trust Architecture Cheat Sheet](Zero_Trust_Architecture_Cheat_Sheet.md).

## API Versioning Security

### Version Management

- Maintain security parity across API versions
- Implement deprecation policies for old versions
- Use semantic versioning for clear communication
- Document security changes between versions

For more information on secure development practices, see [Secure Code Review Cheat Sheet](Secure_Code_Review_Cheat_Sheet.md).

### Backward Compatibility

- Ensure security controls are not weakened in new versions
- Migrate users from deprecated versions securely
- Maintain security patches for supported versions

## Testing and Validation

### Security Testing

**Automated Security Testing**:

- Integrate security tests into CI/CD pipelines
- Use SAST/DAST tools for API security scanning
- Implement contract testing for API specifications
- Perform regular penetration testing

For more information on testing approaches, see [Attack Surface Analysis Cheat Sheet](Attack_Surface_Analysis_Cheat_Sheet.md).

**Manual Security Testing**:

- Test authentication and authorization boundaries
- Validate input handling and error responses
- Test business logic and workflow security
- Verify security controls under load

### API Documentation Security

- Keep API documentation up-to-date with security requirements
- Document authentication and authorization requirements
- Provide security examples and best practices
- Restrict access to internal API documentation

## Monitoring and Incident Response

### Security Monitoring

**Key Metrics to Monitor**:

- Authentication failure rates
- Authorization violations
- Rate limit violations
- Unusual traffic patterns
- Error rates and types

**Alerting and Response**:

- Implement real-time security alerting
- Define incident response procedures
- Maintain security playbooks for common scenarios
- Regular security incident drills

### Threat Intelligence

- Monitor for API-specific threats and vulnerabilities
- Subscribe to security advisories for used technologies
- Participate in threat intelligence sharing
- Regular security assessments and audits

## Compliance and Governance

### Regulatory Compliance

- Understand applicable regulations (GDPR, CCPA, PCI-DSS)
- Implement data protection controls
- Maintain audit trails for compliance
- Regular compliance assessments

For more information on privacy protection, see [User Privacy Protection Cheat Sheet](User_Privacy_Protection_Cheat_Sheet.md).

### API Governance

- Establish API security standards and guidelines
- Implement security review processes
- Maintain API security policies
- Regular security training for development teams

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OpenAPI Security Specification](https://swagger.io/specification/#security-scheme-object)
- [NIST SP 800-204 - Security Strategies for Microservices](https://csrc.nist.gov/publications/detail/sp/800-204/final)
- [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md)
- [GraphQL Cheat Sheet](GraphQL_Cheat_Sheet.md)
- [gRPC Security Cheat Sheet](gRPC_Security_Cheat_Sheet.md)
- [Web Service Security Cheat Sheet](Web_Service_Security_Cheat_Sheet.md)
- [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md)
- [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md)
