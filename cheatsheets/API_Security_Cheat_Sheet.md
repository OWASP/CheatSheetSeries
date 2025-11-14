# API Security Cheat Sheet

## Introduction

This cheat sheet provides **enterprise-grade API security patterns** that apply across all API technologies. It focuses on architectural security not covered by protocol-specific implementations.

### What This Sheet Covers

**Enterprise Security Patterns:**

- Multi-tenant isolation and data segregation
- Cross-organization API federation
- Centralized gateway security enforcement
- Automated threat response and orchestration

**Universal Security Controls:**

- Technology-agnostic authentication and authorization
- Cross-protocol rate limiting and throttling
- Unified security testing approaches

### What This Sheet Does NOT Cover

**Protocol-Specific Security** (see dedicated sheets):

- REST APIs → [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md)
- GraphQL APIs → [GraphQL Cheat Sheet](GraphQL_Cheat_Sheet.md)
- gRPC APIs → [gRPC Security Cheat Sheet](gRPC_Security_Cheat_Sheet.md)
- WebSocket APIs → [WebSocket Security Cheat Sheet](WebSocket_Security_Cheat_Sheet.md)

**Basic API Vulnerabilities:** See [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) for foundational API security guidance

## Enterprise Security Patterns

### Multi-Tenant Isolation

**Challenge:** Serving multiple customers from shared infrastructure while preventing data leakage

**Applies to:** All API types (REST, GraphQL, gRPC, WebSocket)

**Risk:** Data breaches, compliance violations, customer trust loss

Implement strict tenant boundaries by validating access permissions and applying tenant-specific filters to all data operations. This ensures complete isolation between tenants at the application layer.

```javascript
// Universal tenant isolation middleware
class TenantIsolationManager {
    constructor(userService, auditLogger) {
        this.userService = userService;
        this.auditLogger = auditLogger;
    }
    
    isolateTenant(request, tenantId) {
        // Input validation
        if (!tenantId || typeof tenantId !== 'string') {
            throw new InvalidTenantIdError('Tenant ID must be a valid string');
        }
        
        if (!this.validateTenantAccess(request.user, tenantId)) {
            this.auditLogger.logUnauthorizedAccess(request.user.id, tenantId);
            throw new UnauthorizedTenantAccessError('Access denied for tenant');
        }
        
        return {
            dataScope: `tenant_${this.sanitizeTenantId(tenantId)}.*`,
            queryFilter: { tenant_id: tenantId },
            rateLimitKey: `rate:${tenantId}:${request.user.id}`
        };
    }
    
    sanitizeTenantId(tenantId) {
        return tenantId.replace(/[^a-zA-Z0-9_-]/g, '');
    }
    
    validateTenantAccess(user, tenantId) {
        return user.tenants && user.tenants.includes(tenantId);
    }
}

// Custom error classes
class InvalidTenantIdError extends Error {
    constructor(message) {
        super(message);
        this.name = 'InvalidTenantIdError';
    }
}

class UnauthorizedTenantAccessError extends Error {
    constructor(message) {
        super(message);
        this.name = 'UnauthorizedTenantAccessError';
    }
}
```

### Cross-Organization Federation

**Challenge:** Secure API communication between different organizations

**Applies to:** B2B integrations, supply chain APIs, partner ecosystems

**Risk:** Unauthorized access, policy conflicts, trust violations

Establish mutual trust through certificate exchange and OAuth2 token validation, with dynamic trust scoring based on partner behavior. Trust levels determine access permissions and are continuously evaluated.

```java
// Federation security with trust scoring
@Service
@Transactional
public class FederationSecurityManager {
    
    private final Map<String, TrustConfig> trustStore = new ConcurrentHashMap<>();
    private final CertificateService certificateService;
    private final AuditLogger auditLogger;
    
    public FederationSecurityManager(CertificateService certificateService, AuditLogger auditLogger) {
        this.certificateService = certificateService;
        this.auditLogger = auditLogger;
    }
    
    public TrustConfig establishTrust(PartnerOrg partnerOrg) {
        // Validate input
        if (partnerOrg == null || StringUtils.isBlank(partnerOrg.getId())) {
            throw new InvalidPartnerException("Partner organization must have valid ID");
        }
        
        try {
            TrustConfig config = TrustConfig.builder()
                .mutualTLS(certificateService.exchangeCertificates(partnerOrg))
                .tokenExchange(setupOAuth2Exchange(partnerOrg))
                .trustScore(calculateInitialTrust(partnerOrg))
                .establishedAt(Instant.now())
                .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
                .build();
                
            trustStore.put(partnerOrg.getId(), config);
            auditLogger.logTrustEstablished(partnerOrg.getId());
            return config;
        } catch (Exception e) {
            auditLogger.logTrustFailure(partnerOrg.getId(), e.getMessage());
            throw new TrustEstablishmentException("Failed to establish trust", e);
        }
    }
    
    public AccessDecision enforceAccess(HttpServletRequest request, PartnerContext context) {
        TrustConfig config = trustStore.get(context.getPartnerId());
        if (config == null || config.getExpiresAt().isBefore(Instant.now())) {
            throw new ExpiredTrustException("Trust configuration expired or not found");
        }
        
        double currentTrust = evaluateTrust(context);
        double requiredTrust = getRequiredTrustLevel(request.getRequestURI());
        
        if (currentTrust < requiredTrust) {
            auditLogger.logInsufficientTrust(context.getPartnerId(), currentTrust, requiredTrust);
            throw new InsufficientTrustException(
                String.format("Trust level %.2f below required %.2f", currentTrust, requiredTrust)
            );
        }
        
        return grantAccess(request, context);
    }
    
    private double calculateInitialTrust(PartnerOrg partnerOrg) {
        // Base trust calculation
        double baseTrust = 0.5;
        if (partnerOrg.hasValidCertificate()) baseTrust += 0.2;
        if (partnerOrg.hasSecurityAudit()) baseTrust += 0.2;
        if (partnerOrg.hasComplianceCertification()) baseTrust += 0.1;
        return Math.min(baseTrust, 1.0);
    }
    
    private double evaluateTrust(PartnerContext context) {
        TrustConfig config = trustStore.get(context.getPartnerId());
        double currentTrust = config.getTrustScore();
        
        // Adjust based on recent behavior
        if (context.hasRecentFailures()) currentTrust -= 0.1;
        if (context.hasExcessiveRequests()) currentTrust -= 0.05;
        
        return Math.max(currentTrust, 0.0);
    }
    
    private double getRequiredTrustLevel(String uri) {
        if (uri.contains("/admin/")) return 0.9;
        if (uri.contains("/sensitive/")) return 0.7;
        return 0.5;
    }
    
    private AccessDecision grantAccess(HttpServletRequest request, PartnerContext context) {
        return AccessDecision.builder()
            .allowed(true)
            .partnerId(context.getPartnerId())
            .timestamp(Instant.now())
            .build();
    }
}
```

### Centralized Gateway Security

**Challenge:** Unified security enforcement across multiple backend services

**Applies to:** Microservices, distributed architectures, hybrid environments

**Risk:** Inconsistent security, policy gaps, single point of failure

Consolidate authentication, authorization, and rate limiting at the gateway layer to ensure consistent security policies across all backend services. Include circuit breaker patterns for resilience.

```javascript
// API Gateway security middleware
class APIGatewaySecurity {
    constructor(authService, rateLimitService, auditLogger) {
        this.authService = authService;
        this.rateLimitService = rateLimitService;
        this.auditLogger = auditLogger;
        this.circuitBreakers = new Map();
    }
    
    async enforcePolicy(request, serviceConfig) {
        // Validate service configuration
        if (!serviceConfig?.name || !Array.isArray(serviceConfig.requiredPermissions)) {
            throw new InvalidServiceConfigError('Service configuration must have name and permissions');
        }
        
        try {
            // Authentication
            const user = await this.authService.authenticateRequest(request);
            if (!user) {
                this.auditLogger.logAuthenticationFailure(request.ip, serviceConfig.name);
                throw new AuthenticationError('Authentication failed');
            }
            
            // Authorization
            if (!this.isAuthorized(user, serviceConfig.requiredPermissions)) {
                this.auditLogger.logAuthorizationFailure(user.id, serviceConfig.name);
                throw new UnauthorizedError('Insufficient permissions');
            }
            
            // Rate limiting
            const rateLimitKey = `${serviceConfig.name}:${user.id}`;
            if (!await this.rateLimitService.checkLimit(rateLimitKey, serviceConfig.rateLimit)) {
                this.auditLogger.logRateLimitExceeded(user.id, serviceConfig.name);
                throw new RateLimitExceededError('Rate limit exceeded');
            }
            
            // Circuit breaker check
            const circuitBreaker = this.getCircuitBreaker(serviceConfig.name);
            if (circuitBreaker.isOpen()) {
                throw new ServiceUnavailableError('Service temporarily unavailable');
            }
            
            return this.transformRequest(request, serviceConfig.transformRules);
        } catch (error) {
            this.auditLogger.logPolicyEnforcementError(serviceConfig.name, error.message);
            throw error;
        }
    }
    
    getCircuitBreaker(serviceName) {
        if (!this.circuitBreakers.has(serviceName)) {
            this.circuitBreakers.set(serviceName, new CircuitBreaker({
                failureThreshold: 5,
                recoveryTimeout: 30000
            }));
        }
        return this.circuitBreakers.get(serviceName);
    }
    
    isAuthorized(user, requiredPermissions) {
        return requiredPermissions.every(permission => 
            user.permissions && user.permissions.includes(permission)
        );
    }
    
    transformRequest(request, transformRules) {
        if (!transformRules) return request;
        
        const transformed = { ...request };
        transformRules.forEach(rule => {
            if (rule.type === 'header' && rule.action === 'add') {
                transformed.headers[rule.key] = rule.value;
            }
        });
        return transformed;
    }
}

// Circuit breaker implementation
class CircuitBreaker {
    constructor(options) {
        this.failureThreshold = options.failureThreshold || 5;
        this.recoveryTimeout = options.recoveryTimeout || 30000;
        this.failureCount = 0;
        this.lastFailureTime = null;
        this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    }
    
    isOpen() {
        if (this.state === 'OPEN') {
            if (Date.now() - this.lastFailureTime > this.recoveryTimeout) {
                this.state = 'HALF_OPEN';
                return false;
            }
            return true;
        }
        return false;
    }
}
```

### API Versioning Security

**Challenge:** Maintaining security across multiple API versions

**Applies to:** Version migration, backward compatibility, deprecation management

**Risk:** Version confusion attacks, deprecated endpoint exploitation, inconsistent security

Implement version-aware security policies that enforce stricter controls on newer versions while maintaining backward compatibility. Include automatic security upgrades and deprecation warnings.

```java
// Version-aware security enforcement
@Component
public class APIVersionSecurity {
    
    private final Map<String, VersionSecurityPolicy> versionPolicies = new HashMap<>();
    
    @PostConstruct
    public void initializePolicies() {
        // v1.0 - Legacy, minimal security
        versionPolicies.put("v1.0", VersionSecurityPolicy.builder()
            .authRequired(false)
            .rateLimitMultiplier(0.5) // Reduced limits for old versions
            .deprecationWarning(true)
            .build());
            
        // v2.0 - Enhanced security
        versionPolicies.put("v2.0", VersionSecurityPolicy.builder()
            .authRequired(true)
            .rateLimitMultiplier(1.0)
            .requireMFA(false)
            .build());
            
        // v3.0 - Maximum security
        versionPolicies.put("v3.0", VersionSecurityPolicy.builder()
            .authRequired(true)
            .rateLimitMultiplier(1.5) // Higher limits for new versions
            .requireMFA(true)
            .encryptionRequired(true)
            .build());
    }
    
    public SecurityContext enforceVersionSecurity(String version, HttpServletRequest request) {
        VersionSecurityPolicy policy = versionPolicies.get(version);
        if (policy == null) {
            throw new UnsupportedVersionException("API version not supported: " + version);
        }
        
        SecurityContext context = new SecurityContext();
        
        // Version-specific authentication
        if (policy.isAuthRequired()) {
            context.setUser(authenticateRequest(request, policy));
        }
        
        // Deprecation handling
        if (policy.hasDeprecationWarning()) {
            context.addWarning("API version " + version + " is deprecated. Migrate to v3.0");
        }
        
        // Rate limit adjustment
        context.setRateLimitMultiplier(policy.getRateLimitMultiplier());
        
        return context;
    }
}
```

## Universal Security Controls

### Cross-Protocol Rate Limiting

**Challenge:** Consistent rate limiting across different API technologies

**Applies to:** Mixed API environments, unified user quotas

**Risk:** API abuse, resource exhaustion, unfair usage

Use distributed rate limiting with Redis to maintain consistent quotas across all API protocols and instances. Implement sliding window algorithms for accurate rate calculations.

```java
// Universal rate limiting with Redis
@Service
public class UniversalRateLimit {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    public boolean checkLimit(String identifier, RateLimitConfig config) {
        String key = "rate_limit:" + identifier;
        String script = 
            "local current = redis.call('incr', KEYS[1]) " +
            "if current == 1 then " +
            "    redis.call('expire', KEYS[1], ARGV[1]) " +
            "end " +
            "return current <= tonumber(ARGV[2])";
            
        Boolean allowed = redisTemplate.execute(
            RedisScript.of(script, Boolean.class),
            Collections.singletonList(key),
            String.valueOf(config.getWindow()),
            String.valueOf(config.getLimit())
        );
        
        if (!allowed) {
            throw new RateLimitExceededException();
        }
        return true;
    }
}
```

### Technology-Agnostic Authentication

**Challenge:** Unified authentication across different API protocols

**Applies to:** Multi-protocol environments, SSO requirements

**Risk:** Authentication bypass, token confusion, protocol-specific vulnerabilities

Create protocol-aware authentication handlers that can process different authentication methods while maintaining consistent JWT validation and claims processing across all API types.

```javascript
// Multi-protocol authentication handler
class UniversalAuth {
    async authenticate(request, protocol) {
        const handlers = {
            'http': this.handleHTTPAuth,
            'websocket': this.handleWebSocketAuth,
            'webhook': this.handleWebhookAuth,
            'grpc': this.handleGRPCAuth
        };
        
        const handler = handlers[protocol];
        if (!handler) {
            throw new UnsupportedProtocolError(protocol);
        }
        
        return await handler.call(this, request);
    }
    
    // JWT validation for all protocols
    async validateJWT(token) {
        try {
            const decoded = jwt.verify(token, this.getPublicKey());
            
            // Universal claims validation
            this.validateClaims(decoded);
            
            return {
                userId: decoded.sub,
                permissions: decoded.permissions || [],
                tenantId: decoded.tenant,
                expiresAt: decoded.exp
            };
        } catch (error) {
            throw new InvalidTokenError(error.message);
        }
    }
}
```

## Security Operations

### Cross-Protocol Security Testing

**Challenge:** Consistent security validation across different API types

**Applies to:** CI/CD pipelines, security regression testing

**Risk:** Protocol-specific vulnerabilities, inconsistent security posture

Create unified test suites that validate security controls across all API protocols using protocol-specific adapters. This ensures consistent security validation regardless of the underlying API technology.

```javascript
// Multi-protocol security testing
class UniversalAPITester {
    async testAPI(endpoint, protocol, config) {
        const tests = {
            authentication: () => this.testAuth(endpoint, protocol),
            authorization: () => this.testAuthz(endpoint, protocol),
            injection: () => this.testInjection(endpoint, protocol),
            rateLimiting: () => this.testRateLimit(endpoint, protocol),
            dataExposure: () => this.testDataLeakage(endpoint, protocol)
        };
        
        const results = {};
        for (const [testName, testFunc] of Object.entries(tests)) {
            try {
                results[testName] = await testFunc();
            } catch (error) {
                results[testName] = { status: 'failed', error: error.message };
            }
        }
        
        return this.generateReport(results);
    }
    
    // Protocol-specific test adapters
    async testAuth(endpoint, protocol) {
        const adapters = {
            'rest': this.testRESTAuth,
            'graphql': this.testGraphQLAuth,
            'websocket': this.testWebSocketAuth,
            'webhook': this.testWebhookAuth
        };
        
        return await adapters[protocol](endpoint);
    }
    
    async testRESTAuth(endpoint) {
        const tests = [
            { name: 'no_token', headers: {}, expectedStatus: 401 },
            { name: 'invalid_token', headers: { 'Authorization': 'Bearer invalid' }, expectedStatus: 401 },
            { name: 'expired_token', headers: { 'Authorization': 'Bearer ' + this.getExpiredToken() }, expectedStatus: 401 }
        ];
        
        const results = [];
        for (const test of tests) {
            const response = await fetch(endpoint, { headers: test.headers });
            results.push({
                test: test.name,
                passed: response.status === test.expectedStatus
            });
        }
        return results;
    }
    
    generateReport(results) {
        const totalTests = Object.keys(results).length;
        const passedTests = Object.values(results).filter(r => r.status !== 'failed').length;
        
        return {
            summary: `${passedTests}/${totalTests} tests passed`,
            details: results,
            securityScore: (passedTests / totalTests) * 100
        };
    }
}
```

### Automated Threat Orchestration

**Challenge:** Coordinated threat response across multiple API technologies

**Applies to:** Enterprise environments, real-time threat response

**Risk:** Slow manual response, inconsistent threat handling, attack propagation

Implement intelligent threat analysis and automated response coordination across all API types. The system adapts security posture based on threat intelligence and coordinates responses to prevent attack propagation.

```javascript
// Cross-API threat response orchestrator
class APIThreatOrchestrator {
    constructor() {
        this.responseStrategies = new Map();
        this.threatIntelligence = new ThreatIntelligenceEngine();
    }

    async orchestrateResponse(threatEvent) {
        const threatContext = await this.analyzeThreat(threatEvent);
        const affectedAPIs = this.identifyAffectedAPIs(threatContext);

        // Coordinate response across multiple API types
        const responses = await Promise.all(
            affectedAPIs.map(api => this.executeResponse(api, threatContext))
        );

        return this.consolidateResponses(responses);
    }

    async executeResponse(api, threatContext) {
        const strategy = this.getResponseStrategy(api.type, threatContext.severity);

        return {
            apiId: api.id,
            actions: await strategy.execute(api, threatContext),
            timestamp: Date.now()
        };
    }

    // Adaptive security posture adjustment
    async adaptSecurityPosture(threatLandscape) {
        const adjustments = {
            rateLimits: this.calculateRateLimitAdjustments(threatLandscape),
            authStrength: this.adjustAuthRequirements(threatLandscape),
            monitoring: this.enhanceMonitoring(threatLandscape)
        };

        return this.applyGlobalAdjustments(adjustments);
    }
    
    async analyzeThreat(threatEvent) {
        return {
            severity: this.calculateSeverity(threatEvent),
            type: threatEvent.type,
            source: threatEvent.source,
            affectedProtocols: this.identifyAffectedProtocols(threatEvent)
        };
    }
    
    identifyAffectedAPIs(threatContext) {
        // Return APIs that match threat characteristics
        return this.apiRegistry.filter(api => 
            threatContext.affectedProtocols.includes(api.protocol)
        );
    }
    
    getResponseStrategy(apiType, severity) {
        const strategies = {
            'high': new ImmediateBlockStrategy(),
            'medium': new ThrottleStrategy(),
            'low': new MonitorStrategy()
        };
        return strategies[severity] || strategies['low'];
    }
    
    consolidateResponses(responses) {
        return {
            totalAPIs: responses.length,
            actionsExecuted: responses.reduce((sum, r) => sum + r.actions.length, 0),
            timestamp: Date.now()
        };
    }
}
```

## Performance Considerations

### Security Control Performance Impact

**Authentication Overhead:**

- JWT validation: ~1-2ms per request
- Database user lookup: ~5-10ms per request
- **Optimization:** Use Redis caching for user data (reduces to ~0.5ms)

**Rate Limiting Performance:**

- In-memory rate limiting: ~0.1ms per request
- Redis-based rate limiting: ~1-3ms per request
- **Optimization:** Use local caching with Redis sync for high-traffic APIs

**Encryption Impact:**

- TLS handshake: ~50-100ms (one-time per connection)
- Request/response encryption: ~1-5ms per request
- **Optimization:** Use connection pooling and HTTP/2 multiplexing

```javascript
// Performance-optimized security middleware
class OptimizedSecurityMiddleware {
    constructor() {
        this.userCache = new LRUCache({ max: 10000, ttl: 300000 }); // 5min TTL
        this.rateLimitCache = new Map();
    }
    
    async authenticate(token) {
        // Check cache first (0.1ms vs 10ms DB lookup)
        const cached = this.userCache.get(token);
        if (cached && cached.expiresAt > Date.now()) {
            return cached.user;
        }
        
        // Fallback to database
        const user = await this.userService.validateToken(token);
        this.userCache.set(token, { user, expiresAt: Date.now() + 300000 });
        return user;
    }
    
    // Batch rate limit checks for better performance
    async checkRateLimits(requests) {
        const pipeline = this.redis.pipeline();
        requests.forEach(req => {
            pipeline.incr(`rate:${req.userId}:${req.endpoint}`);
        });
        
        const results = await pipeline.exec();
        return results.map((result, index) => ({
            allowed: result[1] <= requests[index].limit,
            current: result[1]
        }));
    }
}
```

**Performance Monitoring:**

- Monitor security middleware latency
- Set SLA targets: <5ms for authentication, <2ms for authorization
- Use circuit breakers for external security services
- Implement graceful degradation for non-critical security checks

## References

### OWASP Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) - Core API vulnerabilities
- [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md) - REST-specific security patterns
- [GraphQL Cheat Sheet](GraphQL_Cheat_Sheet.md) - GraphQL security guidance
- [WebSocket Security Cheat Sheet](WebSocket_Security_Cheat_Sheet.md) - WebSocket security patterns
- [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) - Authentication best practices
- [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md) - Authorization patterns

### Standards and Specifications

- [NIST SP 800-204 - Security Strategies for Microservices](https://csrc.nist.gov/pubs/sp/800/204/final)
- [NIST SP 800-207 - Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [ISO/IEC 27001:2022 - Information Security Management](https://www.iso.org/standard/27001)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 8725 - JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OpenAPI Security Specification v3.1.0](https://spec.openapis.org/oas/v3.1.0#security-scheme-object)
- [NIST Cybersecurity Framework v1.1](https://www.nist.gov/cyberframework)
- [ISO/IEC 27034 - Application Security](https://www.iso.org/standard/44378.html)
