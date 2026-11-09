# Multi-Tenant Application Security Cheat Sheet

## Introduction

Multi-tenant applications serve multiple customers (tenants) from a shared infrastructure, codebase, and often shared databases. This architecture is the foundation of modern SaaS platforms, offering cost efficiency and simplified operations.

However, multi-tenancy introduces critical security challenges: a single vulnerability can expose all tenants' data, misconfigurations can leak data across tenant boundaries, and resource contention can impact availability.

This cheat sheet provides best practices to secure multi-tenant applications, ensure tenant isolation, and prevent cross-tenant attacks.

## Key Risks

Use the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md) for baseline access controls.

- **Cross-Tenant Data Leakage**: Bugs or misconfigurations exposing one tenant's data to another.
- **Tenant Impersonation**: Attackers gaining access to another tenant's context or resources.
- **Broken Tenant Isolation**: Insufficient separation at database, cache, storage, or compute layers.
- **Insecure Direct Object References (IDOR)**: Accessing resources by manipulating tenant/resource IDs.
- **Noisy Neighbor Attacks**: One tenant exhausting shared resources, impacting others (DoS).
- **Privilege Escalation Across Tenants**: Exploiting admin functions to access other tenants.
- **Tenant Context Injection**: Manipulating tenant identifiers in requests, tokens, or headers.
- **Shared Resource Poisoning**: Cache poisoning, queue injection, or storage pollution affecting other tenants.
- **Insecure Tenant Onboarding/Offboarding**: Incomplete provisioning, unauthorized residual access, or retention beyond policy.
- **Audit & Compliance Gaps**: Insufficient tenant-specific logging for regulatory requirements.

## Best Practices

### 1. Tenant Identification & Context Management

- For tenant-scoped operations, establish tenant context early in the request lifecycle (middleware/interceptor).
- Choose identifiers appropriate to their exposure risk. Opaque, random identifiers can reduce enumeration, but they are not authorization controls.
- Treat client-supplied tenant identifiers as selectors only. Verify that the authenticated principal is authorized to act in the selected tenant.
- Bind tenant context to a server-verified identity and current tenant membership or service authorization.
- Propagate server-verified tenant context to components that need it for tenant-sensitive decisions or observability; do not let downstream components replace it with unverified input.

<details>
<summary>Bad example: Trusting client-supplied tenant ID</summary>

```python
# Dangerous: The header selects a tenant without checking the caller's membership.
# Query parameterization prevents injection, not cross-tenant access.
def get_tenant_data(request):
    tenant_id = request.headers.get("X-Tenant-ID")  # Attacker can modify!
    return db.execute("SELECT * FROM data WHERE tenant_id = :tid", {"tid": tenant_id})
```

</details>

<details>
<summary>Good example: Verifying tenant context against authenticated identity</summary>

```python
from functools import wraps
from contextvars import ContextVar
from typing import Optional

class TenantContext:
    def __init__(self, tenant_id: str, user_id: str, roles: list):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.roles = roles
        self.is_validated = True

# Request-local tenant context
current_tenant: ContextVar[Optional[TenantContext]] = ContextVar(
    'current_tenant', default=None
)

class TenantMiddleware:
    """Verify tenant context against authenticated identity and membership."""
    
    async def __call__(self, request, call_next):
        # A verified claim may select the tenant, but authorization still
        # depends on the issuer's guarantees or a current membership check.
        token_claims = request.state.verified_claims  # Set by auth middleware
        
        if not token_claims or "tenant_id" not in token_claims:
            return JSONResponse(status_code=401, content={"error": "Missing tenant context"})
        
        tenant_id = token_claims["tenant_id"]
        
        principal_id = token_claims["sub"]
        membership = await self.tenant_service.get_active_membership(
            principal_id, tenant_id
        )
        if not membership:
            return JSONResponse(status_code=403, content={"error": "Tenant access denied"})
        
        # Set tenant context for this request
        ctx = TenantContext(
            tenant_id=tenant_id,
            user_id=principal_id,
            roles=membership.roles
        )
        token = current_tenant.set(ctx)
        
        try:
            response = await call_next(request)
            return response
        finally:
            current_tenant.reset(token)

def require_tenant(func):
    """Decorator ensuring tenant context is present."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        ctx = current_tenant.get()
        if not ctx or not ctx.is_validated:
            raise SecurityException("Tenant context required")
        return await func(*args, **kwargs)
    return wrapper
```

</details>

### 2. Database Isolation Strategies

Choose an isolation strategy based on security requirements, compliance needs, and operational complexity:

| Strategy | Potential Boundary | Conditions and Trade-Offs |
|----------|--------------------|---------------------------|
| Separate Databases | Database and credential boundary | Strong when credentials, network access, administrative paths, and backups are isolated; higher operational cost |
| Separate Schemas | Namespace and database-role boundary | Requires disciplined grants, role separation, `search_path` handling, and migrations |
| Shared Tables (Row-Level) | Policy and row boundary | Requires enforceable tenant ownership, policy coverage for classified tenant-owned tables, constrained request roles, and negative-path tests |
| Hybrid | Varies by workload or tier | Document and test the boundary used for each data class |

<details>
<summary>Row-Level Security Implementation (PostgreSQL)</summary>

```sql
-- Enable RLS on tenant tables
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;

-- Create policy that restricts access to current tenant
CREATE POLICY tenant_isolation_policy ON orders
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE POLICY tenant_isolation_policy ON customers
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Force RLS for table owners (not superusers or BYPASSRLS roles)
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;
```

</details>

#### Do Not Use an RLS-Bypassing Role for Tenant-Scoped Request Paths

`FORCE ROW LEVEL SECURITY` applies policies to a table owner. It does not constrain a superuser or a role with the `BYPASSRLS` attribute; PostgreSQL documents that [both always bypass row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

- Connect the normal application request path with a least-privileged role that is neither a superuser nor a `BYPASSRLS` role.
- Reserve privileged connections for migrations and explicitly authorized administrative jobs.
- Do not serve ordinary tenant-scoped requests through a privileged connection. A privileged job must explicitly authorize and constrain its tenant set or cross-tenant operation because RLS will not do so.
- Check the deployed request role, not only the role declared in source-controlled configuration. PostgreSQL exposes `rolsuper` and `rolbypassrls` in [`pg_roles`](https://www.postgresql.org/docs/current/view-pg-roles.html).

#### Scope Tenant Context to the Transaction

The example policy depends on `current_setting('app.current_tenant')`. Because it omits the optional `missing_ok => true` argument, PostgreSQL raises an error if the setting does not exist instead of returning `NULL`; that is a deliberate fail-closed choice. The [`current_setting` documentation](https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-SET) describes both behaviors.

A normal `SET` persists until the session ends after its transaction commits, while [`SET LOCAL` lasts only for the current transaction](https://www.postgresql.org/docs/current/sql-set.html). When an application or connection pool reuses a database session without resetting it, session-scoped tenant state can therefore be inherited by the next request.

- Begin a transaction, set the tenant context with `SET LOCAL`, or call `set_config('app.current_tenant', tenant_id, true)`, then execute queries that depend on that setting in the same transaction. The `true` argument makes [`set_config` transaction-local](https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-SET).
- Re-establish the tenant context for every transaction. Never assume a newly borrowed connection has the correct setting.
- Fail closed if the tenant context is missing or invalid; do not fall back to an unscoped query.
- Commit or roll back before returning the connection to the pool.

SQLAlchemy [deprecated `QueryEvents.before_compile`](https://docs.sqlalchemy.org/en/20/orm/events.html#sqlalchemy.orm.QueryEvents.before_compile) because it does not cover ORM-level attribute and relationship loads. The current [recommended pattern](https://docs.sqlalchemy.org/en/20/orm/queryguide/api.html#sqlalchemy.orm.with_loader_criteria) combines `SessionEvents.do_orm_execute` with `with_loader_criteria` so criteria propagate to occurrences of the mapped entity, including eager and lazy relationship loads.

<details>
<summary>Application-Level Enforcement (Python/SQLAlchemy)</summary>

```python
from sqlalchemy import event, Column, String, text
from sqlalchemy.orm import Session, declared_attr, with_loader_criteria
from contextlib import contextmanager

class TenantMixin:
    """Mixin that adds tenant_id to models that inherit it."""
    
    @declared_attr
    def tenant_id(cls):
        return Column(String(36), nullable=False, index=True)

class TenantAwareSession(Session):
    """Session carrying tenant context for participating ORM operations."""
    
    def __init__(self, *args, tenant_id: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._tenant_id = tenant_id
    
    @property
    def tenant_id(self):
        if not self._tenant_id:
            raise SecurityException("Tenant ID not set on session")
        return self._tenant_id

# Add tenant criteria to ORM SELECTs issued through TenantAwareSession.
# with_loader_criteria propagates this rule to eager and lazy relationship loads.
@event.listens_for(TenantAwareSession, "do_orm_execute")
def add_tenant_filter(execute_state):
    if (
        execute_state.is_select
        and not execute_state.is_column_load
        and not execute_state.is_relationship_load
    ):
        tenant_id = execute_state.session.tenant_id
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                TenantMixin,
                lambda model: model.tenant_id == tenant_id,
                include_aliases=True,
            )
        )

# Set and validate tenant_id for new mapped objects in this session.
@event.listens_for(TenantAwareSession, "before_flush")
def set_tenant_on_insert(session, flush_context, instances):
    tenant_id = session.tenant_id
    for target in session.new:
        if isinstance(target, TenantMixin):
            if target.tenant_id not in (None, tenant_id):
                raise SecurityException("Object tenant does not match session")
            target.tenant_id = tenant_id

# Secure session factory
@contextmanager
def tenant_session(tenant_id: str):
    """Create a tenant-scoped database session."""
    ctx = current_tenant.get()
    if not ctx or ctx.tenant_id != tenant_id:
        raise SecurityException("Tenant session requires verified context")

    session = TenantAwareSession(bind=engine, tenant_id=tenant_id)
    
    try:
        # The final true makes the tenant context transaction-local
        session.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": tenant_id}
        )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

</details>

This ORM helper is defense in depth, not complete enforcement. It applies tenant criteria to ORM SELECTs issued through `TenantAwareSession`, with the criteria propagated to relationship loaders. Raw SQL, Core connections, bulk operations, and code using another session type require separate controls; use database policies or constrained roles as the final boundary where possible.

#### Verify Tenant Isolation

Test isolation through the same role, connection path, and pooling mode used by the application. A privileged test connection can make a correct policy appear broken, while a test that never exercises the deployed request role can miss a bypass.

- **Test the authorization matrix.** For each RLS-protected table, prove that expected cross-tenant operations are denied and expected same-tenant operations succeed. Where sharing or platform administration is intentional, test the exact permitted path and prove that it grants no broader access.
- **Discover coverage.** Derive the expected tenant-scoped table inventory from the schema or an explicit classification, then compare it with PostgreSQL's [`pg_class.relrowsecurity` and `relforcerowsecurity`](https://www.postgresql.org/docs/current/catalog-pg-class.html) and the [`pg_policies`](https://www.postgresql.org/docs/current/view-pg-policies.html) view. Fail when a new table has no classification, RLS is disabled, or the expected policy is absent.
- **Assert the request role.** In the deployed environment, fail a configuration test if the request-path role has `rolsuper` or `rolbypassrls` set.
- **Exercise connection reuse.** Run requests for two tenants over reused connections and prove the second request cannot observe the first request's tenant context.

A hand-maintained table list can drift: the same omission that leaves RLS off a new table can also leave that table out of the test. Prefer schema-derived discovery, or gate schema changes so each new table must be classified as tenant-scoped, intentionally shared, or otherwise isolated.

### 3. Preventing Cross-Tenant Data Access (IDOR Prevention)

- For each tenant-scoped resource, verify that the authenticated principal can act in the resource's tenant.
- Include tenant scope in the lookup or authorization policy when ownership is tenant-specific. A composite key (`tenant_id` + `resource_id`) is one option, not a universal requirement.
- Enforce authorization at a boundary traversed by every tenant-owned access path. Add data-layer checks as defense in depth where the architecture supports them.
- Treat opaque or random identifiers as defense in depth against enumeration, not as a substitute for authorization.

<details>
<summary>Bad example: Direct object reference without tenant validation</summary>

```python
# Dangerous: Only checks resource_id, not tenant ownership
@app.get("/api/documents/{document_id}")
async def get_document(document_id: str):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(404)
    return doc  # Could return another tenant's document!
```

</details>

<details>
<summary>Good example: Tenant-scoped resource access</summary>

```python
from uuid import UUID
from typing import TypeVar, Generic, Type

T = TypeVar('T')

class TenantScopedRepository(Generic[T]):
    """Repository that scopes the operations provided below to one tenant."""
    
    def __init__(self, model: Type[T], session: Session):
        self.model = model
        self.session = session
    
    @property
    def tenant_id(self) -> str:
        ctx = current_tenant.get()
        if not ctx:
            raise SecurityException("Tenant context required")
        return ctx.tenant_id
    
    def get_by_id(self, resource_id: UUID) -> Optional[T]:
        """Get resource only if it belongs to current tenant."""
        return self.session.query(self.model).filter(
            self.model.id == resource_id,
            self.model.tenant_id == self.tenant_id  # Tenant-owned resource
        ).first()
    
    def list_all(self, limit: int = 100, offset: int = 0) -> list[T]:
        """List resources for current tenant only."""
        return self.session.query(self.model).filter(
            self.model.tenant_id == self.tenant_id
        ).limit(limit).offset(offset).all()
    
    def create(self, **kwargs) -> T:
        """Create resource with tenant_id automatically set."""
        if 'tenant_id' in kwargs and kwargs['tenant_id'] != self.tenant_id:
            raise SecurityException("Cannot create resource for different tenant")
        
        kwargs['tenant_id'] = self.tenant_id
        instance = self.model(**kwargs)
        self.session.add(instance)
        return instance
    
    def delete(self, resource_id: UUID) -> bool:
        """Delete resource only if it belongs to current tenant."""
        result = self.session.query(self.model).filter(
            self.model.id == resource_id,
            self.model.tenant_id == self.tenant_id
        ).delete()
        return result > 0

# Usage
@app.get("/api/documents/{document_id}")
@require_tenant
async def get_document(document_id: UUID, db: Session = Depends(get_db)):
    repo = TenantScopedRepository(Document, db)
    doc = repo.get_by_id(document_id)
    if not doc:
        raise HTTPException(404, "Document not found")  # Don't reveal if it exists for other tenant
    return doc
```

</details>

### 4. Cache & Session Isolation

- Classify each cached value as global, tenant-scoped, or user-scoped.
- Include the tenant identifier in every cache key whose value or authorization varies by tenant.
- Give intentionally shared entries an explicit global namespace and document why they are safe to share.
- Include every other attribute that changes the result, such as user, locale, feature set, or permission version.
- Authorize the request before reading a protected cached value; cache-key separation does not replace authorization.
- Use separate cache instances for tenants that require stronger physical isolation.
- Choose TTL and invalidation behavior from freshness and authorization risk. Immutable, versioned global entries may not require expiry.

<details>
<summary>Bad example: Tenant-scoped data stored under a shared key</summary>

```python
# Dangerous: user IDs are not guaranteed to be unique across tenants,
# and the key incorrectly places tenant-scoped data in a global namespace.
def get_user_preferences(user_id: str):
    cache_key = f"global:user-preferences:{user_id}"
    cached = redis.get(cache_key)
    if cached:
        return json.loads(cached)
    # ...
```

</details>

<details>
<summary>Good example: Explicit tenant and global cache scopes</summary>

```python
import json

def tenant_cache_key(tenant_id: str, resource: str, item_id: str) -> str:
    return f"tenant:{tenant_id}:{resource}:{item_id}"

def global_cache_key(resource: str, version: str) -> str:
    return f"global:{resource}:{version}"

async def get_user_preferences(user_id: str):
    # These application-specific helpers derive tenant context from the
    # verified session and enforce access before the cache lookup.
    tenant_id = require_authenticated_tenant()
    await authorize_user_access(tenant_id, user_id)

    # Preferences vary by tenant, so tenant_id is part of the key.
    key = tenant_cache_key(tenant_id, "user-preferences", user_id)
    if cached := redis.get(key):
        return json.loads(cached)

    preferences = await db.fetch_preferences(tenant_id, user_id)
    redis.setex(key, 1800, json.dumps(preferences))
    return preferences

async def get_country_codes():
    # This versioned reference data is identical and authorized for all tenants.
    key = global_cache_key("country-codes", "v1")
    if cached := redis.get(key):
        return json.loads(cached)

    country_codes = await db.fetch_public_country_codes()
    redis.setex(key, 86400, json.dumps(country_codes))
    return country_codes
```

</details>

### 5. API, Asynchronous Work & Resource Controls

#### API Security & Rate Limiting

- When tenants share capacity or quotas, include tenant identity as one rate-limit dimension alongside any required global, endpoint, user, or IP limits.
- Rate limits at the HTTP boundary do not constrain every shared resource. Where tenant load can affect other tenants, apply tenant-aware limits or scheduling to the relevant bottlenecks, such as concurrent work, queued messages, database connections, fan-out, CPU, or memory. Retain global safety limits, and isolate a worker or resource pool when the risk or service commitment justifies the operational cost. The [AWS SaaS Lens](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/pe-selection.html) describes scaling, throttling, and selective resource isolation as complementary noisy-neighbor controls.
- Choose tenant quotas and limits according to capacity, abuse risk, contractual quotas, and service tiers rather than arbitrary hardcoded values. Support appropriate time windows and burst controls where applicable.
- Use shared counters with atomic updates when limits must apply across multiple application instances.
- Communicate throttling appropriately, such as returning HTTP 429 and a `Retry-After` header where applicable.
- Validate server-verified tenant context on every tenant-scoped API request, and mount tenant-aware middleware only on routes where tenant context is required. Public or global endpoints need no artificial tenant context.
- Bind API credentials to explicit tenant sets, environments, and permission scopes. An intentionally cross-tenant service identity must be separately authorized and least privileged.
- When B2B request signing is required, bind the signature to the security-relevant request context, such as tenant selection, target audience, method, path, body digest, and expiration, as applicable.

#### Tenant-Aware Asynchronous Work

Classify asynchronous work as global, tenant-scoped, or explicitly cross-tenant. A shared queue or topic is not itself a tenant-isolation boundary. [Microsoft's multitenant messaging guidance](https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/approaches/messaging) describes the trade-off between shared and dedicated messaging infrastructure and the need for application-enforced isolation when infrastructure is shared.

- For tenant-scoped work, derive tenant context from the authenticated producer and bind it to the message through trusted broker routing, authenticated metadata, or an integrity-protected payload. Do not let an unverified message field replace the producer's authorized scope.
- At the consumer, authenticate the producer or broker path, re-establish tenant context, and authorize the operation and target resource. Re-check time-sensitive membership or permission when delayed execution could make the original decision stale.
- Scope idempotency and deduplication keys, retry state, dead-letter access, and per-tenant ordering when their data or effects vary by tenant. Global jobs and authorized cross-tenant jobs should use explicit identities and scopes rather than a fabricated tenant.
- Apply tenant-aware queue depth, concurrency, and throughput controls when a shared worker fleet or broker is susceptible to noisy-neighbor load; retain service-wide limits for aggregate exhaustion.

### 6. File Storage & Blob Isolation

- Classify stored objects as global, tenant-scoped, or user-scoped. Keep intentionally shared assets in an explicit global namespace.
- Partition tenant-scoped objects with a tenant-aware object key, bucket, account, or enforceable storage policy. Object naming or prefixes alone are not authorization boundaries.
- Validate tenant identifiers against an allowlisted canonical format, alongside object-path validation. Reject absolute paths, `..` traversal components, and path-separator tricks that could escape the tenant namespace.
- Authorize the exact tenant, object, and operation before you upload or download an object, delete it, or generate a signed URL.
- Verify object ownership where appropriate; do not trust client-supplied tenant metadata as authorization proof.
- Restrict signed URLs to the required object and operation, with an appropriate expiration and revocation model. The tenant identifier does not need to appear in the URL when authorization happened before signing.
- Ensure tenant deletion targets only that tenant's objects. Use an exact tenant-prefix boundary, such as `tenants/acme/` rather than `tenants/acme`, because the latter could also match `tenants/acme-west/`.
- Account for object versions, replicas, and backups when applying retention and deletion policies.
- Use tenant-specific encryption keys when required by the risk or compliance model; shared managed keys with enforced access context may also be appropriate.

### 7. Tenant Onboarding & Offboarding Security

- Implement secure tenant provisioning with isolated resources. Treat onboarding as an all-or-nothing operation: if a step fails, remove partially created resources and record the failure.
- Generate unique encryption keys per tenant where required.
- Generate tenant API credentials with a cryptographically secure random generator and at least 128 bits of entropy. Return each credential once and store only a hash, never the plaintext value. An approved hash function such as SHA-256 is enough for a high-entropy random key, as [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html#lookupver) allows for look-up secrets. It does not protect low-entropy or user-chosen secrets; store those according to the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md).
- Apply a documented retention and deletion policy to every place tenant data lives: active stores, caches, object versions, replicas, exports, backups, and encryption keys. Restrict access to records kept for legal reasons.
- During offboarding, put the tenant into a state that rejects new operations, then revoke all active sessions, API keys, and other tenant-scoped credentials.
- When the retention policy permits deletion, remove the tenant's active data, cached data, and stored objects. Delete a tenant encryption key only after every copy encrypted under it, including backups, replicas, and records under legal hold, has passed its retention period, unless you intend to destroy those copies too.
- Maintain an audit trail of provisioning and deprovisioning, including failed and partial operations.
- Provide tenant data export when contract, regulation, or product policy requires it.

#### Tenant Backup Restore

A shared backup can contain data from several tenants. For a single-tenant recovery from a shared database, restore into a separate resource and selectively recover the target tenant's data, as described in [Azure's multitenant storage guidance](https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/approaches/storage-data).

- Authorize the operator for the target tenant and record the source backup, target, reason, and outcome.
- Check tenant ownership before copying records or objects into the live tenant scope. Do not give a tenant operator access to a shared backup.
- Reapply current access and retention rules; a backup can contain old memberships or data that should no longer be accessible.
- Test a backup with two tenants: recover one tenant, verify the other tenant's records and objects are absent, and reject a restore request by an unauthorized actor.

### 8. Logging, Monitoring & Audit

- Include server-verified tenant context in tenant-scoped security and audit events, and record the authenticated actor (user or service identity) when available. Do not require an authenticated actor for events where none exists; global infrastructure events may have no tenant.
- A centralized audit store is acceptable when read access enforces tenant scope. Cross-tenant audit reads and writes require explicit platform authorization.
- Distinguish tenant audit readers from platform auditors. Tenant administrator rights must not grant platform-wide audit access.
- Enforce append-only audit behavior through database permissions or storage controls such as write-once, read-many (WORM) rather than relying on application-level methods alone.
- Use tamper-evident mechanisms to detect modifications to stored audit records; tamper detection identifies modifications rather than preventing them.
- Monitor denied or unexpected cross-tenant access attempts without treating explicitly authorized platform operations as violations.
- Alert on tenant-isolation control failures and repeated suspicious denial patterns.
- Explicitly exclude secrets from logs and minimize sensitive tenant data. Mask or otherwise protect sensitive fields that genuinely need to be retained, according to the applicable policy.
- Apply the documented access and retention policy for each audit-data class.
- Configure collection, protection, and retention according to the [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

## Do's and Don'ts

**Do:**

- Derive tenant context from a server-verified identity and current membership or service authorization.
- Use an enforceable isolation boundary appropriate to the data and threat model; database controls such as RLS or schema and credential separation can provide defense in depth.
- Include tenant scope in queries, cache keys, and storage boundaries when the resource or result varies by tenant.
- Include tenant identity in rate limits and quotas when tenants share capacity or have tenant-level entitlements; retain any needed global, endpoint, user, or IP limits.
- Bound tenant consumption of other shared bottlenecks, such as queued work, concurrency, database connections, and compute, when those resources can create cross-tenant availability impact.
- Carry verified tenant context through tenant-scoped asynchronous work and re-establish authorization at the consumer.
- Log verified tenant context for tenant-scoped security and audit events.
- Enforce tenant ownership at a boundary traversed by every tenant-owned access path.
- Use separate encryption keys when the risk or compliance model requires cryptographic isolation.
- Apply and verify the documented retention and deletion policy during offboarding.
- Authorize and test tenant-scoped restores, especially when the source backup contains other tenants.
- Monitor and alert on denied or unexpected cross-tenant access attempts.
- For shared-table PostgreSQL RLS that uses a tenant setting, prefer transaction-local context and re-establish it for each transaction.
- For shared-table PostgreSQL RLS, inventory classified tenant-owned tables and test cross-tenant denial for each one.
- Verify that the ordinary tenant-request database role cannot bypass row security when RLS is the isolation boundary.

**Don't:**

- Treat tenant IDs from client headers or request parameters as authorization proof; they are selectors that require server-side verification.
- Use a shared cache key for data or authorization that varies by tenant.
- Rely on identifier complexity to prevent cross-tenant access.
- Allow an ordinary tenant-owned request path to perform an unscoped query; make any cross-tenant administrative path explicit, separately authorized, and auditable.
- Store tenant-owned data without an enforceable tenant association or isolation boundary; a literal `tenant_id` column is not required by every architecture.
- Give a tenant-scoped credential access to other tenants. Explicitly cross-tenant service credentials require their own least-privileged scope and controls.
- Skip authorization merely because a service is internal.
- Treat a tenant identifier in a queued message as authorization proof without authenticating the producer path and authorizing the consumer operation.
- Allow one tenant unbounded consumption of a shared queue, worker pool, connection pool, or other resource that can degrade other tenants.
- Retain tenant data beyond the documented retention policy without a contractual or legal basis and appropriate access restrictions.
- Restore a shared snapshot over live data to recover only one tenant.
- Log sensitive tenant data in plain text.
- Serve ordinary tenant-scoped PostgreSQL RLS request paths with a superuser or `BYPASSRLS` role.
- Use a session-scoped database tenant setting across pooled requests without reliable reset-on-checkout or equivalent isolation and connection-reuse tests; prefer transaction-local settings.

## References

- [AWS SaaS Lens: Tenant Isolation](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/tenant-isolation.html)
- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Microsoft: Messaging in Multitenant Solutions](https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/approaches/messaging)
