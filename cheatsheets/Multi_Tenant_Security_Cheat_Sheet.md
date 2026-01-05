# Multi-Tenant Application Security Cheat Sheet

## Introduction

Multi-tenant applications serve multiple customers (tenants) from a shared infrastructure, codebase, and often shared databases. This architecture is the foundation of modern SaaS platforms, offering cost efficiency and simplified operations.

However, multi-tenancy introduces critical security challenges: a single vulnerability can expose all tenants' data, misconfigurations can leak data across tenant boundaries, and resource contention can impact availability.

This cheat sheet provides best practices to secure multi-tenant applications, ensure tenant isolation, and prevent cross-tenant attacks.

## Key Risks

- **Cross-Tenant Data Leakage**: Bugs or misconfigurations exposing one tenant's data to another.
- **Tenant Impersonation**: Attackers gaining access to another tenant's context or resources.
- **Broken Tenant Isolation**: Insufficient separation at database, cache, storage, or compute layers.
- **Insecure Direct Object References (IDOR)**: Accessing resources by manipulating tenant/resource IDs.
- **Noisy Neighbor Attacks**: One tenant exhausting shared resources, impacting others (DoS).
- **Privilege Escalation Across Tenants**: Exploiting admin functions to access other tenants.
- **Tenant Context Injection**: Manipulating tenant identifiers in requests, tokens, or headers.
- **Shared Resource Poisoning**: Cache poisoning, queue injection, or storage pollution affecting other tenants.
- **Insecure Tenant Onboarding/Offboarding**: Incomplete provisioning or data retention after deletion.
- **Audit & Compliance Gaps**: Insufficient tenant-specific logging for regulatory requirements.

## Best Practices

### 1. Tenant Identification & Context Management

- Establish tenant context early in the request lifecycle (middleware/interceptor).
- Use cryptographically secure, non-guessable tenant identifiers.
- Never trust client-supplied tenant IDs without validation.
- Bind tenant context to the authenticated user session.
- Propagate tenant context securely through all application layers.

<details>
<summary>Bad example: Trusting client-supplied tenant ID</summary>

```python
# Dangerous: Tenant ID from request header without validation/query parameterization
def get_tenant_data(request):
    tenant_id = request.headers.get("X-Tenant-ID")  # Attacker can modify!
    return db.execute("SELECT * FROM data WHERE tenant_id = :tid", {"tid": tenant_id})
```

</details>

<details>
<summary>Good example: Deriving tenant from authenticated session</summary>

```python
from functools import wraps
from contextvars import ContextVar
from typing import Optional

# Thread-safe tenant context
current_tenant: ContextVar[Optional[str]] = ContextVar('current_tenant', default=None)

class TenantContext:
    def __init__(self, tenant_id: str, user_id: str, roles: list):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.roles = roles
        self.is_validated = True

class TenantMiddleware:
    """Extract and validate tenant context from authenticated session."""
    
    async def __call__(self, request, call_next):
        # Get tenant from verified JWT claims - NOT from headers
        token_claims = request.state.verified_claims  # Set by auth middleware
        
        if not token_claims or "tenant_id" not in token_claims:
            return JSONResponse(status_code=401, content={"error": "Missing tenant context"})
        
        tenant_id = token_claims["tenant_id"]
        
        # Validate tenant exists and is active
        tenant = await self.tenant_service.get_active_tenant(tenant_id)
        if not tenant:
            return JSONResponse(status_code=403, content={"error": "Invalid tenant"})
        
        # Set tenant context for this request
        ctx = TenantContext(
            tenant_id=tenant_id,
            user_id=token_claims["sub"],
            roles=token_claims.get("roles", [])
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

| Strategy | Isolation Level | Use Case |
|----------|----------------|----------|
| Separate Databases | Highest | Regulated industries, enterprise clients |
| Separate Schemas | High | Balance of isolation and manageability |
| Shared Tables (Row-Level) | Medium | Cost-sensitive, high tenant count |
| Hybrid | Variable | Different tiers for different customers |

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

-- Force RLS for table owners too (important!)
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;
```

</details>

<details>
<summary>Application-Level Enforcement (Python/SQLAlchemy)</summary>

```python
from sqlalchemy import event, Column, String
from sqlalchemy.orm import Session, Query
from sqlalchemy.ext.declarative import declared_attr
from contextlib import contextmanager

class TenantMixin:
    """Mixin that adds tenant_id to all models."""
    
    @declared_attr
    def tenant_id(cls):
        return Column(String(36), nullable=False, index=True)

class TenantAwareSession(Session):
    """Session that automatically filters by tenant."""
    
    def __init__(self, *args, tenant_id: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._tenant_id = tenant_id
    
    @property
    def tenant_id(self):
        if not self._tenant_id:
            raise SecurityException("Tenant ID not set on session")
        return self._tenant_id

# Automatically add tenant filter to all queries
@event.listens_for(Query, "before_compile", retval=True)
def add_tenant_filter(query):
    tenant_id = current_tenant.get()
    if not tenant_id:
        raise SecurityException("No tenant context for query")
    
    for desc in query.column_descriptions:
        entity = desc.get('entity')
        if entity and hasattr(entity, 'tenant_id'):
            query = query.filter(entity.tenant_id == tenant_id.tenant_id)
    
    return query

# Automatically set tenant_id on insert
@event.listens_for(TenantMixin, "before_insert", propagate=True)
def set_tenant_on_insert(mapper, connection, target):
    ctx = current_tenant.get()
    if not ctx:
        raise SecurityException("Cannot insert without tenant context")
    target.tenant_id = ctx.tenant_id

# Secure session factory
@contextmanager
def tenant_session(tenant_id: str):
    """Create a tenant-scoped database session."""
    session = TenantAwareSession(bind=engine, tenant_id=tenant_id)
    
    # Set PostgreSQL RLS context
    session.execute(f"SELECT set_config('app.current_tenant', :tenant_id, true);")

    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

</details>

### 3. Preventing Cross-Tenant Data Access (IDOR Prevention)

- Always validate that requested resources belong to the current tenant.
- Use composite keys (tenant_id + resource_id) for all lookups.
- Implement authorization checks at the data access layer, not just API layer.
- Avoid exposing sequential or guessable IDs.

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
    """Repository that enforces tenant isolation on all operations."""
    
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
            self.model.tenant_id == self.tenant_id  # Always include tenant check
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

- Prefix all cache keys with tenant identifier.
- Use separate cache namespaces or instances for sensitive tenants.
- Implement cache key validation to prevent injection.
- Set appropriate TTLs and validate tenant on cache retrieval.

<details>
<summary>Bad example: Shared cache without tenant isolation</summary>

```python
# Dangerous: Cache key collision between tenants
def get_user_preferences(user_id: str):
    cache_key = f"preferences:{user_id}"  # Same key for different tenants!
    cached = redis.get(cache_key)
    if cached:
        return json.loads(cached)
    # ...
```

</details>

<details>
<summary>Good example: Tenant-isolated caching</summary>

```python
import hashlib
import json
from typing import Optional, Any
from functools import wraps

class TenantAwareCache:
    """Cache implementation with tenant isolation."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.default_ttl = 3600
    
    def _build_key(self, tenant_id: str, key: str) -> str:
        """Build tenant-scoped cache key."""
        # Validate key format to prevent injection
        if not key or any(c in key for c in ['{', '}', '\n', '\r']):
            raise ValueError("Invalid cache key format")
        
        # Use hash of tenant_id to prevent key enumeration
        tenant_hash = hashlib.sha256(tenant_id.encode()).hexdigest()[:16]
        return f"t:{tenant_hash}:{key}"
    
    def get(self, key: str, tenant_id: str = None) -> Optional[Any]:
        """Get cached value for current tenant."""
        tenant_id = tenant_id or current_tenant.get().tenant_id
        full_key = self._build_key(tenant_id, key)
        
        cached = self.redis.get(full_key)
        if cached:
            data = json.loads(cached)
            # Verify tenant_id in cached data matches (defense in depth)
            if data.get("_tenant_id") != tenant_id:
                self.redis.delete(full_key)  # Purge potentially poisoned entry
                return None
            return data.get("value")
        return None
    
    def set(self, key: str, value: Any, ttl: int = None, tenant_id: str = None):
        """Set cached value for current tenant."""
        tenant_id = tenant_id or current_tenant.get().tenant_id
        full_key = self._build_key(tenant_id, key)
        
        # Include tenant_id in cached data for verification
        data = {
            "_tenant_id": tenant_id,
            "value": value
        }
        
        self.redis.setex(full_key, ttl or self.default_ttl, json.dumps(data))
    
    def invalidate_tenant(self, tenant_id: str):
        """Invalidate all cache entries for a tenant."""
        tenant_hash = hashlib.sha256(tenant_id.encode()).hexdigest()[:16]
        pattern = f"t:{tenant_hash}:*"
        
        cursor = 0
        while True:
            cursor, keys = self.redis.scan(cursor, match=pattern, count=1000)
            if keys:
                self.redis.delete(*keys)
            if cursor == 0:
                break

def tenant_cached(key_template: str, ttl: int = 3600):
    """Decorator for tenant-aware caching."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache = get_tenant_cache()
            cache_key = key_template.format(**kwargs)
            
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
            
            result = await func(*args, **kwargs)
            cache.set(cache_key, result, ttl=ttl)
            return result
        return wrapper
    return decorator

# Usage
@tenant_cached("user_prefs:{user_id}", ttl=1800)
async def get_user_preferences(user_id: str):
    # This is automatically cached per-tenant
    return await db.fetch_preferences(user_id)
```

</details>

### 5. API Security & Rate Limiting

- Implement per-tenant rate limiting and quotas.
- Apply tenant-specific API throttling.
- Validate tenant context on every API request.
- Use separate API keys per tenant.
- Implement tenant-aware request signing for B2B APIs.

<details>
<summary>Tenant-Aware Rate Limiting</summary>

```python
import time
from dataclasses import dataclass
from enum import Enum

class TenantTier(Enum):
    FREE = "free"
    STARTER = "starter"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

@dataclass
class RateLimitConfig:
    requests_per_minute: int
    requests_per_day: int
    burst_size: int

TIER_LIMITS = {
    TenantTier.FREE: RateLimitConfig(60, 1000, 10),
    TenantTier.STARTER: RateLimitConfig(300, 10000, 50),
    TenantTier.BUSINESS: RateLimitConfig(1000, 100000, 100),
    TenantTier.ENTERPRISE: RateLimitConfig(5000, 1000000, 500),
}

class TenantRateLimiter:
    """Per-tenant rate limiting with tier support."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def check_rate_limit(self, tenant_id: str, tenant_tier: TenantTier) -> dict:
        """Check and update rate limit for tenant."""
        config = TIER_LIMITS[tenant_tier]
        now = time.time()
        minute_key = f"rl:{tenant_id}:min:{int(now // 60)}"
        day_key = f"rl:{tenant_id}:day:{int(now // 86400)}"
        
        pipe = self.redis.pipeline()
        
        # Increment counters
        pipe.incr(minute_key)
        pipe.expire(minute_key, 60)
        pipe.incr(day_key)
        pipe.expire(day_key, 86400)
        
        results = pipe.execute()
        minute_count = results[0]
        day_count = results[2]
        
        # Check limits
        if minute_count > config.requests_per_minute:
            return {
                "allowed": False,
                "reason": "minute_limit_exceeded",
                "retry_after": 60 - (now % 60),
                "limit": config.requests_per_minute
            }
        
        if day_count > config.requests_per_day:
            return {
                "allowed": False,
                "reason": "daily_limit_exceeded",
                "retry_after": 86400 - (now % 86400),
                "limit": config.requests_per_day
            }
        
        return {
            "allowed": True,
            "remaining_minute": config.requests_per_minute - minute_count,
            "remaining_day": config.requests_per_day - day_count
        }

class RateLimitMiddleware:
    """Middleware that enforces tenant rate limits."""
    
    async def __call__(self, request, call_next):
        ctx = current_tenant.get()
        if not ctx:
            return await call_next(request)
        
        tenant = await self.tenant_service.get_tenant(ctx.tenant_id)
        result = await self.rate_limiter.check_rate_limit(
            ctx.tenant_id, 
            tenant.tier
        )
        
        if not result["allowed"]:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "details": result},
                headers={
                    "Retry-After": str(int(result["retry_after"])),
                    "X-RateLimit-Limit": str(result["limit"]),
                    "X-RateLimit-Remaining": "0"
                }
            )
        
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Remaining-Minute"] = str(result["remaining_minute"])
        response.headers["X-RateLimit-Remaining-Day"] = str(result["remaining_day"])
        
        return response
```

</details>

### 6. File Storage & Blob Isolation

- Use tenant-prefixed paths for all file storage.
- Implement storage access policies per tenant.
- Validate tenant ownership before serving files.
- Use signed URLs with tenant context embedded.
- Encrypt files at rest with tenant-specific keys (for high-security requirements).

<details>
<summary>Secure Multi-Tenant File Storage</summary>

```python
import boto3
from botocore.config import Config
from datetime import datetime, timedelta
import hashlib
import hmac

class TenantFileStorage:
    """S3-based file storage with tenant isolation."""
    
    def __init__(self, bucket_name: str, kms_key_id: str = None):
        self.bucket = bucket_name
        self.s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
        self.kms_key_id = kms_key_id
    
    def _get_tenant_prefix(self, tenant_id: str) -> str:
        """Generate tenant-specific path prefix."""
        # Use hashed prefix to prevent enumeration
        tenant_hash = hashlib.sha256(tenant_id.encode()).hexdigest()[:12]
        return f"tenants/{tenant_hash}"
    
    def _build_key(self, tenant_id: str, file_path: str) -> str:
        """Build full S3 key with tenant isolation."""
        # Sanitize file path to prevent traversal
        safe_path = file_path.lstrip('/').replace('..', '')
        return f"{self._get_tenant_prefix(tenant_id)}/{safe_path}"
    
    async def upload_file(self, tenant_id: str, file_path: str, 
                         content: bytes, content_type: str) -> dict:
        """Upload file for tenant."""
        key = self._build_key(tenant_id, file_path)
        
        extra_args = {
            'ContentType': content_type,
            'Metadata': {
                'tenant-id': tenant_id,
                'uploaded-at': datetime.utcnow().isoformat()
            }
        }
        
        # Use tenant-specific KMS key if available
        if self.kms_key_id:
            extra_args['ServerSideEncryption'] = 'aws:kms'
            extra_args['SSEKMSKeyId'] = self.kms_key_id
        
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=content,
            **extra_args
        )
        
        return {"key": key, "size": len(content)}
    
    async def get_file(self, tenant_id: str, file_path: str) -> Optional[bytes]:
        """Get file only if it belongs to tenant."""
        key = self._build_key(tenant_id, file_path)
        
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            
            # Verify tenant ownership from metadata
            metadata_tenant = response.get('Metadata', {}).get('tenant-id')
            if metadata_tenant != tenant_id:
                raise SecurityException("Tenant mismatch in file metadata")
            
            return response['Body'].read()
        except self.s3.exceptions.NoSuchKey:
            return None
    
    def generate_presigned_url(self, tenant_id: str, file_path: str,
                               expiration: int = 3600, 
                               operation: str = 'get_object') -> str:
        """Generate presigned URL with tenant validation."""
        key = self._build_key(tenant_id, file_path)
        
        # Include tenant_id in the signed URL for validation
        url = self.s3.generate_presigned_url(
            ClientMethod=operation,
            Params={
                'Bucket': self.bucket,
                'Key': key,
            },
            ExpiresIn=expiration
        )
        
        return url
    
    async def delete_tenant_data(self, tenant_id: str):
        """Delete all files for a tenant (for offboarding)."""
        prefix = self._get_tenant_prefix(tenant_id)
        
        paginator = self.s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            objects = page.get('Contents', [])
            if objects:
                self.s3.delete_objects(
                    Bucket=self.bucket,
                    Delete={'Objects': [{'Key': obj['Key']} for obj in objects]}
                )
```

</details>

### 7. Tenant Onboarding & Offboarding Security

- Implement secure tenant provisioning with isolated resources.
- Generate unique encryption keys per tenant where required.
- Ensure complete data deletion on tenant offboarding.
- Maintain audit trail of provisioning/deprovisioning.
- Implement data export for tenant portability.

<details>
<summary>Secure Tenant Lifecycle Management</summary>

```python
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import secrets

class TenantStatus(Enum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    OFFBOARDING = "offboarding"
    DELETED = "deleted"

@dataclass
class TenantProvisioningResult:
    tenant_id: str
    status: TenantStatus
    api_key: str
    database_schema: str
    storage_prefix: str

class TenantLifecycleManager:
    """Manages secure tenant onboarding and offboarding."""
    
    def __init__(self, db, cache, storage, audit_log):
        self.db = db
        self.cache = cache
        self.storage = storage
        self.audit = audit_log
    
    async def provision_tenant(self, tenant_name: str, admin_email: str,
                               tier: TenantTier) -> TenantProvisioningResult:
        """Securely provision a new tenant."""
        tenant_id = secrets.token_urlsafe(16)
        
        await self.audit.log("tenant_provisioning_started", {
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "tier": tier.value
        })
        
        try:
            # 1. Create tenant record
            tenant = await self.db.create_tenant(
                id=tenant_id,
                name=tenant_name,
                status=TenantStatus.PROVISIONING,
                tier=tier
            )
            
            # 2. Create isolated database schema (if using schema isolation)
            schema_name = f"tenant_{tenant_id.replace('-', '_')}"
            await self.db.execute(f"CREATE SCHEMA {schema_name}")
            await self._apply_schema_migrations(schema_name)
            
            # 3. Generate API credentials
            api_key = secrets.token_urlsafe(32)
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            await self.db.store_api_key(tenant_id, api_key_hash)
            
            # 4. Create storage prefix
            storage_prefix = self.storage._get_tenant_prefix(tenant_id)
            
            # 5. Initialize tenant-specific encryption key (if required)
            if tier in [TenantTier.BUSINESS, TenantTier.ENTERPRISE]:
                await self._provision_tenant_kms_key(tenant_id)
            
            # 6. Activate tenant
            await self.db.update_tenant_status(tenant_id, TenantStatus.ACTIVE)
            
            await self.audit.log("tenant_provisioning_completed", {
                "tenant_id": tenant_id,
                "schema": schema_name
            })
            
            return TenantProvisioningResult(
                tenant_id=tenant_id,
                status=TenantStatus.ACTIVE,
                api_key=api_key,  # Return only once, never stored in plain text
                database_schema=schema_name,
                storage_prefix=storage_prefix
            )
            
        except Exception as e:
            await self.audit.log("tenant_provisioning_failed", {
                "tenant_id": tenant_id,
                "error": str(e)
            })
            await self._cleanup_failed_provisioning(tenant_id)
            raise
    
    async def offboard_tenant(self, tenant_id: str, 
                             retain_days: int = 30) -> dict:
        """Securely offboard a tenant with data retention."""
        await self.audit.log("tenant_offboarding_started", {"tenant_id": tenant_id})
        
        # 1. Mark tenant as offboarding (prevents new operations)
        await self.db.update_tenant_status(tenant_id, TenantStatus.OFFBOARDING)
        
        # 2. Revoke all active sessions and API keys
        await self._revoke_all_access(tenant_id)
        
        # 3. Export data for compliance/portability
        export_location = await self._export_tenant_data(tenant_id)
        
        # 4. Schedule data deletion after retention period
        deletion_date = datetime.utcnow() + timedelta(days=retain_days)
        await self.db.schedule_tenant_deletion(tenant_id, deletion_date)
        
        await self.audit.log("tenant_offboarding_completed", {
            "tenant_id": tenant_id,
            "export_location": export_location,
            "scheduled_deletion": deletion_date.isoformat()
        })
        
        return {
            "status": "offboarding_complete",
            "data_export": export_location,
            "final_deletion": deletion_date.isoformat()
        }
    
    async def execute_tenant_deletion(self, tenant_id: str):
        """Permanently delete all tenant data."""
        await self.audit.log("tenant_deletion_started", {"tenant_id": tenant_id})
        
        # 1. Delete database schema/data
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        await self.db.execute(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE")
        
        # For shared table model, delete rows
        await self.db.execute(
            "DELETE FROM shared_table WHERE tenant_id = :tid",
            {"tid": tenant_id}
        )
        
        # 2. Delete cached data
        await self.cache.invalidate_tenant(tenant_id)
        
        # 3. Delete stored files
        await self.storage.delete_tenant_data(tenant_id)
        
        # 4. Delete encryption keys
        await self._delete_tenant_kms_key(tenant_id)
        
        # 5. Mark as deleted (keep minimal audit record)
        await self.db.update_tenant_status(tenant_id, TenantStatus.DELETED)
        
        await self.audit.log("tenant_deletion_completed", {"tenant_id": tenant_id})
```

</details>

### 8. Logging, Monitoring & Audit

- Include tenant context in all log entries.
- Implement tenant-isolated audit trails.
- Monitor for cross-tenant access attempts.
- Set up alerts for tenant isolation violations.
- Ensure compliance with tenant-specific retention policies.

<details>
<summary>Tenant-Aware Logging & Monitoring</summary>

```python
import structlog
from typing import Any, Dict
from datetime import datetime

class TenantAwareLogger:
    """Logger that automatically includes tenant context."""
    
    def __init__(self):
        self.logger = structlog.get_logger()
    
    def _enrich_with_tenant(self, event_data: dict) -> dict:
        """Add tenant context to log entry."""
        ctx = current_tenant.get()
        if ctx:
            event_data["tenant_id"] = ctx.tenant_id
            event_data["user_id"] = ctx.user_id
        return event_data
    
    def info(self, message: str, **kwargs):
        self.logger.info(message, **self._enrich_with_tenant(kwargs))
    
    def warning(self, message: str, **kwargs):
        self.logger.warning(message, **self._enrich_with_tenant(kwargs))
    
    def error(self, message: str, **kwargs):
        self.logger.error(message, **self._enrich_with_tenant(kwargs))
    
    def security_event(self, event_type: str, severity: str, **kwargs):
        """Log security-relevant events."""
        self.logger.warning(
            "security_event",
            event_type=event_type,
            severity=severity,
            **self._enrich_with_tenant(kwargs)
        )

class TenantAuditLog:
    """Immutable audit log with tenant isolation."""
    
    def __init__(self, db):
        self.db = db
    
    async def log(self, action: str, details: Dict[str, Any], 
                  tenant_id: str = None):
        """Record audit entry."""
        ctx = current_tenant.get()
        tenant_id = tenant_id or (ctx.tenant_id if ctx else "system")
        
        entry = {
            "id": secrets.token_urlsafe(16),
            "tenant_id": tenant_id,
            "user_id": ctx.user_id if ctx else None,
            "action": action,
            "details": details,
            "timestamp": datetime.utcnow(),
            "ip_address": get_client_ip(),
            "user_agent": get_user_agent()
        }
        
        # Insert into append-only audit table
        await self.db.execute("""
            INSERT INTO audit_log 
            (id, tenant_id, user_id, action, details, timestamp, ip_address, user_agent)
            VALUES (:id, :tenant_id, :user_id, :action, :details, :timestamp, :ip_address, :user_agent)
        """, entry)
    
    async def get_tenant_audit_trail(self, tenant_id: str, 
                                     start_date: datetime,
                                     end_date: datetime) -> list:
        """Retrieve audit trail for a specific tenant."""
        ctx = current_tenant.get()
        
        # Ensure requester can only access their own audit logs
        if ctx.tenant_id != tenant_id and "admin" not in ctx.roles:
            raise SecurityException("Cannot access other tenant's audit logs")
        
        return await self.db.fetch_all("""
            SELECT * FROM audit_log 
            WHERE tenant_id = :tenant_id 
            AND timestamp BETWEEN :start AND :end
            ORDER BY timestamp DESC
        """, {"tenant_id": tenant_id, "start": start_date, "end": end_date})

class CrossTenantAccessMonitor:
    """Monitor and alert on potential cross-tenant access attempts."""
    
    def __init__(self, alert_service):
        self.alerts = alert_service
        self.violation_counts = {}
    
    async def check_access(self, requested_tenant: str, 
                          resource_type: str, resource_id: str):
        """Check for cross-tenant access attempts."""
        ctx = current_tenant.get()
        
        if ctx.tenant_id != requested_tenant:
            # Log violation
            logger.security_event(
                "cross_tenant_access_attempt",
                severity="HIGH",
                requested_tenant=requested_tenant,
                resource_type=resource_type,
                resource_id=resource_id
            )
            
            # Track violations per user
            key = f"{ctx.user_id}:{ctx.tenant_id}"
            self.violation_counts[key] = self.violation_counts.get(key, 0) + 1
            
            # Alert on repeated attempts
            if self.violation_counts[key] >= 3:
                await self.alerts.send(
                    severity="CRITICAL",
                    message=f"Repeated cross-tenant access attempts detected",
                    details={
                        "user_id": ctx.user_id,
                        "tenant_id": ctx.tenant_id,
                        "attempts": self.violation_counts[key]
                    }
                )
            
            raise SecurityException("Access denied: resource belongs to different tenant")
```

</details>

## Do's and Don'ts

**Do:**

- Derive tenant context from authenticated, verified tokens.
- Use database-level isolation (RLS, schemas) as defense in depth.
- Include tenant_id in all resource queries, cache keys, and storage paths.
- Implement per-tenant rate limiting and quotas.
- Log tenant context with every operation.
- Validate tenant ownership at the data access layer.
- Use separate encryption keys for high-security tenants.
- Implement complete data deletion for offboarding.
- Monitor and alert on cross-tenant access attempts.

**Don't:**

- Trust tenant IDs from client headers or request parameters.
- Use shared cache keys without tenant prefixes.
- Expose sequential or guessable tenant/resource IDs.
- Allow queries without tenant filters (even for admins without explicit override).
- Store tenant data without tenant_id columns.
- Share API keys or credentials across tenants.
- Skip tenant validation for "internal" services.
- Retain tenant data indefinitely after offboarding.
- Log sensitive tenant data in plain text.

## References

- [OWASP Cloud Tenant Isolation](https://owasp.org/www-project-cloud-tenant-isolation/)
- [OWASP Authorization Cheat Sheet](Authorization_Cheat_Sheet.md)
- [AWS SaaS Tenant Isolation Strategies](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/tenant-isolation.html)
