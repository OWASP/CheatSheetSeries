# FastAPI Security Cheat Sheet

## Introduction

FastAPI is a modern, high-performance Python web framework built on standard Python type hints and ASGI. While FastAPI includes built-in mechanisms for authentication, data validation, and dependency injection, misconfigurations can expose applications to security risks. This cheat sheet provides practical, framework-specific guidance to help developers secure FastAPI applications.

## Dependency Injection and Access Control

FastAPI relies heavily on its Dependency Injection (DI) system via `Depends()` to manage authentication and authorization. While DI is powerful, incorrect scoping can lead to Broken Function Level Authorization.

### Scoping Authorization Dependencies

Reusing a general authentication dependency (like `get_current_user`) for sensitive endpoints is a common mistake. Endpoints requiring elevated privileges (such as admin tasks) must explicitly require a role-verification dependency.

```python
from fastapi import Depends, HTTPException, status

async def get_current_user(token: str = Depends(oauth2_scheme)):
    # Authenticate and return the user object
    ...

async def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted"
        )
    return current_user

@app.post("/admin/settings")
def update_settings(admin: User = Depends(get_admin_user)):
    return {"status": "success"}
```

## Secure Authentication and JWT Implementation

FastAPI provides helper utilities for OAuth2 flows, but developers are responsible for the underlying cryptographic safety and token handling.

### JWT Cryptographic Safety

- **Use Established Libraries:** Do not write custom JWT parsing or signature verification logic. Use well-maintained libraries like `PyJWT` or `python-jose`.
- **Verify Key Claims:** Always verify the signature and essential claims:
    - `exp` (Expiration Time) to prevent token replay attacks.
    - `nbf` (Not Before) to reject early tokens.
    - `iss` (Issuer) to verify the token origin.
- **Short-Lived Tokens:** Keep access token lifetimes short (e.g., 15 minutes). Use secure, one-time refresh tokens stored in HTTP-only cookies for session renewal.
- **Algorithmic Hardening:** Explicitly specify the expected algorithm (e.g., `algorithms=["HS256"]` or `algorithms=["RS256"]`) during decoding to prevent key-confusion attacks.

## Pydantic Validation and Input Hardening

Pydantic schemas enforce type validation and structure, but they do not automatically protect against logic bypasses or injection attacks.

### Prevent Mass Assignment

Do not use the same Pydantic schema for database models, API inputs, and API outputs. Define separate, focused schemas to control which fields can be modified by users:

- `UserCreate` / `UserUpdate` (for inputs; exclude read-only fields like `is_admin` or `id`).
- `UserResponse` (for outputs; exclude sensitive fields like `password_hash`).

### Enforce Strict Typing

Python type hints can be permissive (e.g., a string `"123"` will automatically cast to an integer `123` in a standard `int` field). Use Pydantic's strict types (like `StrictStr`, `StrictInt`, and `StrictBool`) to prevent unexpected type coercion.

```python
from pydantic import BaseModel, Field, StrictStr

class UserUpdate(BaseModel):
    # Enforce strict string type and length constraint
    display_name: StrictStr = Field(..., min_length=3, max_length=50)
```

## Cross-Origin Resource Sharing (CORS) Configuration

If your frontend and backend run on different domains, you must configure CORS. Incorrect CORS setups can allow malicious websites to access private APIs.

### Restrictive CORS Settings

- **Avoid Wildcards:** Never use `allow_origins=["*"]` when credentials are permitted (`allow_credentials=True`). This allows any third-party domain to read API responses on behalf of authenticated users.
- **Restrict Headers and Methods:** Limit `allow_methods` and `allow_headers` to only the verbs and headers your client application actually uses.

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myfrontend.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Content-Type", "Authorization"],
)
```

## OpenAPI and Swagger UI Exposure

By default, FastAPI generates interactive API documentation at `/docs` (Swagger UI) and `/redoc` (ReDoc). These pages expose schemas, endpoints, and parameter requirements.

### Hardening Documentation in Production

Disable documentation endpoints in your production environments to reduce your attack surface and prevent schema leakage.

```python
import os
from fastapi import FastAPI

# Read deployment environment from system variables
ENV = os.getenv("APP_ENV", "production")

app = FastAPI(
    docs_url=None if ENV == "production" else "/docs",
    redoc_url=None if ENV == "production" else "/redoc",
    openapi_url=None if ENV == "production" else "/openapi.json"
)
```

## Async Event Loop and Background Tasks

FastAPI is built on an asynchronous architecture. Blocking the main thread can lead to Denial of Service (DoS) conditions where the entire server stops responding to all incoming requests.

### Event Loop Blocking

- Do not run blocking database queries or heavy synchronous network calls inside an `async def` route. Use standard `def` routes for synchronous code; FastAPI runs standard functions in a separate thread pool automatically.
- For CPU-heavy tasks or long-running calculations, delegate the work to an external distributed task queue (like Celery or RQ) rather than using FastAPI's lightweight `BackgroundTasks`.

## ASGI Server Hardening

Your FastAPI application runs on an ASGI server (usually Uvicorn or Gunicorn). Hardening this layer prevents server fingerprinting.

### Deployment Configuration

- **Disable Server Header:** Hide the ASGI server version banner to make it harder for attackers to identify vulnerabilities. In Uvicorn, run with the `--no-server-header` flag.
- **Reverse Proxy Setup:** Always run your ASGI server behind a production-grade reverse proxy (like Nginx, HAProxy, or an AWS Application Load Balancer). Configure Uvicorn's `ProxyHeadersMiddleware` only when behind a trusted proxy to prevent IP spoofing.

## References

- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
