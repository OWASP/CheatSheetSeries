# FastAPI Security Cheat Sheet

## Introduction

FastAPI is a modern, high-performance Python web framework built on standard Python type hints and ASGI. While FastAPI includes built-in mechanisms for authentication, data validation, and dependency injection, misconfigurations can expose applications to security risks. This cheat sheet provides practical, framework-specific guidance to help developers secure FastAPI applications, mapping to recommendations in the [official FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/).

## Dependency Injection and Access Control

FastAPI uses its Dependency Injection (DI) system via `Depends()` to manage authentication and authorization. See the [FastAPI Dependencies tutorial](https://fastapi.tiangolo.com/tutorial/dependencies/) for details. While DI is powerful, incorrect scoping can lead to Broken Function Level Authorization.

### OAuth2PasswordBearer Verifies Nothing

The helper class `OAuth2PasswordBearer` only extracts the bearer token from the `Authorization` header. It performs **no validation or signature verification**. Developers must explicitly pass the extracted token to a verification function. See [OAuth2PasswordBearer Reference](https://fastapi.tiangolo.com/reference/security/#fastapi.security.OAuth2PasswordBearer).

### Scoping Authorization Dependencies

Reusing a general authentication dependency (like `get_current_user`) for sensitive endpoints is a common mistake. Endpoints requiring elevated privileges (such as admin tasks) must explicitly require a role-verification dependency.

```python
from fastapi import Depends, HTTPException, status

async def get_current_user(token: str = Depends(oauth2_scheme)):
    # OAuth2PasswordBearer extracts token; verification must be manual.
    user = verify_token_and_get_user(token)
    return user

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

### Router-Level Deny-by-Default

To prevent developers from forgetting to add security dependencies to new endpoints, secure entire router sections at the initialization level.

```python
from fastapi import APIRouter, Depends

# Enforce authentication for all routes registered under this router by default
router = APIRouter(
    prefix="/items",
    dependencies=[Depends(get_current_user)]
)
```

## Secure Authentication and JWT Implementation

FastAPI provides helper utilities for OAuth2 flows, but developers are responsible for token verification and key management. See [FastAPI OAuth2 with JWT tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/).

### Cryptographic Library Choice

- **Use PyJWT:** Do not write custom JWT parsing or signature verification logic. Use the well-maintained [PyJWT library](https://pyjwt.readthedocs.io/). Avoid `python-jose`, which is unmaintained and vulnerable to algorithm confusion attacks ([CVE-2024-33663](https://nvd.nist.gov/vuln/detail/CVE-2024-33663)).

### Key Claims Verification

- **Validate Essential Claims:** Always verify the signature and essential claims in your decoding function:
    - `exp` (Expiration Time) to bound the token's lifetime.
    - `nbf` (Not Before) to reject early tokens.
    - `iss` (Issuer) to verify the token origin.
    - `aud` (Audience) to verify the token destination as required by [RFC 8725 §3.9](https://tools.ietf.org/html/rfc8725#section-3.9).
- **Explicit Algorithms:** Explicitly specify the expected algorithm (e.g., `algorithms=["HS256"]`) during decoding to prevent key-confusion attacks.
- **Replay Protection:** The `exp` claim only bounds the replay window but does not prevent replay attacks. For robust protection, store token identifiers (`jti`) in a revocation blocklist or refer to the [OWASP JSON Web Token Cheat Sheet](../cheatsheets/JSON_Web_Token_Cheat_Sheet.md).

### Cookie-Stored Refresh Tokens

- **HttpOnly:** Store refresh tokens in `HttpOnly` cookies to protect them from Cross-Site Scripting (XSS) access.
- **Secure and SameSite:** Enforce `Secure=True` (HTTPS only) and `SameSite="Lax"` or `"Strict"` to mitigate Cross-Site Request Forgery (CSRF).
- **CSRF Mitigations:** Moving credentials out of the `Authorization` header to cookies introduces CSRF risk. Protect state-changing operations by validating custom headers or referencing the [OWASP CSRF Prevention Cheat Sheet](../cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

### Signing Key Management

Never hardcode secrets in source files. Load keys from environment variables using [Pydantic Settings](https://fastapi.tiangolo.com/advanced/settings/).

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    secret_key: str

settings = Settings()
```

## Pydantic Validation and Input Hardening

Pydantic schemas enforce type validation, but they do not automatically protect against logical parameter tamperings or injection vulnerabilities. See [Pydantic Models documentation](https://docs.pydantic.dev/latest/concepts/models/).

### Reject Unrecognized Fields

By default, Pydantic silently ignores extra input fields. Attackers can inject arbitrary keys into request bodies. To prevent this, configure your input schemas to reject unrecognized fields:

```python
from pydantic import BaseModel, ConfigDict

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str
```

### Prevent Mass Assignment

Do not pass raw input schemas directly into database creation functions. Use separate, restricted input schemas (`UserCreate`, `UserUpdate`) that exclude read-only fields like `is_admin` or `id`.

### Prevent Sensitive Data Exposure

Explicitly specify `response_model` in path decorators to filter database objects and exclude sensitive fields (e.g., `password_hash`) from responses. See [FastAPI Response Model documentation](https://fastapi.tiangolo.com/tutorial/response-model/).

```python
class UserResponse(BaseModel):
    username: str
    email: str

@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate):
    # Filters out any fields not defined in UserResponse
    return save_user_to_db(user)
```

### Strict Typing

Python type hints permit automatic casting (e.g., a string `"123"` casts to `123` in an `int` field). Use Pydantic's strict types (like `StrictStr`, `StrictInt`, and `StrictBool`) to prevent unexpected type coercion.

### Injection Countermeasure

Input validation does not prevent SQL injection. Pair your validation schemas with parameterized queries or Object-Relational Mappers (ORMs) like SQLAlchemy or SQLModel. Never build raw SQL queries using string formatting with user input.

## Cross-Origin Resource Sharing (CORS) Configuration

Incorrect CORS setups can allow malicious websites to access private APIs. For details on CORS configuration, see the [FastAPI CORS documentation](https://fastapi.tiangolo.com/tutorial/cors/).

### Restrictive CORS Settings

- **Avoid Wildcards:** Never use `allow_origins=["*"]` when credentials are permitted (`allow_credentials=True`). This allows any third-party domain to read API responses on behalf of authenticated users.
- **Restrict Headers and Methods:** Limit `allow_methods` and `allow_headers` to only the verbs and headers your client application uses.
- For complete CORS design patterns, refer to the [OWASP HTML5 Security Cheat Sheet](../cheatsheets/HTML5_Security_Cheat_Sheet.md).

## OpenAPI and Swagger UI Exposure

By default, FastAPI generates interactive API documentation at `/docs` (Swagger UI) and `/redoc` (ReDoc). These pages expose schemas, endpoints, and parameters. See [FastAPI Metadata and Docs URLs](https://fastapi.tiangolo.com/tutorial/metadata/).

### Hardening Documentation in Production

Disable documentation endpoints in production environments to reduce the attack surface and prevent schema leakage.

```python
import os
from fastapi import FastAPI

ENV = os.getenv("APP_ENV", "production")

app = FastAPI(
    docs_url=None if ENV == "production" else "/docs",
    redoc_url=None if ENV == "production" else "/redoc",
    openapi_url=None if ENV == "production" else "/openapi.json"
)
```

## Async Event Loop and Background Tasks

FastAPI runs on an asynchronous event loop. Blocking the main thread can lead to Denial of Service (DoS) conditions where the entire server stops responding. See [FastAPI Async tutorial](https://fastapi.tiangolo.com/async/).

### Event Loop Blocking

- Do not run blocking database queries or heavy synchronous network calls inside an `async def` route. Use standard `def` routes for synchronous code; FastAPI automatically runs standard functions in a separate thread pool.
- For CPU-heavy tasks or long-running calculations, delegate the work to an external distributed task queue (like Celery or RQ) rather than using FastAPI's lightweight `BackgroundTasks`.

## Exception Handling and Information Leakage

FastAPI's default handlers can leak implementation details to client responses. See [FastAPI Handling Errors tutorial](https://fastapi.tiangolo.com/tutorial/handling-errors/).

### Validation Error Leakage

By default, FastAPI's `RequestValidationError` (422 Unprocessable Entity) echoes the invalid input parameter name, type, and value back to the client. This can leak database schemas, internal data structures, or user data. Override the validation exception handler in production to return sanitized messages:

```python
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    # Return a generic validation error message instead of echoing raw parameters
    return JSONResponse(
        status_code=422,
        content={"message": "Invalid request parameters provided."}
    )
```

## File Upload Security

FastAPI handles file uploads using `UploadFile` (which uses python-multipart). See [FastAPI Request Files tutorial](https://fastapi.tiangolo.com/tutorial/request-files/).

### Upload Protections

- **Limit Payload Sizes:** Enforce a maximum file size using middleware or a custom dependency to prevent Denial of Service (DoS) from disk exhaustion.
- **Sanitize Filenames:** Never trust the `filename` attribute on `UploadFile`. Generate a unique identifier (like a UUID) or use `werkzeug.utils.secure_filename` to prevent path traversal attacks.
- **Restrict File Types:** Validate file content headers and parse magic numbers to verify files match an allowed MIME type allowlist.

## Rate Limiting

FastAPI does not include built-in rate-limiting capabilities.

### Mitigation Options

- Use a dedicated library like [slowapi](https://github.com/laurentS/slowapi) to implement route-specific rate limiting in code.
- Implement rate limiting at the reverse proxy (Nginx, HAProxy) or API gateway layer.

## ASGI Server Hardening

Your FastAPI application runs on an ASGI server (usually Uvicorn or Gunicorn). Hardening this layer prevents server fingerprinting. See [FastAPI Deployment Guide](https://fastapi.tiangolo.com/deployment/).

### Deployment Configuration

- **Disable Server Header:** Hide the ASGI server version banner by running Uvicorn with the `--no-server-header` flag.
- **Limit Proxy Forwarding:** By default, Uvicorn trusts proxy headers (like `X-Forwarded-For`) from loopback IPs (`127.0.0.1`). Avoid configuring `--forwarded-allow-ips="*"`. Explicitly restrict this parameter to the specific IP address of your trusted reverse proxy (e.g., Nginx's IP) to prevent header spoofing.

## References

- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP REST Security Cheat Sheet](../cheatsheets/REST_Security_Cheat_Sheet.md)
