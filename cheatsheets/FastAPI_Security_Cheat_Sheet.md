# FastAPI Security Cheat Sheet

## Introduction

FastAPI is a Python web framework using the Asynchronous Server Gateway Interface (ASGI). This cheat sheet covers authentication dependencies, input and output models, and deployment controls, building on the [FastAPI security documentation](https://fastapi.tiangolo.com/tutorial/security/).

See the [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md) for general API controls.

Code snippets illustrate individual controls, not complete applications. They assume an existing FastAPI application and application-specific user and persistence functions; adapt and test them for your application.

## Dependency Injection and Access Control

Use FastAPI's dependency injection system, through `Depends()`, to enforce authentication and authorization consistently. Missing or insufficient dependencies can leave sensitive operations accessible to unauthorized users. See the [FastAPI dependencies tutorial](https://fastapi.tiangolo.com/tutorial/dependencies/).

### OAuth2PasswordBearer Does Not Validate Tokens

The helper class `OAuth2PasswordBearer` checks the authorization scheme and extracts the bearer token from the `Authorization` header. It does **not validate the token or verify its signature**. An authentication dependency must verify the token and reject invalid credentials before returning a user. See the [OAuth2PasswordBearer reference](https://fastapi.tiangolo.com/reference/security/#fastapi.security.OAuth2PasswordBearer).

### Scoping Authorization Dependencies

Authentication alone does not authorize an operation. Endpoints requiring elevated privileges, such as admin tasks, must also check the user's permissions. In this example, `get_current_user` is an authentication dependency that rejects invalid credentials.

```python
from fastapi import Depends, HTTPException, status

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

Apply authentication dependencies to an entire `APIRouter` so new endpoints in that router inherit the check. This covers only that router's routes; sensitive operations still need permission checks.

```python
from fastapi import APIRouter, Depends

# Enforce authentication for all routes registered under this router by default
router = APIRouter(
    prefix="/items",
    dependencies=[Depends(get_current_user)]
)
```

## Secure Authentication and JWT Implementation

When using JSON Web Tokens (JWTs), developers are responsible for token verification and key management. The [FastAPI OAuth2 with JWT tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/) demonstrates verification with PyJWT.

### Cryptographic Library Choice

- **Use PyJWT:** Delegate token verification to the library rather than writing custom parsing or cryptographic logic. Configure verification using the [PyJWT decoding API](https://pyjwt.readthedocs.io/en/latest/api.html#jwt.decode).

### Key Claims Verification

- **Validate Required Claims:** Verify the signature and require `exp` (expiration), `iss` (issuer), and `aud` (audience) for authentication tokens. In PyJWT, use `options={"require": ["exp", "iss", "aud"]}` and supply the expected `issuer` and `audience`. Requiring a claim only checks its presence; keep the corresponding verification enabled. Validate `nbf` (not before) when present, and require it if your token profile calls for it.
- **Explicit Algorithms:** Configure the expected algorithm during decoding, for example `algorithms=["HS256"]` for tokens issued with that algorithm. Do not derive the accepted algorithms from the token's header.
- **Revocation and Replay:** Expiration bounds a token's lifetime. Checking a revocation blocklist rejects revoked tokens, but a stolen, still-active bearer token remains reusable. See the [JWT replay-protection guidance](../cheatsheets/JSON_Web_Token_Cheat_Sheet.md#replay-protection) for controls beyond expiration and revocation.

### Cookie-Stored Refresh Tokens

- **Cookie Attributes:** If you store refresh tokens in cookies, set `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict` where compatible with your authentication flow. `HttpOnly` prevents JavaScript from reading the cookie; it does not prevent injected scripts from making authenticated requests.
- **CSRF Mitigations:** Browsers attach cookies automatically, introducing Cross-Site Request Forgery (CSRF) risk. Protect refresh and other state-changing endpoints with the defenses in the [CSRF Prevention Cheat Sheet](../cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md), such as validated CSRF tokens. Treat `SameSite` as defense in depth.

### Signing Key Management

Never hardcode signing secrets or provide a default development key in production. Supply keys from deployment-managed secret storage; prefer a mounted secret file or retrieval from a secret manager, and use environment variables only when safer injection methods are unavailable. Pydantic Settings can read deployment-supplied configuration. Keep local `.env` files containing secrets out of source control. Follow the [Secrets Management Cheat Sheet](../cheatsheets/Secrets_Management_Cheat_Sheet.md) for provisioning and rotation.

## Pydantic Validation and Input Hardening

Pydantic schemas validate data, but they do not replace authorization checks or prevent injection vulnerabilities. See the [Pydantic models documentation](https://docs.pydantic.dev/latest/concepts/models/).

### Reject Unrecognized Fields

By default, Pydantic ignores undeclared input fields. Use `extra="forbid"` when the API should reject requests containing such fields instead of ignoring them:

```python
from pydantic import BaseModel, ConfigDict

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str
```

### Prevent Mass Assignment

Use separate, restricted input schemas (`UserCreate`, `UserUpdate`) that exclude server-controlled fields like `is_admin` or `id`. Persist only validated, allowed fields, not the raw request dictionary. `extra="forbid"` does not prevent clients from setting a sensitive field that you declared in the input schema. See the [Mass Assignment Cheat Sheet](../cheatsheets/Mass_Assignment_Cheat_Sheet.md).

### Prevent Sensitive Data Exposure

Explicitly specify `response_model` in path decorators to filter database objects and exclude sensitive fields (e.g., `password_hash`) from responses. See [FastAPI Response Model documentation](https://fastapi.tiangolo.com/tutorial/response-model/).

```python
class UserResponse(BaseModel):
    username: str

@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate):
    # Application function must hash the password before storing it.
    return save_user_to_db(user)
```

### Strict Typing

Pydantic can convert input values to the declared types, such as `"123"` to `123` for an `int` field. Where security decisions require an exact input type, use strict types such as `StrictInt` and `StrictBool` to reject unintended conversions.

### Injection Countermeasure

Input validation does not prevent SQL injection. Use parameterized queries, including through Object-Relational Mapper (ORM) APIs that bind parameters. Never build raw SQL queries using string formatting with user input. See the [SQL Injection Prevention Cheat Sheet](../cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md).

## Cross-Origin Resource Sharing (CORS) Configuration

Incorrect CORS settings can expose private API responses to untrusted websites in a user's browser. CORS does not replace endpoint authorization or restrict non-browser clients. See the [FastAPI CORS documentation](https://fastapi.tiangolo.com/tutorial/cors/).

### Restrictive CORS Settings

- **Explicit Origins:** When using `allow_credentials=True`, explicitly list trusted origins in `allow_origins`. Do not combine credentialed requests with `allow_origins=["*"]`.
- **Restrict Headers and Methods:** Limit `allow_methods` and `allow_headers` to only the verbs and headers your client application uses.
- For complete CORS design patterns, refer to the [OWASP HTML5 Security Cheat Sheet](../cheatsheets/HTML5_Security_Cheat_Sheet.md).

## OpenAPI and Swagger UI Exposure

FastAPI exposes interactive documentation at `/docs` and `/redoc`, with the schema at `/openapi.json`. Decide whether this information should be public. The [conditional OpenAPI guidance](https://fastapi.tiangolo.com/how-to/conditional-openapi/#about-security-apis-and-docs) explains why hiding documentation does not secure the API operations themselves.

### Hardening Documentation in Production

If the documentation is private, restrict access to both the documentation pages and schema, or disable them with `FastAPI(openapi_url=None)`. This prevents disclosure through those routes; authorization must still protect every API operation.

## Async Event Loop and Background Tasks

Blocking a worker's event loop prevents it from handling other requests, creating a Denial of Service (DoS) risk. See the [FastAPI async tutorial](https://fastapi.tiangolo.com/async/).

### Event Loop Blocking

- Use asynchronous database and network clients inside `async def` routes. For synchronous libraries, use `def` routes or dependencies, which FastAPI runs in a thread pool. Ordinary helper functions called directly inside `async def` are not automatically moved to that pool.
- Move CPU-heavy or long-running work to a separate worker system, such as Celery. `BackgroundTasks` still runs in the application process; see the [background-task caveat](https://fastapi.tiangolo.com/tutorial/background-tasks/#caveat).

## Exception Handling and Information Leakage

Control which error details reach clients and logs. FastAPI supports [custom exception handlers](https://fastapi.tiangolo.com/tutorial/handling-errors/#override-request-validation-exceptions) for sanitizing validation responses.

### Validation Error Leakage

Request validation errors can include submitted values and custom error details. Avoid reflecting passwords or tokens into responses or recording them in logs. In a `RequestValidationError` handler, return only safe field locations and error descriptions, or a generic message where necessary. Do not return `str(exc)` or the entire request body; these can include sensitive input or internal context.

## File Upload Security

FastAPI parses multipart uploads into `UploadFile` objects, which spool larger files to temporary disk storage. See the [UploadFile documentation](https://fastapi.tiangolo.com/tutorial/request-files/#uploadfile).

### Upload Protections

- **Limit Payloads Before Parsing:** Set a request-body limit at the reverse proxy or gateway, for example Nginx's [`client_max_body_size`](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size). Ensure clients cannot bypass that layer. FastAPI [parses the form before running dependencies](https://github.com/fastapi/fastapi/blob/28a206107302ee20ce6a9a876d05a258c1c8d328/fastapi/routing.py#L438-L502); checking `UploadFile.size` in a dependency or endpoint does not protect against the resources already consumed during parsing.
- **Treat Metadata as Untrusted:** Do not use `UploadFile.filename` directly as a storage path or trust `content_type` as proof of file type. Apply the filename, content-validation, and storage controls in the [File Upload Cheat Sheet](../cheatsheets/File_Upload_Cheat_Sheet.md).

## Rate Limiting

Apply request limits to reduce abuse of sensitive or expensive endpoints.

### Mitigation Options

- Use a dedicated library like [slowapi](https://github.com/laurentS/slowapi) to implement route-specific rate limiting in code.
- With multiple workers or replicas, use a shared counter store, such as Redis, so limits apply across instances instead of independently in each process.
- Implement rate limiting at the reverse proxy (Nginx, HAProxy) or API gateway layer.

## ASGI Server Hardening

Configure the ASGI server's proxy trust explicitly so clients cannot spoof the client address or request scheme using forwarding headers. See the [Uvicorn HTTP settings](https://uvicorn.dev/settings/#http).

### Deployment Configuration

- **Limit Proxy Forwarding:** Set `--forwarded-allow-ips` to the addresses of trusted reverse proxies and configure those proxies to overwrite untrusted forwarding headers. Avoid `--forwarded-allow-ips="*"`, which trusts every connecting client. Disable proxy-header handling with `--no-proxy-headers` if it is not needed.
- **Disable Server Header:** Use `--no-server-header` to suppress Uvicorn's default `Server` header. This removes one identifying header; it does not prevent other forms of server fingerprinting.

## References

- [FastAPI: Dependencies](https://fastapi.tiangolo.com/tutorial/dependencies/)
- [FastAPI: OAuth2 with JWT tokens](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
