# FastAPI Security Cheat Sheet

## Introduction

FastAPI is a modern, fast (high-performance), web framework for building APIs with Python 3.6+ based on standard Python type hints. While FastAPI provides many built-in security features, its flexibility and specific architectural patterns (like dependency injection) require careful consideration to ensure applications are secure.

This cheat sheet focuses on security best practices and common pitfalls when building APIs using FastAPI. It aims to bridge the gap between generic API security principles and real-world FastAPI usage.

## Authentication and Authorization

### Use `OAuth2PasswordBearer` Correctly

FastAPI provides `OAuth2PasswordBearer` as a utility to extract the bearer token. Ensure you are validating this token, not just extracting it.

**Vulnerable:**
Using the token without verifying its signature or expiration.

**Secure:**
Verify the JWT signature using a library like `PyJWT` or `python-jose`.

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user_id
```

### Dependency Injection for Security

Use FastAPI's dependency injection system to enforce authentication and authorization consistently.

- **Don't** embed authentication logic directly in route handlers.
- **Do** create reusable dependencies for `get_current_user`, `get_current_active_user`, `get_current_admin_user`.

```python
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

### Role-Based Access Control (RBAC)

Implement checking scopes or roles within dependencies to ensure that only authorized users can access specific endpoints.

```python
from fastapi import Security

def get_admin_user(current_user: User = Security(get_current_active_user, scopes=["admin"])):
    if not "admin" in current_user.roles:
         raise HTTPException(status_code=403, detail="Not enough privileges")
    return current_user

@app.get("/admin", dependencies=[Depends(get_admin_user)])
async def admin_dashboard():
    return {"message": "Admin Access"}
```

## Input Validation

### Leverage Pydantic

FastAPI uses Pydantic for data validation. Define strict schemas for all request bodies.

- Use `EmailStr`, `HttpUrl`, and other specific types.
- Use `Field` constraints (`min_length`, `max_length`, `regex`) to limit input range.

```python
from pydantic import BaseModel, Field, EmailStr

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_]+$")
    email: EmailStr
    age: int = Field(..., gt=0, lt=120)
```

### Business Logic Validation

Pydantic handles structural validation. Don't forget business logic validation (e.g., checking if a username is already taken) inside your service layer or dependencies, not just at the schema level if it requires database access.

## Security Misconfigurations

### CORS (Cross-Origin Resource Sharing)

Avoid using `allow_origins=["*"]` in production. List explicitly allowed origins.

```python
from fastapi.middleware.cors import CORSMiddleware

origins = [
    "https://frontend.example.com",
    "https://api.example.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### OpenAPI / Swagger UI

FastAPI automatically generates documentation at `/docs` (Swagger UI) and `/redoc`.

- **Development:** Useful for testing.
- **Production:** Consider disabling or securing these routes to avoid information disclosure about your API structure.

**Disable in Production:**

```python
app = FastAPI(docs_url=None, redoc_url=None)
```

**Secure behind Authentication:**
You can override the docs endpoints to require authentication.

## Error Handling

FastAPI's default exception handlers are good, but ensure you don't leak sensitive information (like stack traces from internal server errors) in the response body.

- Use `HTTPException` for expected errors.
- Add a global exception handler for unhandled exceptions to return a generic error message in production.

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log the error details here (e.g., to Sentry)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error"},
    )
```

## Deployment

### ASGI Server Configuration

When deploying with Uvicorn or Gunicorn with Uvicorn workers:

- **Workers:** Configure an appropriate number of workers.
- **Headers:** Ensure `ProxyHeadersMiddleware` (TrustedHostMiddleware) is used if behind a reverse proxy (Nginx, LB) to correctly identify client IP and scheme.

```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["example.com", "*.example.com"]
)
```

## References

- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
