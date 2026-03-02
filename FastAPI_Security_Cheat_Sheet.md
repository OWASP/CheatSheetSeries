# FastAPI Security Cheat Sheet

## Production Hardening

### Disable Documentation in Production
By default, FastAPI generates interactive API documentation at `/docs` (Swagger UI) and `/redoc` (ReDoc). While useful during development, leaving these active in production allows attackers to map your entire attack surface.

**Rule:** Disable documentation metadata in production environments using environment variables.

**Secure Implementation:**
```python
from fastapi import FastAPI
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Set this to "production" in your live environment
    env: str = "development" 

settings = Settings()

# Check the environment; if 'production', set URLs to None
app = FastAPI(
    docs_url=None if settings.env == "production" else "/docs",
    redoc_url=None if settings.env == "production" else "/redoc",
    openapi_url=None if settings.env == "production" else "/openapi.json"
)
```

Cross-Origin Resource Sharing (CORS)
Secure CORS Configuration

CORS is a security mechanism that allows a browser to let a web application running at one origin access selected resources from a different origin. A common mistake is using allow_origins=["*"], which permits any website to make requests to your API.

Rule: Always explicitly define a list of trusted origins. Never use wildcards (*) in production.

Secure Implementation:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Define only the domains you trust
origins = [
    "https://your-app-frontend.com",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```
