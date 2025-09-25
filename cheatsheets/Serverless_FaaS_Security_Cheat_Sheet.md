# Serverless / FaaS Security Cheat Sheet

## Introduction

Serverless computing (Functions as a Service — FaaS) platforms such as AWS Lambda, Azure Functions, and Google Cloud Functions simplify application development and scaling.
However, the execution model (short-lived, event-driven functions running in managed environments) introduces unique security risks compared to traditional architectures.

This cheat sheet provides best practices to secure serverless applications and minimize attack surfaces.

## Key Risks

- Over-permissioned functions (broad IAM roles, `*` policies).
- Unvalidated event inputs (API Gateway, S3, Pub/Sub, IoT).
- Cold start data leakage (persistent state, side-channel timing).
- Function chaining abuse (compromised function invoking others).
- Shared environment risks (multi-tenant leakage, `/tmp` reuse).
- Hardcoded secrets in code or env vars.
- Excessive network access.

## Best Practices

### 1. Principle of Least Privilege

- Assign minimal IAM permissions to each function.
- Use role-per-function (avoid shared high-privilege roles).
- Scope database/API keys to the smallest set of actions needed.

**Bad IAM Policy (too broad):**

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

**Good IAM Policy (scoped):**

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
  "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
}
```

### 2. Environment Isolation

- Disable default network access unless required (e.g. outbound internet access).
- Place functions in private subnets with controlled egress.
- Isolate sensitive functions (e.g. payment, auth) from general-purpose ones.
- Separate production vs. staging environments with strict boundaries.

**AWS Lambda VPC Config (restrictive):**

```yaml
VpcConfig:
  SubnetIds:
    - subnet-123456
  SecurityGroupIds:
    - sg-restrict-outbound
```

### 3. Secure Function Invocation

- Enforce authentication and authorization on all triggers (API Gateway, Pub/Sub, S3, IoT).
- Validate function-to-function calls with signed tokens or workload identities.
- Apply rate limiting and throttling to mitigate DoS and abuse.

**API Gateway Authorizer Example (JWT validation):**

```json
{
  "Type": "JWT",
  "IdentitySource": "$request.header.Authorization",
  "Issuer": "https://secure-idp.example.com/",
  "Audience": "my-api-client"
}
```

### 4. Event Data Validation

- Treat all event payloads as untrusted input.
- Apply strong input validation & sanitization (length, type, format).
- Protect against common injection attacks (SQLi, XSS, JSON injection, deserialization).
- Strip unnecessary fields and metadata before processing.

Example: Python input validation for Lambda

```python
import json
import re

def lambda_handler(event, context):
    body = json.loads(event["body"])
    email = body.get("email", "")

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"statusCode": 400, "body": "Invalid email"}

    # process safely
    return {"statusCode": 200, "body": "OK"}
```

### 5. Cold Start & Execution Context Security

- Do not assume function runtime context is clean between invocations.
- Avoid storing secrets or temporary sensitive data in global/static variables.
- Protect against side-channel leaks (timing differences, leftover files in /tmp).
- For sensitive workloads, enforce single-use execution environments if the platform supports it.

**Bad:**

```python
# Secret stays in global variable across invocations
SECRET_KEY = "hardcoded-secret"
```

**Good:**

```python
import os
from my_secrets_lib import get_secret

def lambda_handler(event, context):
    secret = get_secret("db-password")  # fetch fresh each time
    ...
```

### 6. Secrets Management

- Avoid storing secrets in environment variables.
- Fetch secrets from secure stores (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
- Use ephemeral credentials (STS, workload identity federation).
- Rotate secrets automatically.

**AWS Lambda Secret Fetch (Python Boto3):**

```python
import boto3, json

def get_secret(secret_name):
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])
```

### 7. Monitoring & Logging

- Use centralized logging (CloudWatch, Azure Monitor, GCP Logging).
- Mask secrets and PII.

Example: Redacting fields

```python
import logging

def log_event(event):
    safe_event = {k: ("***" if "password" in k else v) for k,v in event.items()}
    logging.info(safe_event)
```

### 8. Supply Chain Security

- Scan dependencies (`npm audit`, `pip-audit`, `safety`).
- Use minimal deployment packages.
- Sign packages with checksums.

**AWS Lambda Layer Hash Validation:**

```bash
shasum -a 256 layer.zip
```

## Do’s and Don’ts

**Do**:

- Enforce least privilege per function.
- Validate all event inputs.
- Fetch secrets from vaults, not env vars.
- Restrict network egress.
- Monitor invocations and logs.

**Don’t**:

- Hardcode secrets in code or configs.
- Assume clean runtime between invocations.
- Give `*` IAM permissions.
- Leave sensitive data in `/tmp` or globals.
- Trust event sources blindly.

## References

- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Azure Functions Security](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [Google Cloud Functions Security](https://cloud.google.com/run/docs/securing/security)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
