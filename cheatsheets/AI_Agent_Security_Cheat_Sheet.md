# AI Agent Security Cheat Sheet

## Introduction

AI agents are autonomous systems powered by Large Language Models (LLMs) that can reason, plan, use tools, maintain memory, and take actions to accomplish goals. This expanded capability introduces unique security risks beyond traditional LLM prompt injection. This cheat sheet provides best practices to secure AI agent architectures and minimize attack surfaces.

## Key Risks

- **Prompt Injection (Direct & Indirect)**: Malicious instructions injected via user input or external data sources (websites, documents, emails) that hijack agent behavior. (See [LLM Prompt Injection Prevention Cheat Sheet](LLM_Prompt_Injection_Prevention_Cheat_Sheet.md))
- **Tool Abuse & Privilege Escalation**: Agents exploiting overly permissive tools to perform unintended actions or access unauthorized resources.
- **Data Exfiltration**: Sensitive information leaked through tool calls, API requests, or agent outputs.
- **Memory Poisoning**: Malicious data persisted in agent memory to influence future sessions or other users.
- **Goal Hijacking**: Manipulating agent objectives to serve attacker purposes while appearing legitimate.
- **Excessive Autonomy**: Agents taking high-impact actions without appropriate human oversight.
- **Cascading Failures**: Compromised agents in multi-agent systems propagating attacks to other agents.
- **Denial of Wallet (DoW)**: Attacks causing excessive API/compute costs through unbounded agent loops.
- **Sensitive Data Exposure**: PII, credentials, or confidential data inadvertently included in agent context or logs.

## Best Practices

### 1. Tool Security & Least Privilege

- Grant agents the minimum tools required for their specific task.
- Implement per-tool permission scoping (read-only vs. write, specific resources).
- Use separate tool sets for different trust levels (e.g., internal vs. user-facing agents).
- Require explicit tool authorization for sensitive operations.

#### Bad: Over-permissioned tool configuration

```python
# Dangerous: Agent has unrestricted shell access
tools = [
    {
        "name": "execute_command",
        "description": "Execute any shell command",
        "allowed_commands": "*"  # No restrictions
    }
]
```

#### Good: Scoped tool with allowlist

```python
# Safe: Restricted to specific, safe commands
tools = [
    {
        "name": "file_reader",
        "description": "Read files from the reports directory",
        "allowed_paths": ["/app/reports/*"],
        "allowed_operations": ["read"],
        "blocked_patterns": ["*.env", "*.key", "*.pem", "*secret*"]
    }
]
```

#### Tool Authorization Middleware Example (Python)

```python
from functools import wraps

SENSITIVE_TOOLS = ["send_email", "execute_code", "database_write", "file_delete"]

def require_confirmation(func):
    @wraps(func)
    async def wrapper(tool_name, params, context):
        if tool_name in SENSITIVE_TOOLS:
            if not context.get("user_confirmed"):
                return {
                    "status": "pending_confirmation",
                    "message": f"Action '{tool_name}' requires user approval",
                    "params": sanitize_for_display(params)
                }
        return await func(tool_name, params, context)
    return wrapper
```

### 2. Input Validation & Prompt Injection Defense

- Treat all external data as untrusted (user messages, retrieved documents, API responses, emails).
- Implement input sanitization before including external content in agent context.
- Use delimiters and clear boundaries between instructions and data.
- Apply content filtering for known injection patterns.
- Consider using separate LLM calls to validate/summarize untrusted content.

Please refer to the [LLM Prompt Injection Prevention Cheat Sheet](LLM_Prompt_Injection_Prevention_Cheat_Sheet.md) for detailed techniques.

### 3. Memory & Context Security

- Validate and sanitize data before storing in agent memory.
- Implement memory isolation between users/sessions.
- Set memory expiration and size limits.
- Audit memory contents for sensitive data before persistence.
- Use cryptographic integrity checks for long-term memory.

#### Bad: Unvalidated memory storage

```python
# Dangerous: Storing arbitrary user input in persistent memory
def save_memory(agent, user_message, assistant_response):
    agent.memory.add({
        "user": user_message,  # Could contain injection payload
        "assistant": assistant_response,
        "timestamp": datetime.now()
    })
```

#### Good: Validated and isolated memory

```python
import hashlib
from datetime import datetime, timedelta

class SecureAgentMemory:
    MAX_MEMORY_ITEMS = 100
    MAX_ITEM_LENGTH = 5000
    MEMORY_TTL_HOURS = 24
    
    def __init__(self, user_id: str, encryption_key: bytes):
        self.user_id = user_id
        self.encryption_key = encryption_key
        self.memories = []
    
    def add(self, content: str, memory_type: str = "conversation"):
        # Validate content
        if len(content) > self.MAX_ITEM_LENGTH:
            content = content[:self.MAX_ITEM_LENGTH]
        
        # Scan for sensitive data patterns
        if self._contains_sensitive_data(content):
            content = self._redact_sensitive_data(content)
        
        # Scan for injection patterns
        content = self._sanitize_injection_attempts(content)
        
        # Create integrity-checked memory entry
        entry = {
            "content": content,
            "type": memory_type,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": self.user_id,
            "checksum": self._compute_checksum(content)
        }
        
        self.memories.append(entry)
        self._enforce_limits()
    
    def get_context(self) -> list:
        """Retrieve valid, non-expired memories."""
        valid_memories = []
        cutoff = datetime.utcnow() - timedelta(hours=self.MEMORY_TTL_HOURS)
        
        for mem in self.memories:
            mem_time = datetime.fromisoformat(mem["timestamp"])
            if mem_time > cutoff and self._verify_checksum(mem):
                valid_memories.append(mem["content"])
        
        return valid_memories
    
    def _contains_sensitive_data(self, content: str) -> bool:
        sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{16}\b',              # Credit card
            r'password\s*[:=]\s*\S+',   # Passwords
            r'api[_-]?key\s*[:=]\s*\S+' # API keys
        ]
        return any(re.search(p, content, re.I) for p in sensitive_patterns)
    
    def _compute_checksum(self, content: str) -> str:
        return hashlib.sha256(
            (content + self.user_id).encode() + self.encryption_key
        ).hexdigest()[:16]
```

### 4. Human-in-the-Loop Controls

- Require explicit approval for high-impact or irreversible actions.
- Implement action previews before execution.
- Set autonomy boundaries based on action risk levels.
- Provide clear audit trails of agent decisions and actions.
- Allow users to interrupt and rollback agent operations.

#### Action Classification and Approval Flow

```python
from enum import Enum
from dataclasses import dataclass

class RiskLevel(Enum):
    LOW = "low"           # Read operations, safe queries
    MEDIUM = "medium"     # Write operations, API calls
    HIGH = "high"         # Financial, deletion, external comms
    CRITICAL = "critical" # Irreversible, security-sensitive

ACTION_RISK_MAPPING = {
    "search_documents": RiskLevel.LOW,
    "read_file": RiskLevel.LOW,
    "write_file": RiskLevel.MEDIUM,
    "send_email": RiskLevel.HIGH,
    "execute_code": RiskLevel.HIGH,
    "database_delete": RiskLevel.CRITICAL,
    "transfer_funds": RiskLevel.CRITICAL,
}

@dataclass
class PendingAction:
    action_id: str
    tool_name: str
    parameters: dict
    risk_level: RiskLevel
    explanation: str
    
class HumanInTheLoopController:
    def __init__(self, auto_approve_threshold: RiskLevel = RiskLevel.LOW):
        self.auto_approve_threshold = auto_approve_threshold
        self.pending_actions = {}
    
    async def request_action(self, tool_name: str, params: dict, 
                            explanation: str) -> dict:
        risk_level = ACTION_RISK_MAPPING.get(tool_name, RiskLevel.HIGH)
        
        # Auto-approve low-risk actions
        if risk_level.value <= self.auto_approve_threshold.value:
            return {"approved": True, "auto": True}
        
        # Queue for human review
        action = PendingAction(
            action_id=generate_uuid(),
            tool_name=tool_name,
            parameters=self._sanitize_params_for_display(params),
            risk_level=risk_level,
            explanation=explanation
        )
        
        self.pending_actions[action.action_id] = action
        
        return {
            "approved": False,
            "pending": True,
            "action_id": action.action_id,
            "requires": "human_approval",
            "risk_level": risk_level.value,
            "preview": self._generate_action_preview(action)
        }
    
    def _generate_action_preview(self, action: PendingAction) -> str:
        return f"""
        Action: {action.tool_name}
        Risk Level: {action.risk_level.value.upper()}
        Explanation: {action.explanation}
        Parameters: {json.dumps(action.parameters, indent=2)}
        """
```

### 5. Output Validation & Guardrails

- Validate agent outputs before execution or display.
- Implement output filtering for sensitive data leakage.
- Use structured outputs with schema validation where possible.
- Set boundaries on output actions (rate limits, scope limits).
- Apply content safety filters to generated responses.

#### Output Validation Pipeline

```python
from pydantic import BaseModel, validator
from typing import Optional, List

class AgentToolCall(BaseModel):
    tool_name: str
    parameters: dict
    reasoning: Optional[str]
    
    @validator('tool_name')
    def validate_tool_allowed(cls, v):
        allowed_tools = ["search", "read_file", "calculator", "get_weather"]
        if v not in allowed_tools:
            raise ValueError(f"Tool '{v}' is not in allowed list")
        return v
    
    @validator('parameters')
    def validate_no_sensitive_data(cls, v):
        sensitive_patterns = [
            r'api[_-]?key', r'password', r'secret', r'token',
            r'credential', r'private[_-]?key'
        ]
        params_str = json.dumps(v).lower()
        for pattern in sensitive_patterns:
            if re.search(pattern, params_str):
                raise ValueError("Parameters contain potentially sensitive data")
        return v

class OutputGuardrails:
    def __init__(self):
        self.pii_patterns = self._load_pii_patterns()
        self.blocked_actions = set()
        self.rate_limiter = RateLimiter(max_calls=100, window_seconds=60)
    
    async def validate_output(self, agent_output: dict) -> dict:
        # Check rate limits
        if not self.rate_limiter.allow():
            raise RateLimitExceeded("Agent action rate limit exceeded")
        
        # Validate structure
        if "tool_calls" in agent_output:
            for call in agent_output["tool_calls"]:
                validated = AgentToolCall(**call)
                
        # Filter PII from responses
        if "response" in agent_output:
            agent_output["response"] = self._filter_pii(agent_output["response"])
        
        # Check for data exfiltration patterns
        if self._detect_exfiltration_attempt(agent_output):
            raise SecurityViolation("Potential data exfiltration detected")
        
        return agent_output
    
    def _detect_exfiltration_attempt(self, output: dict) -> bool:
        """Detect attempts to exfiltrate data through tool calls."""
        suspicious_patterns = [
            # Encoding sensitive data in URLs
            lambda o: "http" in str(o) and any(
                p in str(o).lower() for p in ["base64", "encode", "password"]
            ),
            # Large data in webhook/API calls
            lambda o: o.get("tool_name") in ["http_request", "webhook"] and 
                     len(str(o.get("parameters", ""))) > 10000,
        ]
        return any(pattern(output) for pattern in suspicious_patterns)
```

### 6. Monitoring & Observability

- Log all agent decisions, tool calls, and outcomes.
- Implement anomaly detection for unusual agent behavior.
- Track token usage and costs per session/user.
- Set up alerts for security-relevant events.
- Maintain audit trails for compliance and forensics.

#### Agent Monitoring

```python
import structlog
from dataclasses import dataclass, field
from typing import List, Dict, Any
from datetime import datetime

logger = structlog.get_logger()

@dataclass
class AgentSecurityEvent:
    event_type: str
    severity: str  # INFO, WARNING, CRITICAL
    agent_id: str
    session_id: str
    user_id: str
    timestamp: datetime
    details: Dict[str, Any]
    tool_name: Optional[str] = None
    
class AgentMonitor:
    ANOMALY_THRESHOLDS = {
        "tool_calls_per_minute": 30,
        "failed_tool_calls": 5,
        "injection_attempts": 1,
        "sensitive_data_access": 3,
        "cost_per_session_usd": 10.0,
    }
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.session_metrics = {}
        self.alert_handlers = []
    
    async def log_tool_call(self, session_id: str, tool_name: str, 
                           params: dict, result: dict, user_id: str):
        # Redact sensitive data before logging
        safe_params = self._redact_sensitive(params)
        safe_result = self._redact_sensitive(result)
        
        event = AgentSecurityEvent(
            event_type="tool_call",
            severity="INFO",
            agent_id=self.agent_id,
            session_id=session_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            details={
                "parameters": safe_params,
                "result_status": result.get("status"),
                "execution_time_ms": result.get("execution_time_ms"),
            }
        )
        
        await self._emit_event(event)
        await self._check_anomalies(session_id, event)
    
    async def log_security_event(self, session_id: str, event_type: str,
                                  severity: str, details: dict, user_id: str):
        event = AgentSecurityEvent(
            event_type=event_type,
            severity=severity,
            agent_id=self.agent_id,
            session_id=session_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            details=details
        )
        
        await self._emit_event(event)
        
        if severity == "CRITICAL":
            await self._trigger_alert(event)
    
    async def _check_anomalies(self, session_id: str, event: AgentSecurityEvent):
        metrics = self.session_metrics.setdefault(session_id, {
            "tool_calls": [],
            "failed_calls": 0,
            "total_cost": 0.0,
        })
        
        metrics["tool_calls"].append(datetime.utcnow())
        
        # Check tool call rate
        recent_calls = [t for t in metrics["tool_calls"] 
                       if (datetime.utcnow() - t).seconds < 60]
        if len(recent_calls) > self.ANOMALY_THRESHOLDS["tool_calls_per_minute"]:
            await self.log_security_event(
                session_id, "anomaly_detected", "WARNING",
                {"reason": "excessive_tool_calls", "count": len(recent_calls)},
                event.user_id
            )
    
    def _redact_sensitive(self, data: dict) -> dict:
        """Redact sensitive fields from log data."""
        sensitive_keys = {"password", "api_key", "token", "secret", "credential"}
        
        def redact(obj):
            if isinstance(obj, dict):
                return {
                    k: "***REDACTED***" if k.lower() in sensitive_keys else redact(v)
                    for k, v in obj.items()
                }
            elif isinstance(obj, list):
                return [redact(i) for i in obj]
            return obj
        
        return redact(data)
```

### 7. Multi-Agent Security

- Implement trust boundaries between agents.
- Validate and sanitize inter-agent communications.
- Prevent privilege escalation through agent chains.
- Isolate agent execution environments.
- Apply circuit breakers to prevent cascading failures.

#### Secure Multi-Agent Communication

```python
from typing import Optional
import jwt
from datetime import datetime, timedelta

class AgentTrustLevel(Enum):
    UNTRUSTED = 0
    INTERNAL = 1
    PRIVILEGED = 2
    SYSTEM = 3

class SecureAgentBus:
    """Secure communication layer for multi-agent systems."""
    
    def __init__(self, signing_key: bytes):
        self.signing_key = signing_key
        self.agent_registry = {}
        self.message_validators = []
        self.circuit_breakers = {}
    
    def register_agent(self, agent_id: str, trust_level: AgentTrustLevel,
                       allowed_recipients: List[str]):
        self.agent_registry[agent_id] = {
            "trust_level": trust_level,
            "allowed_recipients": allowed_recipients,
            "allowed_message_types": self._get_allowed_types(trust_level)
        }
        self.circuit_breakers[agent_id] = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60
        )
    
    async def send_message(self, sender_id: str, recipient_id: str,
                          message_type: str, payload: dict) -> dict:
        # Validate sender
        sender = self.agent_registry.get(sender_id)
        if not sender:
            raise SecurityViolation(f"Unknown sender agent: {sender_id}")
        
        # Check circuit breaker
        if self.circuit_breakers[sender_id].is_open:
            raise CircuitBreakerOpen(f"Agent {sender_id} is temporarily blocked")
        
        # Validate recipient authorization
        if recipient_id not in sender["allowed_recipients"]:
            await self._log_security_event(
                "unauthorized_message_attempt",
                {"sender": sender_id, "recipient": recipient_id}
            )
            raise SecurityViolation("Sender not authorized to message recipient")
        
        # Validate message type
        if message_type not in sender["allowed_message_types"]:
            raise SecurityViolation(f"Message type '{message_type}' not allowed")
        
        # Sanitize payload
        sanitized_payload = self._sanitize_payload(payload, sender["trust_level"])
        
        # Create signed message
        signed_message = {
            "sender": sender_id,
            "recipient": recipient_id,
            "type": message_type,
            "payload": sanitized_payload,
            "timestamp": datetime.utcnow().isoformat(),
            "signature": self._sign_message(sender_id, recipient_id, 
                                           message_type, sanitized_payload)
        }
        
        return signed_message
    
    async def receive_message(self, recipient_id: str, message: dict) -> dict:
        # Verify signature
        if not self._verify_signature(message):
            raise SecurityViolation("Invalid message signature")
        
        # Check message freshness (prevent replay attacks)
        msg_time = datetime.fromisoformat(message["timestamp"])
        if (datetime.utcnow() - msg_time) > timedelta(minutes=5):
            raise SecurityViolation("Message expired (possible replay attack)")
        
        # Validate recipient
        if message["recipient"] != recipient_id:
            raise SecurityViolation("Message recipient mismatch")
        
        return message["payload"]
    
    def _sanitize_payload(self, payload: dict, trust_level: AgentTrustLevel) -> dict:
        """Remove sensitive data based on trust level."""
        if trust_level < AgentTrustLevel.PRIVILEGED:
            # Remove system-level fields for lower trust agents
            payload = {k: v for k, v in payload.items() 
                      if not k.startswith("_system")}
        
        # Always sanitize potential injection content
        return sanitize_untrusted_content(payload)
```

### 8. Data Protection & Privacy

- Minimize sensitive data in agent context.
- Implement data classification and handling rules.
- Apply encryption for data at rest and in transit.
- Enforce data retention and deletion policies.
- Comply with privacy regulations (GDPR, CCPA).

#### Data Classification and Handling

```python
from enum import Enum
from typing import Callable

class DataClassification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # PII, financial, health

class DataProtectionPolicy:
    def __init__(self):
        self.classification_rules = []
        self.handling_rules = {}
        
    def classify_data(self, data: str, context: dict) -> DataClassification:
        """Automatically classify data based on content patterns."""
        patterns = {
            DataClassification.RESTRICTED: [
                r'\b\d{3}-\d{2}-\d{4}\b',      # SSN
                r'\b\d{16}\b',                  # Credit card
                r'\b[A-Z]{2}\d{6,9}\b',         # Passport
                r'diagnosis|prescription|patient',  # Health
            ],
            DataClassification.CONFIDENTIAL: [
                r'salary|compensation|bonus',
                r'api[_-]?key|password|secret',
                r'confidential|internal only',
            ],
            DataClassification.INTERNAL: [
                r'@company\.com',
                r'internal|draft|not for distribution',
            ]
        }
        
        for classification, pattern_list in patterns.items():
            if any(re.search(p, data, re.I) for p in pattern_list):
                return classification
        
        return DataClassification.PUBLIC
    
    def apply_protection(self, data: str, classification: DataClassification,
                         operation: str) -> str:
        """Apply appropriate protection based on classification."""
        handlers = {
            DataClassification.RESTRICTED: {
                "include_in_context": self._redact_fully,
                "log": self._redact_fully,
                "output": self._redact_fully,
            },
            DataClassification.CONFIDENTIAL: {
                "include_in_context": self._mask_partially,
                "log": self._redact_fully,
                "output": self._mask_partially,
            },
            DataClassification.INTERNAL: {
                "include_in_context": lambda x: x,
                "log": self._mask_partially,
                "output": lambda x: x,
            },
        }
        
        handler = handlers.get(classification, {}).get(operation, lambda x: x)
        return handler(data)
    
    def _redact_fully(self, data: str) -> str:
        return "[REDACTED]"
    
    def _mask_partially(self, data: str) -> str:
        if len(data) <= 4:
            return "****"
        return data[:2] + "*" * (len(data) - 4) + data[-2:]


# Usage in agent context building
class SecureContextBuilder:
    def __init__(self, policy: DataProtectionPolicy):
        self.policy = policy
    
    def build_context(self, documents: List[str], max_tokens: int = 4000) -> str:
        protected_docs = []
        
        for doc in documents:
            classification = self.policy.classify_data(doc, {})
            protected = self.policy.apply_protection(
                doc, classification, "include_in_context"
            )
            protected_docs.append(protected)
        
        # Combine and truncate
        context = "\n---\n".join(protected_docs)
        return context[:max_tokens * 4]  # Rough char estimate
```

## Do's and Don'ts

**Do:**

- Apply least privilege to all agent tools and permissions.
- Validate and sanitize all external inputs (user messages, documents, API responses).
- Implement human-in-the-loop for high-risk actions.
- Isolate memory and context between users/sessions.
- Monitor agent behavior and set up anomaly detection.
- Use structured outputs with schema validation.
- Sign and verify inter-agent communications.
- Classify data and apply appropriate protections.

**Don't:**

- Give agents unrestricted tool access or wildcard permissions.
- Trust content from external sources (websites, emails, documents).
- Allow agents to execute arbitrary code without sandboxing.
- Store sensitive data in agent memory without encryption/redaction.
- Let agents make high-impact decisions without human oversight.
- Ignore cost controls (unbounded loops can cause DoW).
- Pass unsanitized data between agents in multi-agent systems.
- Log sensitive data (PII, credentials) in plain text.

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](LLM_Prompt_Injection_Prevention_Cheat_Sheet.md)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [OpenAI Safety Best Practices](https://platform.openai.com/docs/guides/safety-best-practices)
- [Google Secure AI Framework (SAIF)](https://safety.google/safety/saif/)
