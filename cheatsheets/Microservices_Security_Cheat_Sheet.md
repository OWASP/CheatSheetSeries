# Microservices Security Cheat Sheet

## Introduction

The microservice architecture is being increasingly used for designing and implementing application systems in both cloud-based and on-premise infrastructures, high-scale applications and services. There are many security challenges that need to be addressed in the application design and implementation phases. The fundamental security requirements that have to be addressed during design phase are authentication and authorization. Therefore, it is vital for applications security architects to understand and properly use existing architecture patterns to implement authentication and authorization in microservices-based systems. The goal of this cheat sheet is to identify such patterns and to do recommendations for applications security architects on possible ways to use them.

## Edge-level authorization

Use gateway checks to reject unauthorized ingress requests, and prevent direct access that bypasses those checks. Keep fine-grained authorization at the service when it needs resource or business context. See [Authorization Patterns](Authorization_Patterns_Cheat_Sheet.md#gateway-and-proxy-enforcement) for gateway and proxy enforcement, its limitations, and propagated authorization context.

## Service-level authorization

Each service must enforce access to its protected operations, including internal calls. Prefer shared, reviewed policies as the system grows, with service-level enforcement of object, tenant, and business-specific rules. See [Authorization Patterns](Authorization_Patterns_Cheat_Sheet.md#service-level-authorization) for policy placement and [Policy and Data Distribution](Authorization_Policy_And_Data_Distribution_Cheat_Sheet.md) for update and outage handling. Gateway checks complement these controls; they do not establish that a downstream operation is authorized.

## External Entity Identity Propagation

Propagate authenticated user context in a form each receiving service can validate, and authenticate the calling service separately. A signature protects an assertion's integrity; it does not itself grant access to a requested resource. See [Identity Propagation Patterns](Identity_Propagation_Patterns_Cheat_Sheet.md) for forwarding, token exchange, trusted internal assertions, and their limitations.

## Service-to-service authentication

### Existing patterns

#### Mutual transport layer security

With an mTLS approach, each microservice can legitimately identify who it talks to, in addition to achieving confidentiality and integrity of the transmitted data. Each microservice in the deployment has to carry a public/private key pair and use that key pair to authenticate to the recipient microservices via mTLS. mTLS is usually implemented with a self-hosted Public Key Infrastructure. The main challenges of using mTLS are key provisioning and trust bootstrap, certificate revocation, and key rotation.

#### Token-based

The token-based approach works at the application layer. A token is a container that may contain the caller ID (microservice ID) and its permissions (scopes). The caller microservice can obtain a signed token by invoking a special security token service using its own service ID and password and then attaches it to every outgoing request, e.g., via HTTP headers. The called microservice can extract the token and validate it online or offline.
![Signed ID propagation](../assets/Token_validation.png)

1. Online scenario:
    - To validate incoming tokens, the microservice invokes a centralized service token service via network call.
    - Revoked (compromised) tokens can be detected.
    - High latency.
    - Should be applied to critical requests.
2. Offline scenario:
    - To validate incoming tokens, the microservice uses the downloaded service token service public key.
    - Revoked (compromised) tokens may not be detected.
    - Low latency.
    - Should be applied to non-critical requests.
In most cases, token-based authentication works over TLS, which provides confidentiality and integrity of data in transit.

## Logging

Logging services in microservice-based systems aim to meet the principles of accountability and traceability and help detect security anomalies in operations via log analysis. Therefore, it is vital for application security architects to understand and adequately use existing architecture patterns to implement audit logging in microservices-based systems for security operations. A high-level architecture design is shown in the picture below and is based on the following principles:

- Each microservice writes a log message to a local file using standard output (via stdout, stderr).
- The logging agent periodically pulls log messages and sends (publishes) them to the message broker (e.g., NATS, Apache Kafka).
- The central logging service subscribes to messages in the message broker, receives them, and processes them.
![Logging pattern](../assets/ms_logging_pattern.png)

High-level recommendations to logging subsystem architecture with its rationales are listed below.

1. Microservice shall not send log messages directly to the central logging subsystem using network communication. Microservice shall write its log message to a local log file:
    - this allows to mitigate the threat of data loss due to logging service failure due to attack or in case of its flooding by legitimate microservice
    - in case of logging service outage, microservice will still write log messages to the local file (without data loss), and after logging service recovery, logs will be available to shipping;
2. There shall be a dedicated component (logging agent) decoupled from the microservice. The logging agent shall collect log data on the microservice  (read local log file) and send it to the central logging subsystem. Due to possible network latency issues, the logging agent shall be deployed on the same host (virtual or physical machine) with the microservice:
    - this allows mitigating the threat of data loss due to logging service failure due to attack or in case of its flooding by legitimate microservice
    - in case of logging agent failure, microservice still writes information to the log file, logging agent after recovery will read the file and send information to message broker;
3. A possible DoS attack on the central logging subsystem logging agent shall not use an asynchronous request/response pattern to send log messages. There shall be a message broker to implement the asynchronous connection between the logging agent and central logging service:
    - this allows to mitigate the threat of data loss due to logging service failure in case of its flooding by legitimate microservice
    - in case of logging service outage, microservice will still write log messages to the local file (without data loss), and after logging service recovery, logs will be available to shipping;
4. Logging agent and message broker shall use mutual authentication (e.g., based on TLS) to encrypt all transmitted data (log messages) and authenticate themselves:
    - this allows mitigating threats such as: microservice spoofing, logging/transport system spoofing, network traffic injection, sniffing network traffic
5. Message broker shall enforce access control policy to mitigate unauthorized access and implement the principle of least privileges:
    - this allows mitigating the threat of microservice elevation of privileges
6. Logging agent shall filter/sanitize output log messages to make sure that sensitive data (e.g., PII, passwords, API keys) is never sent to the central logging subsystem (data minimization principle). For a comprehensive overview of items that should be excluded from logging, please see the [OWASP Logging Cheat Sheet](Logging_Cheat_Sheet.md#data-to-exclude).
7. Microservices shall generate a correlation ID that uniquely identifies every call chain and helps group log messages to investigate them. The logging agent shall include a correlation ID in every log message.
8. The logging agent shall periodically provide health and status data to indicate its availability or non-availability.
9. The logging agent shall publish log messages in a structured logs format (e.g., JSON, CSV).
10. The logging agent shall append log messages with context data, e.g., platform context (hostname, container name), runtime context (class name, filename).

For a comprehensive overview of events that should be logged and possible data format, please see the [OWASP Logging Cheat Sheet](Logging_Cheat_Sheet.md#which-events-to-log) and [Application Logging Vocabulary Cheat Sheet](Logging_Vocabulary_Cheat_Sheet.md)

## References

- [NIST Special Publication 800-204](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf) “Security Strategies for Microservices-based Application Systems”
- [NIST Special Publication 800-204A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf) “Building Secure Microservices-based Applications Using Service-Mesh Architecture”
- [Microservices Security in Action](https://www.manning.com/books/microservices-security-in-action), Prabath Siriwardena and Nuwan Dias, 2020, Manning
