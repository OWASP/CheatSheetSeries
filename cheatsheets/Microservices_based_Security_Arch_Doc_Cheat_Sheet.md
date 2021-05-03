# Microservices based Security Arch Doc Cheat Sheet

## Introduction

The microservice architecture is being increasingly used for designing and implementing application systems in both cloud-based and on-premise infrastructures. There are many security challenges need to be addressed in the application design and implementation phases. In order to address some security challenges it is necessity to collect security-specific information on application architecture.
The goal of this article is to provide a concrete proposal of approach to collect microservice-based architecture information to securing application.

## Context

During securing applications based on microservices architecture, security architects/engineers usually face with the following questions (mostly referenced in the [OWASP Application Security Verification Standard Project](https://github.com/OWASP/ASVS) under the section [V1 "Architecture, Design and Threat Modeling Requirements"](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)):

1. Threat modeling and enforcement of the principle of least privilege:
    - What scopes or API keys does microservice minimally need to access other microservice APIs?
    - What grants does microservice minimally need to access database or message queue?
2. Data leakage analysis:
    - What storages or message queues do contain sensitive data?
    - Does microservice read/write date from/to specific database or message queue?
    - What microservices are invoked by dedicated microservice? What data is passed between microservices?
3. Attack surface analysis:
    - What microservices endpoints need to be tested during security testing?

In most cases, existing application architecture documentation is not suitable to answer those questions. Next sections propose what architecture security-specific information can be collected to answer the questions above.

## Objective

The objectives of the cheat sheet are to explain what architecture security-specific information can be collected to answer the questions above and provide concrete proposal of approach to collect microservice-based architecture information to securing application.

## Proposition

### Collect information on the building blocks

#### Identify and describe application-functionality services

Application-functionality services implement one or several business process or functionality (e.g., storing customer details, storing and displaying product catalog). Collect information on the parameters listed below related to each application-functionality service.

| Parameter name | Description |
| :--- | :--- |
| Service name (ID) | Unique service name or ID
| Short description | Short description of business process or functionality implemented by the microservice
| Link to source code repository | Specify a link to service source code repository
| Development Team | Specify development team which develops the microservice
| API definition | If microservice exposes external interface specify a link to the interface description (e.g., OpenAPI specification). It is advisable to define used security scheme, e.g. define scopes or API keys needed to invoke dedicated endpoint (e.g., [see](https://swagger.io/docs/specification/authentication/)).
| The microservice architecture description | Specify a link to the microservice architecture diagram, description (if available)|
| Link to runbook | Specify a link to the microservice runbook |

#### Identify and describe infrastructure services

Infrastructure services including remote services may implement authentication, authorization, service registration and discovery, security monitoring, logging etc. Collect information on the parameters listed below related to each infrastructure service.

| Parameter name | Description |
| :--- | :--- |
|Service name (ID) | Unique service name or ID
|Short description | Short description of functionality implemented by the service (e.g., authentication, authorization, service registration and discovery, logging, security monitoring, API gateway).
|Link to source code repository | Specify a link to service source code repository (if applicable)
|Link to the service documentation | Specify a link to the service documentation that includes service API definition, operational guidance/runbook, etc.

#### Identify and describe data storages

Collect information on the parameters listed below related to each data storage.

| Parameter name | Description |
| :--- | :--- |
|Storage name (ID) | Unique storage name or ID
|Software type | Specify software that implements the data storage (e.g., PostgreSQL, Redis, Apache Cassandra).

#### Identify and describe message queues

Messaging systems (e.g., RabbitMQ or Apache Kafka) are used to implement asynchronous microservices communication mechanism. Collect information on the parameters listed below related to each message queue.

| Parameter name | Description |
| :--- | :--- |
|Message queue (ID) | Unique message queue name or ID
|Software type | Specify software that implements the message queue (e.g., RabbitMQ, Apache Kafka).

#### Identify and describe data assets

Identify and describe data assets that processed by system microservices/services. It is advisable firstly to identify assets, which are valuable from a security perspective (e.g., "User information", "Payment"). Collect information on the parameters listed below related to each asset.

| Parameter name | Description |
| :--- | :--- |
| Asset name (ID) | Unique asset name or ID
| Protection level | Specify asset protection level (e.g., PII, confidential)
| Additional info | Add clarifying information

### Collect information on relations between building blocks

#### Identify "service-to-storage" relations

Collect information on the parameters listed below related to each "service-to-storage" relation.

| Parameter name | Description |
| :--- | :--- |
| Service name (ID) | Specify service name (ID) defined above
| Storage name (ID) | Specify storage name (ID) defined above
| Access type | Specify access type, e.g. "Read" or "Read/Write"

#### Identify "service-to-service" synchronous communications

Collect information on the parameters listed below related to each "service-to-service" synchronous communication.

| Parameter name | Description |
| :--- | :--- |
| Caller service name (ID) | Specify caller service name (ID) defined above
| Called service name (ID) | Specify called service name (ID) defined above
| Protocol/framework used| Specify protocol/framework used for communication, e.g. HTTP (REST, SOAP), Apache Thrift, gRPC
| Short description | Shortly describe the purpose of communication (requests for query of information or request/commands for a state-changing business function) and data passed between services (if possible, in therms of assets defined above)

#### Identify "service-to-service" asynchronous communications

Collect information on the parameters listed below related to each "service-to-service" asynchronous communication.

| Parameter name | Description |
| :--- | :--- |
| Publisher service name (ID) | Specify publisher service name (ID) defined above
| Subscriber service name (ID) | Specify subscriber service name (ID) defined above
| Message queue (ID) | Specify message queue (ID) defined above
| Short description | Shortly describe the purpose of communication (receiving of information or commands for a state-changing business function) and data passed between services (if possible, in therms of assets defined above)

#### Identify "asset-to-storage" relations

Collect information on the parameters listed below related to each "asset-to-storage" relation.

| Parameter name | Description |
| :--- | :--- |
| Asset name (ID) | Asset name (ID) defined above
| Storage name (ID) | Specify storage name (ID) defined above
| Storage type | Specify storage type for the asset, e.g. "golden source" or "cache"

### Create a graphical presentation of application architecture

It is advisable to create graphical presentation of application architecture (building blocks and relations defined above) in form of services call graph or data flow diagram. In order to do that one can use special software tools (e.g. Enterprise Architect) or [DOT language](https://en.wikipedia.org/wiki/DOT_%28graph_description_language%29). See example of using DOT language [here](https://gist.github.com/vladgolubev/80c5523336ddec3859c0e90d9a070882).

### Use collected information in secure software development practices

Collected information may be useful for doing application security practices, e.g. during defining security requirements, threat modeling or security testing. Sections below contains examples of activities related to securing application architecture (as well as its mapping to OWASP projects) and tips for their implementation using information collected above.

#### Attack surface analysis

##### Implementation tips

To enumerate microservices endpoints that need to be tested during security testing and analyzed during threat modeling analyze data collected under the following sections:

- Identify and describe application-functionality services (parameter "API definition")
- Identify and describe infrastructure services (parameter "Link to the service documentation")

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.1.2](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)
- [OWASP Attack Surface Analysis Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)

#### Data leakage analysis

##### Implementation tips

To analyze possible data leakage analyze data collected under the following sections:

- Identify and describe data assets
- Identify "service-to-storage" relations
- Identify "service-to-service" synchronous communications
- Identify "service-to-service" asynchronous communications
- Identify "asset-to-storage" relations

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.1.2](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)
- [OWASP Top 10-2017 A3-Sensitive Data Exposure](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)

#### Application's trust boundaries, components, and significant data flows justification

##### Implementation tips

To verify documentation and justification of all the application's trust boundaries, components, and significant data flows analyze data collected under the following sections:

- Identify and describe application-functionality services
- Identify and describe infrastructure services
- Identify and describe data storages
- Identify and describe message queues
- Identify "service-to-storage" relations
- Identify "service-to-service" synchronous communications
- Identify "service-to-service" asynchronous communications

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.1.4](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)

#### Analysis of the application's high-level architecture

##### Implementation tips

To verify definition and security analysis of the application's high-level architecture and all connected remote services analyze data collected under the following sections:

- Identify and describe application-functionality services
- Identify and describe infrastructure services
- Identify and describe data storages
- Identify and describe message queues

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.1.5](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)

#### Implementation of centralized security controls verification

##### Implementation tips

To verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls analyze data collected under the section "Identify and describe infrastructure services".

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.1.6](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)

#### Enforcement of the principle of least privilege

##### Implementation tips

To define minimally needed microservice permissions analyze data collected under the following sections:

- Identify and describe application-functionality services (parameter "API definition")
- Identify "service-to-storage" relations
- Identify "service-to-service" synchronous communications
- Identify "service-to-service" asynchronous communications

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.4.3](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)

#### Sensitive data identification and classification

##### Implementation tips

To verify that all sensitive data is identified and classified into protection levels analyze data collected under the following sections:

- Identify and describe data assets
- Identify "asset-to-storage" relations

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.8.1](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)

#### Application components business/security functions verification

##### Implementation tips

To verify the definition and documentation of all application components in terms of the business or security functions they provide analyze data collected under the following sections (parameter "Short description"):

- Identify and describe application-functionality services
- Identify and describe infrastructure services

##### Mapping to OWASP projects

- [OWASP ASVS, V1 "Architecture, Design and Threat Modeling Requirements", #1.11.1](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md#v1-architecture-design-and-threat-modeling-requirements)
