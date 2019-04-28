# Introduction

The microservice architecture is being increasingly used for designing and implementing application systems in both cloud-based and enterprise infrastructures. There are many security challenges need to be addressed in the application design and implementation phases. In order to address some security challenges it is necessity to collect information on application architecture.
The goal of this article is to provide concrete proposal of approach to collect microservice-based architecture information to securing application.

# Context

During securing applications based on microservices architecture, security architects/engineers usually face with the following questions (mostly referenced in the OWASP Application Security Verification Standard Project under the section V1 “Architecture, Design and Threat Modeling Requirements”), e.g.:
1. Threat modeling and enforcement of the principle of least privilege:
    * What scopes or API keys does microservice minimally need to access other microservice APIs?
    * What grants does microservice minimally need to access database or message queue?
2. Data leakage analysis:
    * What storages or message queues do contain sensitive data?
    * Does microservice read/write date from/to specific database or message queue?
    * What microservices are invoked by dedicated microservice? What data are passed between microservices?
3. Attack surface analysis:
    * What microservices endpoints need to be tested during security testing?

In most cases, existing application architecture documentation is not suitable to answer those questions. Next sections propose what architecture security-specific information can be collected to answer the questions above.

# Objective

The objective of the cheat sheet is to explain what architecture security-specific information can be collected to answer the questions above and provide to the security architects concrete proposal of approach to collect microservice-based architecture information to securing application.

# Proposition

## Collect information on the building blocks

### Identify and describe application-functionality services

Application-functionality services implement one or several business process or functionality (e.g., storing customer details, storing and displaying product catalog, customer order processing). Collect information on the parameters listed below related to each application-functionality service.
| Parameter name | Description | 
| :--- | :--- |
| Service name (ID) | Unique service name or ID
| Short description	| Short description of business process or functionality implemented by the microservice
| Link to source code repository | Specify a link to service source code repository
| Development Team | Specify development team which develops the microservice
| Application programming interface (API) definition | If microservice exposes external interface specify a link to the interface description (e.g., OpenAPI specification). It is advisable to define used security scheme, e.g. define scopes or API keys needed to invoke dedicated endpoint (e.g., [see](https://swagger.io/docs/specification/authentication/)).
| The microservice architecture description | Specify a link to the microservice architecture diagram, description (if available)|
| Link to runbook |	Specify a link to the microservice runbook | 

### Identify and describe infrastructure services

Infrastructure services including remote services implement authentication and authorization, service registration and discovery, security monitoring etc. Collect information on the parameters listed below related to each infrastructure service.
| Parameter name | Description | 
| :--- | :--- |
Parameter name	| Parameter description
|Service name (ID) | Unique service name or ID
|Short description | Short description of functionality implemented by the service (e.g., authentication, authorization, service registration and discovery, logging, security monitoring, API gateway).
|Link to source code repository | Specify a link to service source code repository (if applicable)
|Link to the service documentation | Specify a link to the service documentation that includes service API definition, operational guidance/runbook, etc.

### Identify and describe data storages

Collect information on the parameters listed below related to each data storage.
| Parameter name | Description | 
| :--- | :--- |
|Storage name (ID) | Unique storage name or ID
|Software type | Specify software that implements the data storage (e.g., PostgreSQL,Redis, Apache Cassandra).

### Identify and describe message queues

Messaging systems (e.g., Rabbit MQ or Apache Kafka) are used to implement asynchronous microservices communication mechanism. Collect information on the parameters listed below related to each message queue.
| Parameter name | Description | 
| :--- | :--- |
|Message queue (ID) | Unique message queue name or ID
|Software type | Specify software that implements the message queue (e.g., Rabbit MQ, Apache Kafka).

### Identify and describe data assets

Identify and describe data assets that processed by system microservices/services. It is advisable firstly to identify assets, which are valuable from a security perspective (e.g., “User information”, “Payment”). Collect information on the parameters listed below related to each asset.
| Parameter name | Description | 
| :--- | :--- |
| Asset name (ID) | Unique asset name or ID
| Protection level | Specify asset protection level (e.g., PII, confidential)
| Additional info | Add clarifying information

## Collect information on relations between building blocks

### Identify “service-to-storage” relations

Collect information on the parameters listed below related to each “service-to-storage” relation.
| Parameter name | Description | 
| :--- | :--- |
| Service name (ID) | Specify service name (ID) defined above
| Storage name (ID) | Specify storage name (ID) defined above
| Access type | Specify access type (e.g., “Read” or “Read/Write”

### Identify “service-to-service” synchronous communications

Collect information on the parameters listed below related to each “service-to-service” synchronous communication.
| Parameter name | Description | 
| :--- | :--- |
| Caller service name (ID) | Specify caller service name (ID) defined above
| Called service name (ID) | Specify called service name (ID) defined above
| Protocol/framework used| Specify Protocol/framework used for communication, e.g. HTTP (REST, SOAP), Apache Thrif, gRPC
| Short description | Shortly describe the purpose of communication (requests for query of information or request/commands for a state-changing business function) and data passed between services (if possible, specify asset name (ID) defined above)

### Identify “service-to-service” asynchronous communications

Collect information on the parameters listed below related to each “service-to-service” asynchronous communication.
| Parameter name | Description | 
| :--- | :--- |
| Publisher service name (ID) | Specify publisher service name (ID) defined above
| Subscriber service name (ID) | Specify subscriber service name (ID) defined above
| Message queue (ID) | Specify message queue (ID)defined above
| Short description | Shortly describe the purpose of communication (receiving of information or commands for a state-changing business function) and data passed between services (if possible, specify asset name (ID) defined above)

### Identify “asset-to-storage” relations

Collect information on the parameters listed below related to each “asset-to-storage” relations.
| Parameter name | Description | 
| :--- | :--- |
| Asset name (ID) | Asset name (ID) defined above
| Storage name (ID) | Specify storage name (ID) defined above
| Storage type | Specify storage type for the asset (golden source or cache)

## Create a graphical presentation of application architecture

It is advisable to create graphical presentation of application architecture (building blocks and relations defined above in form of services call graph or data flow diagram. In order to do that one can use special software tools (e.g. Enterprise Architect) or [DOT language](https://en.wikipedia.org/wiki/DOT_(graph_description_language)). See example of using DOT language [here](https://gist.github.com/vladgolubev/80c5523336ddec3859c0e90d9a070882).

## Use collected information in secure software development practices

Collected information may be useful for doing application security practices, e.g. during defining security requirements, threat modeling or security testing. Table below contain examples of  activities related to securing application architecture (as well as its mapping to OWASP ASVS 4.0) and tips for their implementation using information collected above.

| Activity description | Implementation tips | Mapping to OWASP ASVS 4.0 |
| :--- | :--- | :--- |
| Attack surface analysis | To enumerate microservices endpoints that need to be tested during security testing and analyzed during threat modeling analyze data collected under the following sections: "Identify and describe application-functionality services" (parameter “Application programming interface (API) definition”) and "Identify and describe infrastructure services" (parameter “Link to the service documentation”) | 1.1.2
| Data leakage analysis | To analyze possible data leakage analyze data collected under the following sections: "Identify and describe data assets", "Identify “service-to-storage” relations", "Identify “service-to-service” synchronous communications", "Identify “service-to-service” asynchronous communications" and "Identify “asset-to-storage” relations"	| 1.1.2
| Verify documentation and justification of all the application's trust boundaries, components, and significant data flows | To do that activity analyze data collected under the following sections: "Identify and describe application-functionality services", "Identify and describe infrastructure services", "Identify and describe data storages", "Identify and describe message queues", "Identify “service-to-storage” relations", "Identify “service-to-service” synchronous communications" and "Identify “service-to-service” asynchronous communications" | 1.1.4
| Verify definition and security analysis of the application's high-level architecture and all connected remote services | To do that activity analyze data collected under the following sections: "Identify and describe application-functionality services", "Identify and describe infrastructure services", "Identify and describe data storages" and "Identify and describe message queues" | 1.1.5
| Verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls | To do that activity analyze data collected under the section "Identify and describe infrastructure services" | 1.1.6
|Verify enforcement of the principle of least privilege in functions, data files, URLs, controllers, services, and other resources. This implies protection against spoofing and elevation of privilege | To define minimally needed microservice permissions analyze data collected under the following sections: "Identify and describe application-functionality services (parameter “Application programming interface (API) definition”)", "Identify “service-to-storage” relations", "Identify “service-to-service” synchronous communications" and "Identify “service-to-service” asynchronous communications" | 1.4.3
| Verify that all sensitive data is identified and classified into protection levels | To do that activity analyze data collected under the following sections "Identify and describe data assets" and "Identify “asset-to-storage” relations" | 1.8.1
|Verify the definition and documentation of all application components in terms of the business or security functions they provide | To do that activity analyze data collected under the following sections (parameter “Short description”): "Identify and describe application-functionality services" and "Identify and describe infrastructure services" | 1.11.1

# Authors and Primary Editors

Alexander Barabanov - barabanov.iu8@gmail.com