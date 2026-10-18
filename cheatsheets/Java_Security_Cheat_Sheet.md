# Java Security Cheat Sheet

This cheat sheet highlights some specific topics for Java applications and references specific Cheat Sheets for more details.

See as well:

- [JAAS Cheat Sheet](JAAS_Cheat_Sheet.md)
- [Bean Validation Cheat Sheet](Bean_Validation_Cheat_Sheet.md)

## Serialization

Java Serialization can potentially be used to trigger arbitrary code execution:

- Do not deserialize untrusted data.
- Even deserializing trusted data coming from a database could be a security risk. A compromised database could be exploited to execute arbitrary code in your application.

See the [Deserialization Cheat Sheet](Deserialization_Cheat_Sheet.md) for more information on this topic.

## SQL and JPA injections

See the following Cheat Sheets for protection against SQL injection protection:

- [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md);
- [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md).

Using an ORM such as JPA/Hibernate does not constitute a blanket protection against injection attacks. JPA/Hibernate applications may be vulnerable to JPQL/HQL injection attacks. Query parameterization is still necessary. See the [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md) for example of JPA/Hibernate usage.
