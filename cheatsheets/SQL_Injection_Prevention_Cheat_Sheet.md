# SQL Injection Prevention Cheat Sheet

## Introduction

SQL injection occurs when untrusted data becomes part of a query's SQL syntax. It can expose or modify database contents and, depending on database features and privileges, affect files or execute operating system commands. See the [OWASP Web Security Testing Guide](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/) for the attack model and testing guidance.

Use parameterized queries for data values, fixed application-owned choices for dynamic query structure, and least privilege to limit damage. These controls apply regardless of whether data comes from an HTTP request, another service, or previously stored data. For other injection types, see the [Injection Prevention Cheat Sheet](Injection_Prevention_Cheat_Sheet.md).

## Primary Defenses

### Defense Option 1: Prepared Statements (with Parameterized Queries)

Define the SQL structure separately from its data values, then bind those values through the database API. [Prepared statements treat bound values as data rather than SQL syntax](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html). Concatenating untrusted values into the query before preparing it defeats this protection.

This illustrative Java example assumes an existing connection and a `customerName` value supplied by the application. It shows parameter binding; resource cleanup and error handling are omitted.

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, customerName);
ResultSet results = statement.executeQuery();
```

An input such as `tom' or '1'='1` is treated as the literal username to match, not as a condition added to the query. Parameter binding prevents this value from changing SQL syntax; it does not decide whether the caller may access the matching account.

When using object-relational mapping (ORM) frameworks, bind untrusted values in query strings instead of concatenating them; [Hibernate queries can be vulnerable to injection](https://cwe.mitre.org/data/definitions/564.html). For language and framework examples, see the [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md).

### Stored Procedures

Stored procedures keep SQL code in the database, but are not automatically safe from injection. Bind arguments when calling a procedure; see [Oracle's JDBC stored-procedure documentation](https://docs.oracle.com/javase/tutorial/jdbc/basics/storedprocedures.html) for the API.

**Binding procedure arguments protects the call, not dynamic SQL constructed inside the procedure.** Use static SQL with parameters, or separately bind data values in internal dynamic queries instead of concatenating them into SQL text. [Microsoft's secure dynamic SQL guidance](https://learn.microsoft.com/en-us/sql/connect/ado-net/sql/writing-secure-dynamic-sql?view=sql-server-ver17) calls for reviewing procedures that construct SQL and parameterizing their commands.

For example, [PostgreSQL documents `EXECUTE ... USING` for binding values](https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-EXECUTING-DYN) and `format('%I', ...)` for quoting identifiers. Select identifiers from fixed application-owned mappings. Identifier quoting protects SQL syntax, but does not restrict which tables the application may select.

### Allow-List Input Validation

Parameter markers represent data values, not table names, column names, or SQL keywords such as `ASC` and `DESC`; see the [PDO parameter-marker limitations](https://www.php.net/manual/en/pdo.prepare.php). Keep these structural choices fixed in code where possible. When users need to select among them, map their selection to a small set of application-owned tokens allowed for that query and reject unknown choices. For example, map a requested sort direction to the literal `ASC` or `DESC`, rather than appending the supplied text.

This mapping complements parameter binding. Continue binding all data values, even when they pass type, length, or format checks. Validation of a value does not make it safe to concatenate into SQL. See the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md) for validation guidance.

### Escaping All Dynamic Inputs (STRONGLY DISCOURAGED)

Do not use manual escaping as a substitute for parameter binding. Escaping depends on the SQL dialect and configuration: for example, MySQL's [NO_BACKSLASH_ESCAPES mode](https://dev.mysql.com/doc/refman/9.7/en/sql-mode.html#sqlmode_no_backslash_escapes) disables backslash escaping. Replace query construction that relies on escaping with parameterized queries.

## Hardening

Use least privilege alongside parameterized queries and allow-list mapping. It limits the damage an attacker can cause through a database account; it does not prevent SQL injection.

### Least Privilege

To minimize the potential damage of a successful SQL injection attack, you should minimize the privileges assigned to every database account in your environment. Start from the ground up to determine what access rights your application accounts require, rather than trying to figure out what access rights you need to take away.

Make sure that accounts that only need read access are only granted read access to the tables they need access to. DO NOT ASSIGN DBA OR ADMIN TYPE ACCESS TO YOUR APPLICATION ACCOUNTS. We understand that this is easy, and everything just "works" when you do it this way, but it is very dangerous.

#### Minimizing Application and OS Privileges

SQL injection is not the only threat to your database data. Attackers can simply change the parameter values from one of the legal values they are presented with, to a value that is unauthorized for them, but the application itself might be authorized to access. As such, minimizing the privileges granted to your application will reduce the likelihood of such unauthorized access attempts, even when an attacker is not trying to use SQL injection as part of their exploit.

While you are at it, you should minimize the privileges of the operating system account that the DBMS runs under. Don't run your DBMS as root or system! Most DBMSs run out of the box with a very powerful system account. For example, MySQL runs as system on Windows by default! Change the DBMS's OS account to something more appropriate, with restricted privileges.

#### Details Of Least Privilege When Developing

If an account only needs access to portions of a table, consider creating a view that limits access to that portion of the data and assigning the account access to the view instead of the underlying table. Rarely, if ever, grant create or delete access to database accounts.

If you adopt a policy where you use stored procedures everywhere, and don't allow application accounts to directly execute their own queries, then restrict those accounts to only be able to execute the stored procedures they need. Don't grant them any rights directly to the tables in the database.

#### Least Admin Privileges For Multiple DBs

The designers of web applications should avoid using the same owner/admin account in the web applications to connect to the database. Different DB users should be used for different web applications.

In general, each separate web application that requires access to the database should have a designated database user account that the application will use to connect to the DB. That way, the designer of the application can have good granularity in the access control, thus reducing the privileges as much as possible. Each DB user will then have select access to only what it needs, and write-access as needed.

As an example, a login page requires read access to the username and password fields of a table, but no write access of any form (no insert, update, or delete). However, the sign-up page certainly requires insert privilege to that table; this restriction can only be enforced if these web apps use different DB users to connect to the database.

#### Enhancing Least Privilege with SQL Views

You can use SQL views to further increase the granularity of access by limiting the read access to specific fields of a table or joins of tables. It could have additional benefits.

For example, a product catalog can use a view that exposes product names and retail prices while omitting supplier costs. Grant the application's database account only `SELECT` access to that view, without access to the underlying table or other objects that expose the omitted fields. Verify your database's view privilege rules; for example, [PostgreSQL normally checks underlying table access using the view owner's privileges](https://www.postgresql.org/docs/current/sql-createview.html).

This limits the data exposed through a compromised application account. Queries against views still require parameterization to prevent SQL injection.

## Detection

Review query construction in application code and stored procedures. Check that untrusted values are bound rather than concatenated into SQL, and that dynamic identifiers and sort directions come from the query's fixed mapping. Preparing the outer call is not evidence that a procedure's internal SQL is safe.

Use the [OWASP Web Security Testing Guide's SQL injection tests](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/) for manual and automated testing, including blind and out-of-band techniques.

## References

- [Oracle JDBC: Using Prepared Statements](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)
- [PostgreSQL: Executing Dynamic Commands](https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-EXECUTING-DYN)
- [PHP PDO: Parameter-Marker Limitations](https://www.php.net/manual/en/pdo.prepare.php)
