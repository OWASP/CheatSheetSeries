# SQL Injection Prevention Cheat Sheet

## Introduction

This cheat sheet will help you prevent SQL injection flaws in your applications. It will define what SQL injection is, explain where those flaws occur, and recommend solutions for defending against SQL injection attacks. [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) attacks are common because:

1. SQL Injection vulnerabilities are very common.
2. The application's database is a frequent target for attackers because it typically contains sensitive or critical data.

See as well:

* the [Injection Prevention Cheat Sheet](Injection_Prevention_Cheat_Sheet.md) for general information about injection attacks;
* the [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md).

## Overview

An SQL injection attack consists of insertion (injection) of additional logic into SQL request made by the application through.

This type of attacks happens as a result of building SQL queries using string concatenation with dynamic untrusted malicious data (usually strings).

**Impact:** A successful SQL injection attack can read sensitive data from the database, modify database data (insert/update/delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file existing on the DBMS file system or write files into the file system, and, in some cases, execute operating system commands.

The malicious data can come from various sources such as:

* from a user (eg. from a HTTP request);
* from a LDAP directory;
* from an incoming email;
* from a third party REST API service.

A related class of vulnerability, happens when using ORMs frameworks, such as JPA/Hibernate, which have their own query language (JPQL/HQL). These application might be vulnerable to injections of these requests (eg. **JPQL/SQL injections**).

### Simple example of SQL injections

A simple SQL injection flaw in Java is shown below. The "customerName" parameter is simply concatenated to build the query and an attacker can enter SQL code into that query and the application would take the attacker's code and execute it on the database.

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = '"
    + request.getParameter("customerName") + "'";
Statement statement = connection.createStatement();
ResultSet results = statement.executeQuery(query);
```

As explained below, a safe implementation would be:

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, customerName);
ResultSet results = statement.executeQuery();
```

### SQL injection and stored procedures

With stored procedures, the SQL code defined and stored in the database itself, and then called from the application. In this case the vulnerable code actually be stored and executed in the database.

The following contrived example, uses a stored procedure (PostgreSQL) to build a dynamic query from dynamic input and is vulnerable to SQL injections:

```sql
CREATE OR REPLACE FUNCTION get_user_from_table(
    p_table TEXT,
    p_username TEXT
)
RETURNS TABLE (user_id INT, username TEXT, email TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_table NOT IN ('users', 'archived_users') THEN
        RAISE EXCEPTION 'Invalid table name';
    END IF;

    RETURN QUERY EXECUTE format(
        'SELECT user_id, username, email
         FROM %I
         WHERE username = $1',
        p_table
    )
    USING p_username;
END;
$$;
```

### Classes of SQL injections

SQL Injection attacks can be divided into the following three classes:

- **Inband:** data is extracted using the same channel that is used to inject the SQL code. This is the most straightforward kind of attack, in which the retrieved data is presented directly in the application web page.
- **Out-of-band:** data is retrieved using a different channel (e.g., an email with the results of the query is generated and sent to the tester).
- **Inferential or Blind:** there is no actual transfer of data, but the tester is able to reconstruct the information by sending particular requests and observing the resulting behavior of the DB Server.

## Primary Defenses

When including dynamic data into SQL requests, the recommended pattern is to **parameterized queries** (prepared statement) to including dynamic data into SQL requests. You can as well use **parameterized call statements** (stored precedure calls).

Other options can be used to protect against SQL injections but are error-prone and their usage is not recommended:

- Input validation (using an allow-list) of dynamic input;
- Escaping all dynamic inputs.

### Parameterized Queries

Injecting dynamic data through parameterized queries ensure that an attacker is not able to change the intent of a query.

If you need examples of prepared queries/parameterized queries in other languages, including Ruby, PHP, Cold Fusion, Perl, and Rust, see the [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md) or this [site](http://bobby-tables.com/).

#### Safe Java Prepared Statement

The following code example uses a `PreparedStatement`, Java's implementation of a parameterized query, to execute the same database query.

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, customerName);
ResultSet results = statement.executeQuery();
```

In this example, if an attacker were to enter the userID as `tom' or '1'='1`, the parameterized query would look for a username that literally matches the entire string `tom' or '1'='1`. Thus, the database would be protected against injections of malicious SQL code.

The same pattern can be used for stored procedures:

```java
CallableStatement statement = connection.prepareCall("{call sp_getAccountBalance(?)}");
statement.setString(1, customerName);
ResultSet results = cs.executeQuery();
```

#### Safe Parameterized Queries in C\# (.NET)

In .NET, the creation and execution of the query doesn't change. Just pass the parameters to the query using the `Parameters.Add()` call as shown below.

```csharp
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
OleDbCommand command = new OleDbCommand(query, connection);
command.Parameters.Add(new OleDbParameter("customerName", CustomerName.Text));
OleDbDataReader reader = command.ExecuteReader();
```

#### Safe Parameterized Queries in Hibernate Query Language (HQL)

Some ORM frameworks such as [Hibernate](http://hibernate.org/) use dedicated query languages, such as Hibernate Query Language (HQL), which may suffer from the same injection problems ([HQL Injection](http://cwe.mitre.org/data/definitions/564.html)):

```java
// UNSAFE: HQL injection!
Query unsafeHQLQuery = session.createQuery("from Inventory where productID='"+userSuppliedParameter+"'");
```

Here as well parameterized queries is the recommended solution:

```java
// Here is a safe version of the same query using named parameters
Query safeHQLQuery = session.createQuery("from Inventory where productID=:productid");
safeHQLQuery.setParameter("productid", userSuppliedParameter);
```

### Allow-List Input Validation

Various parts of SQL queries aren't legal locations for the use of bind variables, such as the names of tables or columns, and the sort order indicator (ASC or DESC). In such situations, input validation or query redesign is the most appropriate defense. For the names of tables or columns, ideally those values come from the code, and not from user parameters.

But if user parameter values are used to make different for table names and column names, then the parameter values should be mapped to the legal/expected table or column names to make sure unvalidated user input doesn't end up in the query. Please note, this is a symptom of poor design and a full rewrite should be considered if time allows.

### Allow-list Input Validation (DISCOURAGED)

In addition to being a primary defense when nothing else is possible (e.g., when a bind variable isn't legal), input validation can also be a secondary defense used to detect unauthorized input before it is passed to the SQL query. For more information please see the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md). Proceed with caution here. Validated data is not necessarily safe to insert into SQL queries via string building.

See below for a discussion of using input validation for queries with dynamic table and column names.

This approach may be dangerous, an incomplete validation may allow for SQL injections. Moreover, a safe validation approach for a given SQL dialect may turn out to be unsafe for another SQL dialect.

### Escaping All Dynamic Inputs (STRONGLY DISCOURAGED)

This technique should only be used as a last resort, when none of the above are feasible. Input validation is probably a better choice as this methodology is frail compared to other defenses and we cannot guarantee it will prevent all SQL Injection in all situations.

This technique is to escape user input before putting it in a query. It's usually only recommended to retrofit legacy code when implementing input validation isn't cost effective.

This approach is unsound and dangerous because SQL escaping rules are not always straightforward and different SQL dialects have different rules. Moreover, some databases have configuration which might affect the escaping behavior (such as MySQL [NO_BACKSLASH_ESCAPES](https://dev.mysql.com/doc/refman/9.7/en/sql-mode.html#sqlmode_no_backslash_escapes)). For these reason, parameterized queries must be used.

## Other considerations

#### Dynamic table and columns names

Using user parameter values to target table or column names is a symptom of poor design and a full rewrite should be considered if time allows. If that is not possible, developers should map the parameter values to the legal/expected table or column names to make sure unvalidated user input doesn't end up in the query.

In the example below, since `tableName` is identified as one of the legal and expected values for a table name in this query, it can be directly appended to the SQL query:

```java
String tableName;
switch(PARAM) {
  case "Value1":
    tableName = "fooTable";
    break;
  case "Value2":
    tableName = "barTable";
    break;
  default:
    throw new InputValidationException("unexpected table name");
}
```

## Hardening

Beyond adopting one of the four primary defenses, we also recommend adopting all of these additional defenses to provide defense in depth. These additional defenses are:

- **Least Privilege**
- **Allow-list Input Validation**

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

### Code review

Check for any queries to the database which use string concatenation instead of parameterized queries.

Auditors should always look for uses of sp_execute, execute or exec within SQL Server stored procedures. Similar audit guidelines are necessary for similar functions for other vendors.

### Manual test

### Dynamic detection

[SQLMap](https://wiki.owasp.org/index.php/Automated_Audit_using_SQLMap) can automatically detect (and exploit) many types of SQL injections.

### Static code analysis

Static Code Analysis Data flow rules can detect use of unsanitized user controlled input into in SQL queries.

### Time delay Exploitation technique

The time delay exploitation technique is very useful when the tester find a Blind SQL Injection situation, in which nothing is known on the outcome of an operation. This technique consists in sending an injected query and in case the conditional is true, the tester can monitor the time taken to for the server to respond. If there is a delay, the tester can assume the result of the conditional query is true. This exploitation technique can be different from DBMS to DBMS (check DBMS specific section).

```text
http://www.example.com/product.php?id=10 AND IF(version() like '5%', sleep(10), 'false'))--
```

In this example the tester is checking whether the MySql version is 5.x or not, making the server delay the answer by 10 seconds. The tester can increase the delay time and monitor the responses. The tester also doesn't need to wait for the response. Sometimes they can set a very high value (e.g. 100) and cancel the request after some seconds.

### Out of band Exploitation technique

This technique is very useful when the tester find a Blind SQL Injection situation, in which nothing is known on the outcome of an operation. The technique consists of the use of DBMS functions to perform an out of band connection and deliver the results of the injected query as part of the request to the tester's server. Like the error based techniques, each DBMS has its own functions. Check for specific DBMS section.

## References

- [Oracle JDBC: Using Prepared Statements](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)
- [PHP PDO: Prepared Statements and Stored Procedures](https://www.php.net/pdo.prepared-statements)
