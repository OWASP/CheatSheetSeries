# SQL Injection Prevention Cheat Sheet

## Introduction

An SQL injection attack occurs when untrusted data (usually strings) becomes part of a query's SQL syntax, modifying the logic of the SQL request.

The malicious data can come from various sources such as:

- a HTTP request (eg. from a malicious user);
- a LDAP directory;
- an incoming email;
- a third party REST API service;
- the database itself.

**Impact:** A successful SQL injection attack can, depending on database features and privileges, read data from the database, modify database data (insert/update/delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file existing on the DBMS file system or write files into the file system, and, in some cases, execute operating system commands.

**Resolution:** define the SQL structure separately from its data values, then bind those values through the database API:

- use parameterized queries for dynamic data values;
- use fixed application-owned choices for dynamic table names, columns names, sorting order (`ASC`, `DESC`), etc.

These controls apply regardless of whether data comes from an HTTP request, another service, or previously stored data.

A related class of vulnerability, happens when using ORMs frameworks, such as JPA/Hibernate, which have their own query language (JPQL/HQL). Applications using these frameworks might be vulnerable to injections of these query languages:

- JPQL injections (JPA);
- HQL injections (Hibernate);
- Dynamic LINQ injections.

For other injection types, see the [Injection Prevention Cheat Sheet](Injection_Prevention_Cheat_Sheet.md).

## Examples

### Basic SQL injection

A simple SQL injection flaw in Java is shown below. The "customerName" parameter is simply concatenated to build the query and an attacker can enter SQL code into that query and the application would take the attacker's code and execute it on the database.

```java
// UNSAFE!
String query = "SELECT account_balance FROM user_data WHERE user_name = '"
    + request.getParameter("customerName") + "'";
Statement statement = connection.createStatement();
ResultSet results = statement.executeQuery(query);
```

As explained below, the recommended safe implementation would use parameterized queries, using `?` as placeholders for the values:

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, customerName);
ResultSet results = statement.executeQuery();
```

### SQL injection with Procedure Calls

SQL injections can happen as well in procedure calls:

```java
// UNSAFE
CallableStatement statement = connection.prepareCall("{call sp_updateAccountBalance('" + customerName + "' , " + amount + ")}");
statement.execute();
```

As below, the recommended implementation uses parameterized queries:

```java
CallableStatement statement = connection.prepareCall("{call sp_updateAccountBalance(?,?)}");
statement.setString(1, customerName);
statement.setBigDecimal(2, amount);
statement.execute();
```

While this prevents injection when calling the procedure, the procedure itself might still be vulnerable to SQL injection as explained in the next subsection.

### SQL Injection inside stored Procedures and Functions

With stored procedures and user defined functions, the vulnerable code can actually be stored and executed in the database itself.

The following example, uses a PostgreSQL function to build a dynamic query from dynamic input and is vulnerable to SQL injections through both `p_table` and `p_username`:

```sql
-- UNSAFE!
CREATE OR REPLACE FUNCTION search_user(
    p_query TEXT
)
RETURNS TABLE (
    user_id INT,
    username TEXT,
    name TEXT,
    email TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT user_id, username, name, email
         FROM users
         WHERE username = ''' || p_query || '''
            OR name = ''' || p_query || '''
            OR email = ''' || p_query || '''';
END;
$$;
```

This is a safe version which avoids dynamic SQL (`EXECUTE`):

```sql
CREATE OR REPLACE FUNCTION search_user(
    p_query TEXT
)
RETURNS TABLE (
    user_id INT,
    username TEXT,
    name TEXT,
    email TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT u.user_id, u.username, u.name, u.email
    FROM users AS u
    WHERE u.username = p_query
       OR u.name = p_query
       OR u.email = p_query;
END;
$$;
```

## Primary Defenses

The preferred pattern is to use **parameterized queries** when including dynamic data in SQL requests. This works equally with SQL requests (through prepared statements) and calls to stored procedures.

Other options can be used to protect against SQL injections but are error-prone and their usage is not recommended:

- Input validation (using an allow-list) of dynamic input;
- Escaping dynamic inputs.

### Parameterized Queries

Injecting dynamic data through parameterized queries ensure that an attacker is not able to change the intent of a query.

If you need examples of prepared queries/parameterized queries in other languages, including Ruby, PHP, Cold Fusion, Perl, and Rust, see the [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md) or [Bobby Tables](http://bobby-tables.com/).

#### Parameterized Queries in Java

The following code example uses a `PreparedStatement`, Java's implementation of a parameterized query, to execute the same database query.

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, customerName);
ResultSet results = statement.executeQuery();
```

An input such as `tom' or '1'='1` is treated as the literal username to match, not as a condition added to the query. Parameter binding prevents this value from changing SQL syntax; it does not decide whether the caller may access the matching account.

The same pattern can be used for passing parameters to stored procedures:

```java
CallableStatement statement = connection.prepareCall("{call sp_updateAccountBalance(?,?)}");
statement.setString(1, customerName);
statement.setBigDecimal(2, amount);
statement.execute();
```

See [Oracle's JDBC stored-procedure documentation](https://docs.oracle.com/javase/tutorial/jdbc/basics/storedprocedures.html) for the API.

#### Parameterized Queries in C\# (.NET)

In .NET, the creation and execution of the query doesn't change. Just pass the parameters to the query using the `Parameters.Add()` call as shown below.

```csharp
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
OleDbCommand command = new OleDbCommand(query, connection);
command.Parameters.Add(new OleDbParameter("customerName", CustomerName.Text));
OleDbDataReader reader = command.ExecuteReader();
```

#### Parameterized Queries in Hibernate Query Language (HQL)

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

In addition to being a primary defense when nothing else is possible (e.g., when a bind variable isn't legal), input validation can also be a secondary defense used to detect unauthorized input before it is passed to the SQL query. For more information please see the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md). Proceed with caution here. Validated data is not necessarily safe to insert into SQL queries via string building.

See below for a discussion of using input validation for queries with dynamic table and column names.

This approach may be dangerous, an incomplete validation may allow for SQL injections. Moreover, a safe validation approach for a given SQL dialect may turn out to be unsafe for another SQL dialect.

Parameter markers represent data values, not table names, column names, or SQL keywords such as `ASC` and `DESC`; see the [PDO parameter-marker limitations](https://www.php.net/manual/en/pdo.prepare.php). Keep these structural choices fixed in code where possible. When users need to select among them, map their selection to a small set of application-owned tokens allowed for that query and reject unknown choices. For example, map a requested sort direction to the literal `ASC` or `DESC`, rather than appending the supplied text.

This mapping complements parameter binding. Continue binding all data values, even when they pass type, length, or format checks. Validation of a value does not make it safe to concatenate into SQL. See the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md) for validation guidance.

### Manually escaping (STRONGLY DISCOURAGED)

**Do not manually escape untrusted values to construct SQL queries. Use parameterized queries instead.**

Manually escaping the values into the SQL string is error-prone and attempts to do something which is normally handled by the database driver through parameter bindings. It can fail and allow SQL injections for several reasons:

- SQL escaping rules are not always straightforward;
- different SQL dialects have different rules;
- some databases have configuration which might affect the escaping behavior (such as MySQL [NO_BACKSLASH_ESCAPES](https://dev.mysql.com/doc/refman/9.7/en/sql-mode.html#sqlmode_no_backslash_escapes)).

Manually escaping should only be used as a last resort. If this is done, do not write your own SQL escaping logic, use one which is suitable for your database system and make sure this to adapt the escaping logic if another database system is used later on.

## Advanced topics

### Dynamic table and columns names

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

### Dynamic SQL in stored procedures and functions

PostgreSQL documents [`EXECUTE ... USING` for binding values](https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-EXECUTING-DYN) and `format('%I', ...)` for quoting identifiers.

See [Microsoft's secure dynamic SQL guidance](https://learn.microsoft.com/en-us/sql/connect/ado-net/sql/writing-secure-dynamic-sql?view=sql-server-ver17) calls for reviewing procedures that construct SQL and parameterizing their commands.

## Hardening

We also recommend adopting all of these additional defenses to provide defense in depth to limit damage in case of successful SQL injection attacks.

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

## Testing and detection

Review query construction in application code and stored procedures. Check that untrusted values are bound rather than concatenated into SQL, and that dynamic identifiers and sort directions come from the query's fixed mapping. Preparing the outer call is not evidence that a procedure's internal SQL is safe.

Use the [OWASP Web Security Testing Guide's SQL injection tests](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/) for manual and automated testing, including blind and out-of-band techniques.

## References

- [Oracle JDBC: Using Prepared Statements](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)
- [PostgreSQL: Executing Dynamic Commands](https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-EXECUTING-DYN)
- [PHP PDO: Parameter-Marker Limitations](https://www.php.net/manual/en/pdo.prepare.php)
