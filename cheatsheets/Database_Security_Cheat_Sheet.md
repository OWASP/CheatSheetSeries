# Database Security Cheat Sheet

## Introduction

This cheat sheet describes methods for securing the SQL and NoSQL databases. It is designed to help application developers who must handle database security because their organization doesn't have a dedicated database administrator. However, this document does not address SQL injection attacks--refer to the [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md) for more information on that topic.

Index:

[Protecting the Backend Database](#protecting-the-backend-database)
[Managing Authentication for Database Servers](#managing-authentication-for-database-servers)
[Managing Permissions for Database Servers](#managing-permissions-for-database-servers)
[Database Server Hardening](#database-server-hardening)

## Protecting the Backend Database

First, you should protect your application's backend database from attackers by making sure that it only connects to absolutely necessary services. The scope of this task depends on your system and your network architecture. Here are some common approaches to limiting database connections:

- Disable network (TCP) access and require that all access occur using a local socket file or named pipe.
- Configure the database to only bind on localhost.
- Only provide network port access to specific hosts with tough firewall rules.
- Put the actual database server in a separate DMZ that is isolated from the application server.

Also you should add strong protective measures to all the web-based management tools used with the database (such as phpMyAdmin).

IMPORTANT: If an application is running on an untrusted system (such as a thick-client), it must always connect to the backend through an API that can enforce appropriate access control and restrictions. Direct connections should **never ever** be made from a thick client to the backend database.

### Managing the Transport Layer for Maximum Protection

Unfortunately, most database configurations default to unencrypted network connections. While some databases (like Microsoft SQL Server) encrypt the initial authentication at first, usually the rest of the traffic is still unencrypted. As a result, most servers default to sending sensitive information across the network in clear text. The [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md) contains further guidance on securely configuring the security of your server's transport layer, but you can immediately take some steps to prevent unencrypted traffic:

- Configure the database to only allow encrypted connections.
- Install a trusted digital certificate on the server.
- Ensure that the client application connects with TLSv1.2+ and modern ciphers (e.g, AES-GCM or ChaCha20).
- Make sure that the client application knows that the target server's digital certificate is correct.

## Managing Authentication for Database Servers

Your database should always require authentication, even with connections from the local server. Database accounts should be:

- Protected with strong and unique passwords.
- Used by a single application or service.
- Configured with the bare minimum permissions required to operate as discussed in the [permissions section below](#managing-permissions-for-database-servers).

If your system that has its own user accounts, follow the usual account management processes. They include:

- Regular reviews of the accounts to ensure that they are still required.
- Regular reviews of permissions using the principle of least privilege.
- Reviewing and removing user accounts when an application is decommissioned.
- Conducting password reviews when staff leave, or there is reason to believe that they may have been compromised.

### Authentication for SQL Server and MySQL in Windows

If your system uses Microsoft SQL Server databases, you should seriously consider [Windows or Integrated-Authentication](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/authentication-in-sql-server) because it uses existing Windows accounts instead of SQL Server accounts. Since this authentication method connects to SQL Server databases with the credentials of the Windows user and not their system credentials, you do not need to store credentials in the application. If you are using MySQL in Windows, the [Windows Native Authentication Plugins](https://dev.mysql.com/doc/connector-net/en/connector-net-programming-authentication-windows-native.html) provides similar functionality for system administrators.

### Storing Database Credentials

**Database credentials should never be stored in the application source code, especially if they are unencrypted**. Instead, they should be stored in a configuration file that:

- Is outside of the webroot.
- Has appropriate permissions so that it can only be read by the required user(s).
- Is not checked into source code repositories.

Where possible, these credentials should also be encrypted or otherwise protected using built-in functionality, such as the `web.config` encryption available in [ASP.NET](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings-and-configuration-files#encrypting-configuration-file-sections-using-protected-configuration).

## Managing Permissions for Database Servers

The permissions assigned to database user accounts should be based on the principle of least privilege (i.e, the accounts should only have the minimal permissions required for the account to function properly). Depending on the functionality available in the database, permissions can usually be applied at multiple granular levels. However, the following steps should be available to all environments:

- The built-in `root`, `sa` or `SYS` accounts should not be used.
- No account should have administrative rights over database instances.
- All accounts should only be able to connect from allowed hosts.
    - Generally, alllowed hosts should be `localhost` or the address of the application server.
- Each account should only have access to the databases that are needed by the user.
- Development, UAT and Production environments should all have separate databases and separate accounts (i.e. users should have different accounts for each environment).
- Each user should only have the appropriate database permissions that they need for their tasks and no more.
    - Most users only need `SELECT`, `UPDATE` and `DELETE` permissions for an application.
    - No account should be the owner of any database because that can lead to privilege escalation vulnerabilities.
- Avoid database links or linked servers if at all posssible.
    - Where they are absolutely required, the target account should only be granted access to only the minimum databases, tables, and system privileges required for that particular user.

Most security-critical applications are able to apply permissions at more granular levels, which normally includes:

- Table-level permissions.
- Column-level permissions.
- Row-level permissions.
- Blocking access to the underlying tables.
- Requiring all access through restricted [views](https://en.wikipedia.org/wiki/View_(SQL)).

## Database Server Hardening

Like all network servers, a database server's underlying operating system should be hardened using a secure baseline such as the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) or the [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines). Also, the database application itself should also be configured and hardened. At minimum, apply these hardening principles to a database application and its platform:

- Install all required security updates and patches.
- Configure the database services to run under a low privileged user account.
- Remove any default accounts and databases.
- Store [transaction logs](https://en.wikipedia.org/wiki/Transaction_log) on a disk that is separate from the main database files.
- Configure a regular backup of the database.
    - Ensure that the backups are protected with appropriate permissions, and ideally encrypted.

Below, we have advice for hardening specific database software beyond the general recommendations above.

### Hardening Microsoft SQL Server

- Disable `xp_cmdshell`, `xp_dirtree` and other stored procedures that are not required.
- Disable Common Language Runtime (CLR) execution.
- Disable the SQL Browser service.
- Disable [Mixed Mode Authentication](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver15) unless it is required.
- Ensure that the sample [Northwind and AdventureWorks databases](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/linq/downloading-sample-databases) have been removed.
- See Microsoft's articles on [securing SQL Server](https://docs.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server).

### Hardening MySQL and MariaDB

- Run the `mysql_secure_installation` script to remove the default databases and accounts.
- Disable the [FILE](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) privilege for all users to prevent them reading or writing files.
- See the [Oracle MySQL](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html) and [MariaDB](https://mariadb.com/kb/en/library/securing-mariadb/) hardening guides.

### Hardening PostgreSQL

- See the [PostgreSQL Server Setup and Operation documents](https://www.postgresql.org/docs/current/runtime.html) and the older [Security documentation](https://www.postgresql.org/docs/7.0/security.htm).

### Hardening MongoDB

- See the [MongoDB security checklist](https://docs.mongodb.com/manual/administration/security-checklist/).

### Hardening Redis

- See the [Redis security guide](https://redis.io/topics/security).
