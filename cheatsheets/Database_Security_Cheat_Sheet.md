# Database Security Cheat Sheet

## Introduction

This cheat sheet provides advice for securely configuring SQL and NoSQL databases. It is designed to be used by application developers if they are responsible for managing the databases. For details about protecting against SQL Injection attacks, see the [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md).

## Protecting the Backend Database

The application's backend database should be isolated from other servers and only connect with as few hosts as possible. This task will depend on the system and network architecture. Consider these suggestions:

- Disabling network (TCP) access and requiring all access is over a local socket file or named pipe.
- Configuring the database to only bind on localhost.
- Restricting access to the network port to specific hosts with firewall rules.
- Placing the database server in a separate DMZ isolated from the application server.

Similar protections should protect any web-based management tools used with the database, such as phpMyAdmin.

When an application is running on an untrusted system (such as a thick-client), it should always connect to the backend through an API that can enforce appropriate access control and restrictions. Direct connections should **never ever** be made from a thick client to the backend database.

### Implementing Transport Layer Protection

Most database default configurations start with unencrypted network connections, though some do encrypt the initial authentication (such as Microsoft SQL Server). Even if the initial authentication is encrypted, the rest of the traffic will be unencrypted and all kinds of sensitive information will be sent across the network in clear text. The following steps should be taken to prevent unencrypted traffic:

- Configure the database to only allow encrypted connections.
- Install a trusted digital certificate on the server.
- The client application to connect using TLSv1.2+ with modern ciphers (e.g, AES-GCM or ChaCha20).
- The client application to verify that the digital certificate is correct.

The [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md) contains further guidance on securely configuring TLS.

## Configuring Secure Authentication

The database should always require authentication, including connections from the local server. Database accounts should be:

- Protected with strong and unique passwords.
- Used by a single application or service.
- Configured with the minimum permissions required as discussed in the [permissions section below](#creating-secure-permissions).

As with any system that has its own user accounts, the usual account management processes should be followed, including:

- Regular reviews of the accounts to ensure that they are still required.
- Regular reviews of permissions.
- Removing user accounts when an application is decommissioned.
- Changing the passwords when staff leave, or there is reason to believe that they may have been compromised.

For Microsoft SQL Server, consider the use of [Windows or Integrated-Authentication](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/authentication-in-sql-server), which uses existing Windows accounts rather than SQL Server accounts. This also removes the requirement to store credentials in the application, as it will connect using the credentials of the Windows user it is running under. The [Windows Native Authentication Plugins](https://dev.mysql.com/doc/connector-net/en/connector-net-programming-authentication-windows-native.html) provides similar functionality for MySQL.

### Storing Database Credentials Securely

Database credentials should never be stored in the application source code, especially if they are unencrypted. Instead, they should be stored in a configuration file that:

- Is outside of the web root.
- Has appropriate permissions so that it can only be read by the required user(s).
- Is not checked into source code repositories.

Where possible, these credentials should also be encrypted or otherwise protected using built-in functionality, such as the `web.config` encryption available in [ASP.NET](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings-and-configuration-files#encrypting-configuration-file-sections-using-protected-configuration).

## Creating Secure Permissions

When developers are assigning permissions to database user accounts, they should employ the principle of least privilege (i.e, the accounts should only have the minimal permissions required for the application to function). This principle can be applied at a number of increasingly granular levels depending on the functionality available in the database. You can do the following in all environments:

- Do not use the built-in `root`, `sa` or `SYS` accounts.
- Do not grant the account administrative rights over the database instance.
- Make sure the account can only connect from allowed hosts. This would often be `localhost` or the address of the application server.
- The account should only access the specific databases it needs. Development, UAT and Production environments should all use separate databases and accounts.
- Only grant the required permissions on the databases. Most applications would only need `SELECT`, `UPDATE` and `DELETE` permissions. The account should not be the owner of the database as this can lead to privilege escalation vulnerabilities.
- Avoid using database links or linked servers. Where they are required, use an account that has been granted access to only the minimum databases, tables, and system privileges required.

Most security-critical applications, apply permissions at more granular levels, including:

- Table-level permissions.
- Column-level permissions.
- Row-level permissions
- Blocking access to the underlying tables, and requiring all access through restricted [views](<https://en.wikipedia.org/wiki/View_(SQL)>).

## Database Configuration and Hardening

The database server's underlying operating system should be hardened by basing the it on a secure baseline such as the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) or the [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines).

The database application should also be properly configured and hardened. The following principles should apply to any database application and platform:

- Install any required security updates and patches.
- Configure the database services to run under a low privileged user account.
- Remove any default accounts and databases.
- Store [transaction logs](https://en.wikipedia.org/wiki/Transaction_log) on a separate disk to the main database files.
- Configure a regular backup of the database. Ensure that the backups are protected with appropriate permissions, and ideally encrypted.

The following sections gives some further recommendations for specific database software, in addition to the more general recommendations given above.

### Hardening a Microsoft SQL Server

- Disable `xp_cmdshell`, `xp_dirtree` and other stored procedures that are not required.
- Disable Common Language Runtime (CLR) execution.
- Disable the SQL Browser service.
- Disable [Mixed Mode Authentication](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver15) unless it is required.
- Ensure that the sample [Northwind and AdventureWorks databases](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/linq/downloading-sample-databases) have been removed.
- See Microsoft's articles on [securing SQL Server](https://docs.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server).

### Hardening a MySQL or a MariaDB Server

- Run the `mysql_secure_installation` script to remove the default databases and accounts.
- Disable the [FILE](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) privilege for all users to prevent them reading or writing files.
- See the [Oracle MySQL](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html) and [MariaDB](https://mariadb.com/kb/en/library/securing-mariadb/) hardening guides.

### Hardening a PostgreSQL Server

- See the [PostgreSQL Server Setup and Operation documentation](https://www.postgresql.org/docs/current/runtime.html) and the older [Security documentation](https://www.postgresql.org/docs/7.0/security.htm).

### MongoDB

- See the [MongoDB security checklist](https://docs.mongodb.com/manual/administration/security-checklist/).

### Redis

- See the [Redis security guide](https://redis.io/topics/security).
