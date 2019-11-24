# Database Security Cheat Sheet

## Introduction

This cheat sheet provides guidance on securely configuring and using SQL databases. It is intended to be used by application developers when they are responsible for managing the databases, in the absence of a dedicated database administrator (DBA).

## Contents

FIXME

## Connecting to the Database

- Do not expose the database to the internet.
  - Connect over local sockets if network access is not required.
- Don't connect to DB from thick client or user-side applications.
- Restrict access to any web frontends such as phpMyAdmin.

### Transport Layer Protection

Most databases will allow unencrypted network connections in their default configurations. Although some will encrypt the initial authentication (such as Microsoft SQL Server), the rest of the traffic will be unencrypted, meaning that all kinds of sensitive information will be sent across the network in clear text. The following steps should be taken to avoid this

- Configure the database to only allow encrypted connections.
- Install a trusted digital certificate on the server.
- Configure the client application to connect using TLSv1.2 with modern (GCM) ciphers.
- Configure the client application to verify that the digital certificate is correct.

The [Transport Layer Protection](Transport_Layer_Protection_Cheat_Sheet.md) and [TLS Cipher String](TLS_Cipher_String_Cheat_Sheet.md) Cheat Sheets contain further guidance on securely configuring TLS.

## Authentication

The database should be configured to always require authentication, including connections from the local server. Database accounts should be :

- Protected with strong and unique passwords.
- Used by a single application or service.
- Configured with the minimum permissions required (as discussed in the [permissions section below](#permissions).

As with any system that has its own user accounts, the usual account management processes should be followed, including:

- Regular reviews of the accounts to ensure that they are still required.
- Regular reviews of permissions.
- Removing user accounts when an application is decommissioned.
- Changing the passwords when staff leave, or there is reason to believe that they may have been compromised.

For Microsoft SQL Server, consider the use of [Windows or integrated authentication](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/authentication-in-sql-server), which uses existing Windows accounts rather than SQL Server accounts. This also removes the requirement to store credentials in the application, as it will connect using the credentials of the Windows user it is running under.

### Storing Database Credentials

Database credentials should never be stored in the application source code, especially if they are unencrypted. Instead, they should be stored in a configuration file that:

- Is outside of the webroot.
- Has appropriate permissions so that it can only be read by the required user(s).
- Is not checked into source code repositories.

Where possible, these credentials should also be encrypted or otherwise protected using built in functionality, such as the `web.config` encryption available in [ASP.NET](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings-and-configuration-files#encrypting-configuration-file-sections-using-protected-configuration).

## Permissions

The permissions assigned to database user accounts should be based on the principle of least privilege (i.e, the accounts should only have the minimal permissions required for the application to function). This can be applied at a number of increasingly granular levels levels depending on the functionality available in the database. The following steps should be applicable to all environments:

- Do not use the built in `root` or `sa` or `SYS` accounts.
- Do not grant the account administrative rights over the database instance.
- Only allow the account to connect from whitelisted hosts.
  - This would often be `localhost` or the address of the application server.
- Only grant the account access to the specific databases it needs.
  - Development, UAT and Production environments should all use separate databases and accounts.
- Only grant the required permissions on the databases.
  - Most applications would only need `SELECT`, `UPDATE` and `DELETE` permissions.
  - The account should not be the owner of the database as this can allow privilege escalation.

For more security-critical applications, it is possible to apply permissions are more granular levels, including:

- Table-level permissions.
- Column-level permissions.
- Row-level permissions
- Blocking access to the underlying tables, and requiring all access through restricted [views](https://en.wikipedia.org/wiki/View_(SQL)).

### Advanced Permissions

- Only allow required operations (read/write).
- Use views to restrict access.
- Use table, column and row level security.

## Database Configuration and Hardening

- Install any required security updates and patches.
- Don't run DB services under privileged accounts (root/SYSTEM).
- Remove default accounts and databases.
- Harden DB based on vendor guidelines or CIS benchmarks.

## Database Specific Recommendations

### MySQL

- Run the `mysql_secure_installation` script to clean up default databases and accounts.
- Disable the [FILE](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) privilege for all users to prevent them reading or writing files.
- See the [Oracle](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html) and [CIS](FIXME) guidelines.

### Microsoft SQL Server

- Disable `xp_cmdshell`.
- Disable the SQL Browser service.
- See the [Microsoft](https://docs.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server) and [CIS](FIXME) guidelines.
