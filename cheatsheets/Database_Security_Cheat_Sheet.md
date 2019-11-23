# Database Security Cheat Sheet

## Introduction

This cheat sheet provides guidance on securely configuring and using SQL databases. It is intended to be used by application developers when they are responsible for managing the databases, in the absence of a dedicated database administrator (DBA).

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

- Use strong and unique passwords.
- Use integrated authentication where available.
- Store credentials securely.

## Permissions

- Don't use `root` or `sa` accounts.
  - These should be disabled where possible
- Restrict permissions based on principle of least privilege.
  - Only allow access from required hosts (or localhost).
  - Only allow access to required databases.
  - Application account should not be DB owner.
- Separate production and UAT/dev databases.

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
