# Introduction


This Cheat Sheet provides guidance on the various areas that need to be considered related to storing sensitive data.
Since sensitive data storage is not a new concept but instead can be referrenced by compbining aspects of other things, this cheatsheet links to the relevant parts of other cheatsheets.

# Contents

- [Storage Systems](#system-sec)
    - [DBMS-Security](#dbms-sec)
    - [Filesystem storage](#fs-sec)
    - [Cloud and Bucket Storage](#cloud-fs)
- [Managing secrets](#pain-and-suffering)
    - [Managing Keys and Salts](#kms)
- [Bonus Considerations](#data-storage-security)
    - [Encrypting data per user](#encryption-per-user)
    - [Tokenizing](#tokenizing)
- [Access to Data and Permissions](#permissions-and-access)

# Storage Systems

## DBMS Security
Often sensitive data is stored in databases which need to be secured, in order to do so, please refer to the [database security cheatsheet|Database_Security_Cheat_Sheet.md]

## File System Security
If a filesystem is used to store Sensitive Data, then please refer to the [file storage location |File_Upload_Cheat_Sheet.md#file-storage-location], [user permissions|File_Upload_Cheat_Sheet.md#user-permissions] and [file system permissions | File_Upload_Cheat_Sheet.md#filesystem-permissions]

# Managing Secrets
For managing secrets you can refer to the [Cryptographic Storage Cheatsheet | Cryptographic_Storage_Cheat_Sheet.md]

## Key Management Systems
Please refer to the relevant Key Management Section of the [Cryptographic Storage Cheatsheet | Cryptographic_Storage_Cheat_Sheet.md#key-management]

# Permissions and Access
The [Access Control Cheatsheet | Access_Control_Cheat_Sheet.md]
contains all the relevant information

# Bonus Considerations
## Encrypting Per User
If the sensitive data can be clearly associated with a single user (e.g. medical records, financial transactions) then the user's data can be encrypted with a key that is associated with the user. The Cryptographic Storage Cheatsheet can be used as a guidance on how to do this. This approach protects against an attacker who already has access to the data store, since the attacker will also have to get access to the storage location of the user's keys.
The unintented advantage of this approach is that if a user's data needs to be deleted, only the associated key needs to be destroyed as this will make data unusable.
