# Introduction


This Cheat Sheet provides guidance on the various areas that need to be considered related to storing sensitive data. In short:


# Contents

- [Background](#background)
- [Storage Systems](#system-sec)
    - [DBMS-Security](#dbms-sec)
    - [Filesystem storage](#fs-sec)
    - [Cloud and Bucket Storage](#cloud-fs)
- [Data storage security architecture](#data-storage-security)
    - [Data used for Validation vs. Information](#validation-vs-information)
    - [Attack Vectors](#attack-vectors)
    - [Encrypting Data at rest](#encryption-at-rest)
    - [Encrypting data per user](#encryption-per-user)
    - [Tokenizing](#tokenizing)
- [Managing secrets](#pain-and-suffering)
    - [Managing Keys and Salts](#kms)
- [Access to Data and Permissions](#permissions-and-access)