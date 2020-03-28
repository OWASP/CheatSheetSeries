# Introduction


This Cheat Sheet provides guidance on the various areas that need to be considered related to storing sensitive data. In short:


# Contents

- [Background](#background)
- [Data used for Validation vs. Information](#validation-vs-information)
- [Attack Vectors](#attack-vectors)
- [Encrypting Data at rest](#encryption-at-rest)
- [Encrypting data per user](#encryption-per-user)
- [Tokenizing](#tokenizing)
- [Managing Keys and Salts](#kms)



## Background
In the age of GDPR and a host of privacy related information we have a pretty clear idea of which data is considered sensitive.
However, the information on how to handle sensitive data is surprising sparse and vague.
This document attempts to describe 3 progressively stricter levels of securing data.
The strictest data security level attempts to build several layers of security on top of an individual piece of data, in an attempt to make 
the application leak-resilient even when the application's code or configuration are problematic.
Since data usage is highly susceptible to individual business use cases, perhaps not all suggestions in this writeup apply to the use case at hand.

## Data used for Validation vs. Information

Before we begin considering possible attacks or solutions we need to know what use-cases we expect out of a piece of data.
In very general terms, we could split received data into Validation and Information.
**Validation** - used data is anything the user supplies to confirm something the application should already know. For example a credit card PIN number, a password, a card security number or the answer to a security question.

**Information** - used data is data that need to be shown to the user or other parties. This could be a username, first and last name, a user's address or any analytics or location data.

**Note** analytics or location data can of course be anonymized using several [differential privacy](https://en.wikipedia.org/wiki/Differential_privacy) techniques. However, this isn't in scope for this document.

## Attack Vectors
Usually, a system might leak data due to one of the following:
* data-store ACL misconfiguration such as unsecured S3 buckets, browsable db backups or public dbs
* application permission errors such as IDOR
* injections such as SQLi or command injections

There is a host of cheatsheets describing how to prevent each of the attack vectors considered above.

## Encrypting Data at Rest
This could be considered the simplest and easiest way of protecting sensitive data.
Most modern DBMS offer functionality that allows for encrypted databases or encrypted tables while some even allow encrypted rows.
Encrypting a database and it's backups adds an initial layer of security making life much harder for attackers with access to database files or backups.

## Encrypting data per user
While at rest encryption protects against data-store ACL misconfigurations, the application still has the one secret that can be used to access the data, be it a database connection string or an S3 bucket token.
Attackers with access to the data store as the application (in the case of a sql injection for example) can still read and manipulate data.
A possible solution is to remove the application's ability to access all the data at once. This could be implemented with encrypting individual user's data with a per-user key.

Using this architectural pattern, when the application need to access Information type data for a specific user, it can request the user's key from a third-party system such as a KMS or an HSM and use the key to decrypt the sensitive information before showing it to the user.
This way, if an attacker gains direct access to the data store with application level access (e.g. by exploiting a sqli), they won't be able to view the data.


## Tokenizing
The application does not require to know all the user's data, in a lot of cases it only needs a predictable representation of such data to use for validation purposes. Moreover, not all components, microservices or third parties need access to the **actual** user data.
Often, we can get away with [Tokenizing](https://en.wikipedia.org/wiki/Tokenization_(data_security)).

There are several approaches to data tokenizing with different advantages and disadvantages.
In general terms, a mapping between actual data and tokens can be stored or generated.
This mapping can then be used to represent the actual data for the remainder of the computation.

For example, let's consider the scenario where a user attempts to perform <X>. Usually during this action a user needs to provide <Y> to validate that they are who they claim to be.
The server only needs <Y> in order to compare it to a stored value, however, if the server can hash <Y> either using a per-user salt or an externally stored salt, <Y> can be substituted with it's token value. This way an attacker with access to this user's data cannot see the plain text value of <Y> since even the application does not know it.

An alternative tokenization approach is using some form of HSM to store a mapping between the plaintext and the token. The application can then submit the plain text to receive the token.
**Note** tokenizing is a sufficiently complicated process that depends on the specific use case. There is a lot of advice online on different tokenization approaches and it is suggested to consult a subject matter expert before implementing anything.



