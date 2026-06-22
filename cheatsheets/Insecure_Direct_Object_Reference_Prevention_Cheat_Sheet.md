# Insecure Direct Object Reference Prevention Cheat Sheet

## Introduction

Insecure Direct Object Reference (IDOR) is a vulnerability that arises when attackers can access or modify objects by manipulating identifiers used in a web application's URLs or parameters. It occurs due to missing access control checks, which fail to verify whether a user should be allowed to access specific data.

There are three ingredients to an IDOR:

1. An **object** such as an account, document, support ticket, transaction or partner profile.
2. A **reference** to that object in the form of an ID, UUID, account number, token or slug.
3. A **missing object-level authorization check** that allows a user to access or manipulate an object they should not be able to access.

## Examples

For instance, when a user accesses their profile, the application might generate a URL like this:

```
https://example.org/users/123
```

The 123 in the URL is a direct reference to the user's record in the database, often represented by the primary key. If an attacker changes this number to 124 and gains access to another user's information, the application is vulnerable to Insecure Direct Object Reference. This happens because the app didn't properly check if the user had permission to view data for user 124 before displaying it.

In some cases, the identifier may not be in the URL, but rather in the POST body, as shown in the following example:

```
<form action="/update_profile" method="post">
  <!-- Other fields for updating name, email, etc. -->
  <input type="hidden" name="user_id" value="12345">
  <button type="submit">Update Profile</button>
</form>
```

In this example, the application allows users to update their profiles by submitting a form with the user ID in a hidden field. If the app doesn't perform proper access control on the server-side, attackers can manipulate the "user_id" field to modify profiles of other users without authorization.

IDORs however are not limited to user profiles and sequential IDs. For instance:

```
GET /documents/annual-report.pdf
```

In this example, the filename acts as the object reference. If an attacker modifies the filename to another valid document, such as:

```
GET /documents/financial-statement.pdf
```

and gains access to a document belonging to another user, the application is vulnerable to IDOR. Object references are not limited to numeric identifiers and may include filenames, account numbers, tokens, or other values.

## Identifier complexity

In some cases, using more complex identifiers like GUIDs can make it practically impossible for attackers to guess valid values. However, even with complex identifiers, access control checks are essential. If attackers obtain URLs for unauthorized objects, the application should still block their access attempts.

## Verifying access controls

When testing for IDOR vulnerabilities, it is useful to create multiple user accounts with different authorization scopes. This allows developers and testers to verify that object-level authorization checks are consistently enforced.

For example:

1. Create User A and User B.
2. Create objects owned by each user (documents, support tickets, invoices, etc.).
3. Authenticate as User A and attempt to access User B's objects by modifying object references in requests.
4. Verify that the application denies unauthorized access regardless of whether the object identifier is predictable or unguessable.

This verification should be performed for all operations involving object references, including read, create, update, delete, export, and administrative actions.

## Mitigation

To mitigate IDOR, implement access control checks for each object that users try to access. Web frameworks often provide ways to facilitate this. Additionally, use complex identifiers as a defense-in-depth measure, but remember that access control is crucial even with these identifiers.

Avoid exposing identifiers in URLs and POST bodies if possible. Instead, determine the currently authenticated user from session information. When using multi-step flows, pass identifiers in the session to prevent tampering.

When looking up objects based on primary keys, use datasets that users have access to. For example, in Ruby on Rails:

```
// vulnerable, searches all projects
@project = Project.find(params[:id])
// secure, searches projects related to the current user
@project = @current_user.projects.find(params[:id])
```

Verify the user's permission every time an access attempt is made. Implement this structurally using the recommended approach for your web framework.

As an additional defense-in-depth measure, replace enumerable numeric identifiers with more complex, random identifiers. You can achieve this by adding a column with random strings in the database table and using those strings in the URLs instead of numeric primary keys. Another option is to use UUIDs or other long random values as primary keys. Avoid encrypting identifiers as it can be challenging to do so securely.

## Related Articles

- [Insecure Direct Object Reference (IDOR)](https://owasp.org/www-community/attacks/insecure_direct_object_reference)
- [Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
