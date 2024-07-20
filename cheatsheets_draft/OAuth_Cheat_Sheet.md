# OAuth 2.0 Cheat Sheet

## Introduction

OAuth 2.0 is an open standard that allows applications to get access to protected resources and APIs on behalf of users without accessing their credentials. OAuth 2.0 can be used in Web, mobile, and desktop applications and is widely supported by identity providers and API vendors. OAuth 2.0, along with related standards and recommendations, provides a versatile framework for addressing a diverse set of use cases. With this versatility comes complexity that often has security implications. Mistakes can lead to serious vulnerabilities.

This Cheat Sheet provides guidance for application builders on how to deploy OAuth 2.0 and integrate with other participants of the OAuth 2.0 ecosystem in a secure manner.

## Contents

- [Terminology](#terminology)
    - [Roles](#roles)
    - [Access Tokens](#access-tokens)
    - [Refresh Tokens](#refresh-tokens)
    - [Tokens TTL](#tokens-ttl)
    - [Managing Tokens](#managing-tokens)
    - [Redirect URI](#redirect-uri)
- [Security Protective Measures](#security-protective-measures)
    - [Client Credentials Protection](#client-credentials-protection)
    - [CSRF Protection](#csrf-protection)
    - [Referer Header Leaks Protection](#referer-header-leaks-protection)
    - [Token Logging Protection](#token-logging-protection)
    - [Authorization Server Mix-Up Protection](#authorization-server-mix-up-protection)
    - [PKCE Considerations](#pkce-considerations)
- [Use Cases](#use-cases)
    - [Classic Web Application](#classic-web-application)
    - [Single Page Application](#single-page-application)
    - [Mobile Application](#mobile-application)
    - [Backend Service](#backend-service)

## Terminology

In this section, the most important terms for OAuth 2.0 will be shortly explained:

### Roles

OAuth 2.0 defines these four most important roles:

#### Resource Owner

The Resource Owner is the person or entity that can grant access to a certain resource. Typically, this is the end-user of an application.

#### Resource Server

The Resource Server is the server hosting the protected resource and deciding whether access (with an OAuth 2.0 Access Token) is accepted or not. This is the application or API you want to access.

#### Client

The Client is the application that accesses a protected resource (on the [Resource Server]) on behalf, and with the authorization of a [Resource Owner] (end-user).

#### Authorization Server

The Authorization Server is the service that authenticates the [Resource Owner] and issues [Access Tokens] to the [Client] after authorization by the [Resource Owner]. This could be your central Single Sign On (SSO) solution, or other Identity Provider (IdP).

### Access Tokens

Access tokens are credentials that the [Client] uses to obtain access to protected resources on behalf of the [Resource Owner]. Access tokens are issued to the [Client] by the [Authorization Server] after authorization (consent) from the [Resource Owner], and need to be verified by the [Resource Server].

Access tokens are opaque. The [Client] does not have to parse or understand token structure to use it at the [Resource Server].

### Refresh Tokens

Refresh tokens, on the other hand, are credentials that the [Client] uses to obtain access tokens. Refresh tokens are optionally issued to the [Client] in addition to the access token by the [Authorization Server] after authorization (consent) from the [Resource Owner]. The [Client] uses the refresh token to obtain a new access token after the old one has expired or has been otherwise invalidated.

Refresh tokens are also opaque. The [Client] only presents refresh tokens to the [Authorization Server], and never to the Resource Server.

### Tokens TTL

Time to live recommendation and the need for this feature.

### Managing Tokens

Best practices for managing tokens for client and authorization services

### Redirect URI

Implementing redirect URI in a secure and safe manner

## Security Protective Measures

### Client Credentials Protection

Implement `client_id` and `client_secret`

### CSRF Protection

Implement `state` parameter

### Referer Header Leaks Protection

How to avoid leaking the authorization code through the `Referer` Header

### Token Logging Protection

How to protect against logging the tokens in middlewares and server logs

### Authorization Server Mix-Up Protection

How to validate and target the proper authorization server

### PKCE Considerations

// Can be injected in the use cases as well.

## Use Cases

### Classic Web Application

### Single Page Application

### Mobile Application

### Backend Service

Backend services communicate between each other based on their needs, _e.g._ update database from a provider. In order to keep this communication secure and authorized, the client credentials grant is used, otherwise discussed as Machine to Machine (M2M) flow. This grant allows one service to be the [Client] and the [Resource Owner] at the same time. Authorization is then conducted by sending the Client ID and Secret to the [Authorization Server], and in return providing the service an access token.

This allows for only trusted back-end services to access the [Resource Server] by tracking the client IDs and secrets.

There are multiple ways to send the required fields to the Authorization server. The two most welcomed are by using POST parameters, or by using POST parameters in conjunction with the web Basic authentication.

#### Client Credentials Request

- POST parameters example:

```http
POST /oauth/accesstoken HTTP/1.1
Host: authorization.server.org
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<client_id>&client_secret=<client_secret>
```

- POST parameters in conjunction with the web Basic authentication:

```http
POST /oauth/accesstoken HTTP/<version>
Host: authorization.server.org
Authorization: Basic <base64(<client_id>:<client_secret>)>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<client_id>&client_secret=<client_secret>
```

The developer has the freedom to add scopes, and send them as a part of the request.

#### Client Credentials Response

The [Authorization Server] must return an access token, an expiry time, and a token type. A refresh token **should not** be returned in this flow!

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache
 
{
  "access_token":<access_token>,
  "token_type":"bearer",
  "expires_in":1800,
}
```

The developer has the freedom to add scopes, and it is essential to return the scope to validate the scope sent from the client side.

For more information on this flow, refer to [section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4) from [RFC6749].

[Resource Owner]: #resource-owner
[Resource Server]: #resource-server
[Client]: #client
[Authorization Server]: #authorization-server
[Access Tokens]: #access-tokens
[RFC6749]: https://tools.ietf.org/html/rfc6749
