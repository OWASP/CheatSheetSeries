# OAuth 2.0 Protocol Cheatsheet

This cheatsheet describes the best current security practices [1] for OAuth 2.0 as derived from its RFC [2][3]. OAuth became the standard for API protection and the basis for federated login using OpenID Connect. OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables clients to verify the identity of the end user based on the authentication performed by an authorization server, as well as to obtain basic profile information about the end user in an interoperable and REST-like manner.

## Terminology

- Access tokens = provide an abstraction, replacing different authorization constructs (e.g., username and password, assertion) for a single token understood by the resource server. This abstraction enables issuing access tokens valid for a short period, as well as removing the resource server's need to understand a wide range of authentication schemes.
- Refresh tokens = are credentials used to obtain access tokens. These are issued to the client by the authorization server and are used to obtain a new access token when the current access token becomes invalid or expires or to obtain additional access tokens with identical or narrower scope (access tokens may have a shorter lifetime and fewer permissions than authorized by the resource owner).
- Client = generally refers to an application making protected resource requests on behalf of the resource owner and with its authorization. The term "client" does not imply any particular implementation characteristics (e.g., whether the application executes on a server, a desktop, or other devices).
- Authorization Server (AS) = refers to the server issuing access tokens to the client after successfully authenticating the resource owner and obtaining authorization.
- Resource Owner (RO) = refers to an entity capable of granting access to a protected resource. When the resource owner is a person, it is referred to as an end user.
- Resource Server (RS) = refers to the server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.

## OAuth 2.0 Essential Basics

1. Clients and Authorization Server must not expose URLs that forward the user's browser to arbitrary URIs obtained from a query parameter ("open redirectors") which can enable exfiltration of authorization codes and access tokens.
2. Clients have ensured that the Authorization Server supports PKCE may rely on the CSRF protection provided by PKCE. In OpenID Connect flows, the "nonce" parameter provides CSRF protection. Otherwise, one-time user CSRF tokens carried in the "state" parameter that are securely bound to the user agent must be used for CSRF protection.
3. When an OAuth Client can interact with more than one Authorization Server, Clients should use the issuer "iss" parameter as a countermeasure, or based on an "iss" value in the authorization response (such as the "iss" Claim in the ID Token in OpenID)
4. When the other countermeasure options for OAuth clients interacting with more than one Authorization Servers are absent, Clients may instead use distinct redirect URIs to identify authorization endpoints and token endpoints.
5. An Authorization Server avoids forwarding or redirecting a request potentially containing user credentials accidentally.

## PKCE - Proof Key for Code Exchange Mechanism

OAuth 2.0 public clients utilizing the Authorization Code Grant are susceptible to the authorization code interception attack. Proof Key for Code Exchange (PKCE, pronounced "pixy") is the technique used to mitigate against the threat of authorization code interception attack.

Originally, PKCE is intended to be used solely focused on securing native apps, but then it became a deployed OAuth feature. It does not only protect against authorization code injection attacks but also protects authorization codes created for public clients as PKCE ensures that the attacker cannot redeem a stolen authorization code at the token endpoint of the authorization server without knowledge of the code_verifier.

6. Clients are preventing injection (replay) of authorization codes into the authorization response by using PKCE flow. Additionally, clients may use the OpenID Connect "nonce" parameter and the respective Claim in the ID Token instead. The PKCE challenge or OpenID Connect "nonce" must be transaction-specific and securely bound to the client and the user agent in which the transaction was started.
7. When using PKCE, Clients should use PKCE code challenge methods that do not expose the PKCE verifier in the authorization request. Otherwise, attackers who can read the authorization request can break the security provided by the PKCE. Authorization servers must support PKCE.
8. If a Client sends a valid PKCE "code_challenge" parameter in the authorization request, the authorization server enforces the correct usage of "code_verifier" at the token endpoint.
9. Authorization Servers are mitigating PKCE Downgrade Attacks by ensuring a token request containing a "code_verifier" parameter is accepted only if a "code_challenge" parameter is present in the authorization request.

## Implicit Grant

The implicit grant is a simplified authorization code flow optimized for clients implemented in a browser using a scripting language such as JavaScript. In the implicit flow, instead of issuing the client an authorization code, the client is issued an access token directly (as the result of the resource owner authorization). The grant type is implicit, as no intermediate credentials (such as an authorization code) are issued (and later used to obtain an access token).

10. Clients are using the response type "code" (aka authorization code grant type) or any other response type that causes the authorization server to issue access tokens in the token response, such as the "code id_token" response type. This allows the Authorization Server to detect replay attempts by attackers and generally reduces the attack surface since access tokens are not exposed in the URLs. It also allows the Authorization Server to sender-constrain the issued tokens.

## Token Replay Prevention

11. The Authorization and Resource Servers are using mechanisms for sender-constraining access tokens to prevent token replays, such as Mutual TLS for OAuth 2.0 or OAuth Demonstration of Proof of Possession (DPoP).
12. Refresh tokens are sender-constrained or use refresh token rotation.

## Access Token Privilege Restriction

13. The privileges associated with an access token should be restricted to the minimum required for the particular application or use case. This prevents clients from exceeding the privileges authorized by the Resource Owner. It also prevents users from exceeding their privileges authorized by the respective security policy. Privilege restrictions also help to reduce the impact of access token leakage.
14. Access tokens are restricted to certain Resource Servers (audience restriction), preferably to a single Resource Server. The Authorization Server should associate the access token with certain Resource Servers and every Resource Server is obliged to verify, for every request, whether the access token sent with that request was meant to be used for that particular Resource Server. If not, the Resource Server must refuse to serve the respective request. Clients and Authorization Servers may utilize the parameters "scope" and "resource", respectively to determine the Resource Server they want to access.
15. Access tokens are restricted to certain resources and actions on Resource Servers or resources. The Authorization Server should associate the access token with the respective resource and actions and every Resource Server is obliged to verify, for every request, whether the access token sent with that request was meant to be used for that particular action on the particular resource. If not, the Resource Server must refuse to serve the respective request. Clients and Authorization Servers may utilize the parameters "scope" and "authorization_details" to determine those resources and/or actions.

## Resource Owner Password Credentials Grant

16. The Resource Owner password credentials grant is not used. This grant type insecurely exposes the credentials of the Resource Owner to the client, increasing the attack surface of the application.

## Client Authentication

17. Authorization Servers are using client authentication if possible. It is recommended to use asymmetric (public-key based) methods for client authentication such as mTLS or "private_key_jwt" (OpenID Connect). When asymmetric methods for client authentication are used, Authorization Servers do not need to store sensitive symmetric keys, making these methods more robust against several attacks.

## Other Recommendations

18. Authorization Servers do not allow clients to influence their "client_id" or "sub" value or any other Claim that can be confused with a genuine Resource Owner. It is recommended to use end-to-end TLS.
19. Authorization responses are not transmitted over unencrypted network connections. Authorization Servers must not allow redirect URIs that use the "http" scheme except for native clients that use Loopback Interface Redirection.

References:

- [RFC 6750](https://www.rfc-editor.org/info/rfc6750)
- [RFC 6749](https://www.rfc-editor.org/info/rfc6749)
- [OAuth 2.0 Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#name-best-practices)
- [Mix-up attacks](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-18#mix_up)
- [RFC9207](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-18#section-2.1-4)
- [Other Countermeasures for Mix-up attacks](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-18#section-2.1-6)
