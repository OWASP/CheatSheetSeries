# Introduction

Many applications use **JSON Web Tokens** (JWT) to allow the client to indicate its identity for further exchange after authentication.

From [JWT.IO](https://jwt.io/introduction):

*JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA.*

JSON Web Token is used to carry information related to the identity and characteristics (claims) of a client. This "container" is signed by the server in order to avoid that a client tamper it in order to change, for example, the identity or any characteristics (example: change the role from simple user to admin or change the client login).

This token is created during authentication (is provided in case of successful authentication) and is verified by the server before any processing. It is used by an application to allow a client to present a token representing his "identity card" (container with all information about him) to server and allow the server to verify the validity and integrity of the token in a secure way, all of this in a stateless and portable approach (portable in the way that client and server technologies can be different including also the transport channel even if HTTP is the most often used).

# Token structure

Token structure example taken from [JWT.IO](https://jwt.io/#debugger):

`[Base64(HEADER)].[Base64(PAYLOAD)].[Base64(SIGNATURE)]`

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```    

Chunk 1: **Header**

```json
    {
     "alg": "HS256",
     "typ": "JWT"
    }
```    

Chunk 2: **Payload**

```json
    {
     "sub": "1234567890",
     "name": "John Doe",
     "admin": true
    }
```    

Chunk 3: **Signature**

```javascript
HMACSHA256( base64UrlEncode(header) + "." + base64UrlEncode(payload), KEY )
```    

# Objective

This cheatsheet provides tips to prevent common security issues when using JSON Web Tokens (JWT) with Java.

The tips presented in this article are part of a Java project that was created to show the correct way to handle creation and validation of JSON Web Tokens. 

You can find the Java project [here](https://github.com/righettod/poc-jwt), it uses the official [JWT library](https://jwt.io/#libraries).

In the rest of the article, the term **token** refer to the **JSON Web Tokens** (JWT).

# Consideration about using JWT

Even if a JWT token is "easy" to use and allow to expose services (mostly REST style) in a stateless way, it's not the solution that fits for all applications because it comes with some caveats, like for example the question of the storage of the token (tackled in this cheatsheet) and others...

If your application does not need to be fully stateless, you can consider using traditional session system provided by all web frameworks and follow the advice from the dedicated [cheatsheet](Session_Management_Cheat_Sheet.md). However, for stateless applications, when well implemented, it's a good candidate.

# Issues

## NONE hashing algorithm

### Symptom

This attack, described [here](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) occur when a attacker alter the token and change the hashing algorithm to indicate, through, the *none* keyword, that the integrity of the token has already been verified. As explained in the link above *some libraries treated tokens signed with the none algorithm as a valid token with a verified signature*, so an attacker can alter the token claims and tkey will be trusted by the application.

### How to prevent

First, use a JWT library that is not exposed to this vulnerability.

Last, during token validation, explicitly request that the expected algorithm was used.

### Implementation example

``` java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;

...

//Create a verification context for the token requesting 
//explicitly the use of the HMAC-256 hashing algorithm
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC)).build();

//Verify the token, if the verification fail then a exception is throwed
DecodedJWT decodedToken = verifier.verify(token);
```

## Token sidejacking

### Symptom

This attack occur when a token has been intercepted/stolen by a attacker and this one use it to gain access to the system using targeted user identity.

### How to prevent

A way to protect is to add "user context" in the token. User context will be composed by the following information:

- A random string that will be generated during the authentication phase and will be included into the token and also send to the client as an hardened cookie (flags: [HttpOnly + Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) + [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies) + [cookie prefixes](https://googlechrome.github.io/samples/cookie-prefixes/)).
- A SHA256 hash of the random string will be stored in the token (instead of the raw value) in order to prevent that any XSS issue allow the attacker to read the random string value and set the expected cookie.

IP address will not be used because there some situation in which IP address can change during the same session like for example when a user access an application through his mobile and he change of mobile operator during the exchange then he change legitimately (often) is IP address. Moreover, using IP address can potentially cause issue at [European GDPR](http://www.eugdpr.org/) compliance level.

During token validation, if the received token do not contains the right context so, it is replayed and then it must be rejected.

### Implementation example

Code to create the token after success authentication.

``` java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;
// Random data generator
private SecureRandom secureRandom = new SecureRandom();

...

//Generate a random string that will constitute the fingerprint for this user
byte[] randomFgp = new byte[50];
secureRandom.nextBytes(randomFgp);
String userFingerprint = DatatypeConverter.printHexBinary(randomFgp);

//Add the fingerprint in a hardened cookie - Add cookie manually because 
//SameSite attribute is not supported by javax.servlet.http.Cookie class
String fingerprintCookie = "__Secure-Fgp=" + userFingerprint 
                           + "; SameSite=Strict; HttpOnly; Secure";
response.addHeader("Set-Cookie", fingerprintCookie);

//Compute a SHA256 hash of the fingerprint in order to store the 
//fingerprint hash (instead of the raw value) in the token
//to prevent an XSS to be able to read the fingerprint and 
//set the expected cookie itself
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

//Create the token with a validity of 15 minutes and client context (fingerprint) information
Calendar c = Calendar.getInstance();
Date now = c.getTime();
c.add(Calendar.MINUTE, 15);
Date expirationDate = c.getTime();
Map<String, Object> headerClaims = new HashMap<>();
headerClaims.put("typ", "JWT");
String token = JWT.create().withSubject(login)
   .withExpiresAt(expirationDate)
   .withIssuer(this.issuerID)
   .withIssuedAt(now)
   .withNotBefore(now)
   .withClaim("userFingerprint", userFingerprintHash)
   .withHeader(headerClaims)
   .sign(Algorithm.HMAC256(this.keyHMAC));
```

Code to validate the token.

``` java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;

...

//Retrieve the user fingerprint from the dedicated cookie
String userFingerprint = null;
if (request.getCookies() != null && request.getCookies().length > 0) {
 List<Cookie> cookies = Arrays.stream(request.getCookies()).collect(Collectors.toList());
 Optional<Cookie> cookie = cookies.stream().filter(c -> "__Secure-Fgp"
                                            .equals(c.getName())).findFirst();
 if (cookie.isPresent()) {
   userFingerprint = cookie.get().getValue();
 }
}

//Compute a SHA256 hash of the received fingerprint in cookie in order to compare 
//it to the fingerprint hash stored in the token
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

//Create a verification context for the token
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC))
                              .withIssuer(issuerID)
                              .withClaim("userFingerprint", userFingerprintHash)
                              .build();

//Verify the token, if the verification fail then a exception is throwed
DecodedJWT decodedToken = verifier.verify(token);
```

## Token explicit revocation by the user

### Symptom

This problem is inherent to JWT because a token become only invalid when it expires. The user has no built-in feature to explicitly revoke the validity of an token. This means that if it is stolen, a user cannot revoke the token itself and then block the attacker.

### How to prevent

A way to protect is to implement a token blacklist that will be used to mimic the "logout" feature that exists with traditional session system.

The blacklist will keep a digest (SHA-256 encoded in HEX) of the token with a revokation date, this, for a duration that must be superior to the duration validity of a issued token.

When the user want to "logout" then it call a dedicated service that will add the provided user token to the blacklist resulting in a immediate invalidation of the token for further usage in the application.

### Implementation example

#### Blacklist storage

A database table with the following structure will used as central blacklist storage.

``` sql
create table if not exists revoked_token(jwt_token_digest varchar(255) primary key, 
revokation_date timestamp default now());
```

#### Token revocation management

Code in charge of adding a token to the blacklist and check if a token is revoked.

``` java
/**
* Handle the revokation of the token (logout).
* Use a DB in order to allow multiple instances to check for revoked token 
* and allow cleanup at centralized DB level.
*/
public class TokenRevoker {

 /** DB Connection */
 @Resource("jdbc/storeDS")
 private DataSource storeDS;

 /**
  * Verify if a digest encoded in HEX of the ciphered token is present 
  * in the revokation table
  *
  * @param jwtInHex Token encoded in HEX
  * @return Presence flag
  * @throws Exception If any issue occur during communication with DB
  */
 public boolean isTokenRevoked(String jwtInHex) throws Exception {
     boolean tokenIsPresent = false;
     if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
         //Decode the ciphered token
         byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

         //Compute a SHA256 of the ciphered token
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] cipheredTokenDigest = digest.digest(cipheredToken);
         String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

         //Search token digest in HEX in DB
         try (Connection con = this.storeDS.getConnection()) {
             String query = "select jwt_token_digest from revoked_token where jwt_token_digest = ?";
             try (PreparedStatement pStatement = con.prepareStatement(query)) {
                 pStatement.setString(1, jwtTokenDigestInHex);
                 try (ResultSet rSet = pStatement.executeQuery()) {
                     tokenIsPresent = rSet.next();
                 }
             }
         }
     }

     return tokenIsPresent;
 }


 /**
  * Add a digest encoded in HEX of the ciphered token to the revokation token table
  *
  * @param jwtInHex Token encoded in HEX
  * @throws Exception If any issue occur during communication with DB
  */
 public void revokeToken(String jwtInHex) throws Exception {
     if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
         //Decode the ciphered token
         byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

         //Compute a SHA256 of the ciphered token
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] cipheredTokenDigest = digest.digest(cipheredToken);
         String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

         //Check if the token digest in HEX is already in the DB and add it if it is absent
         if (!this.isTokenRevoked(jwtInHex)) {
             try (Connection con = this.storeDS.getConnection()) {
                 String query = "insert into revoked_token(jwt_token_digest) values(?)";
                 int insertedRecordCount;
                 try (PreparedStatement pStatement = con.prepareStatement(query)) {
                     pStatement.setString(1, jwtTokenDigestInHex);
                     insertedRecordCount = pStatement.executeUpdate();
                 }
                 if (insertedRecordCount != 1) {
                     throw new IllegalStateException("Number of inserted record is invalid," +
                     " 1 expected but is " + insertedRecordCount);
                 }
             }
         }

     }
 }
```

## Token information disclosure

### Symptom

This attack occur when a attacker access to a token (or a set of tokens) and extract information stored into it (JWT token information are base64 encoded at the basis) in order to obtains information about the system. Information can be for example the security roles, login format...

### How to prevent

A way to protect, is to cipher the token using for example a symmetric algorithm.

It's also important to protect the ciphered data against attack like [Padding Oracle](https://www.owasp.org/index.php/Testing_for_Padding_Oracle_%28OTG-CRYPST-002%29) or any other attack using cryptanalysis.

In order to achieve all these goals, the algorithm *AES-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)* is used, this one provide *Authenticated Encryption with Associated Data*.

More details from [here](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#deterministic-authenticated-encryption-with-associated-data):

```text
AEAD primitive (Authenticated Encryption with Associated Data) provides functionality of symmetric 
authenticated encryption. 

Implementations of this primitive are secure against adaptive chosen ciphertext attacks. 

When encrypting a plaintext one can optionally provide associated data that should be authenticated 
but not encrypted. 

That is, the encryption with associated data ensures authenticity (ie. who the sender is) and 
integrity (ie. data has not been tampered with) of that data, but not its secrecy.

See RFC5116: https://tools.ietf.org/html/rfc5116
```

**Note:**

Here ciphering is added mainly to hide internal information but it's very important to remember that the first protection against tampering of the JWT token is the signature so, the token signature and is verification must be always in place.

### Implementation example

#### Token ciphering

Code in charge of managing the ciphering. [Google Tink](https://github.com/google/tink) dedicated crypto library is used to handle ciphering operations in order to use built-in best practices provided by this library.

``` java
/**
 * Handle ciphering and deciphering of the token using AES-GCM.
 *
 * @see "https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md"
 */
public class TokenCipher {

    /**
     * Constructor - Register AEAD configuration
     *
     * @throws Exception If any issue occur during AEAD configuration registration
     */
    public TokenCipher() throws Exception {
        AeadConfig.register();
    }

    /**
     * Cipher a JWT
     *
     * @param jwt          Token to cipher
     * @param keysetHandle Pointer to the keyset handle
     * @return The ciphered version of the token encoded in HEX
     * @throws Exception If any issue occur during token ciphering operation
     */
    public String cipherToken(String jwt, KeysetHandle keysetHandle) throws Exception {
        //Verify parameters
        if (jwt == null || jwt.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("Both parameters must be specified !");
        }

        //Get the primitive
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        //Cipher the token
        byte[] cipheredToken = aead.encrypt(jwt.getBytes(), null);

        return DatatypeConverter.printHexBinary(cipheredToken);
    }

    /**
     * Decipher a JWT
     *
     * @param jwtInHex     Token to decipher encoded in HEX
     * @param keysetHandle Pointer to the keyset handle
     * @return The token in clear text
     * @throws Exception If any issue occur during token deciphering operation
     */
    public String decipherToken(String jwtInHex, KeysetHandle keysetHandle) throws Exception {
        //Verify parameters
        if (jwtInHex == null || jwtInHex.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("Both parameters must be specified !");
        }

        //Decode the ciphered token
        byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

        //Get the primitive
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        //Decipher the token
        byte[] decipheredToken = aead.decrypt(cipheredToken, null);

        return new String(decipheredToken);
    }
}
```

#### Creation / Validation of the token

Use the token ciphering handler during the creation and the validation of the token.

Load keys (ciphering key was generated and stored using [Google Tink](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#generating-new-keysets)) and setup cipher.

``` java
//Load keys from configuration text/json files in order to avoid to store keys as String in JVM memory
private transient byte[] keyHMAC = Files.readAllBytes(Paths.get("src", "main", "conf", "key-hmac.txt"));
private transient KeysetHandle keyCiphering = CleartextKeysetHandle.read(JsonKeysetReader.withFile(
Paths.get("src", "main", "conf", "key-ciphering.json").toFile()));

...

//Init token ciphering handler
TokenCipher tokenCipher = new TokenCipher();
```

Token creation.

``` java
//Generate the JWT token using the JWT API...
//Cipher the token (String JSON representation)
String cipheredToken = tokenCipher.cipherToken(token, this.keyCiphering);
//Send the ciphered token encoded in HEX to the client in HTTP response...
```

Token validation.

``` java
//Retrieve the ciphered token encoded in HEX from the HTTP request...
//Decipher the token
String token = tokenCipher.decipherToken(cipheredToken, this.keyCiphering);
//Verify the token using the JWT API...
//Verify access...
```

## Token storage on client side

### Symptom

This occurs when an application stores the token in a manner exhibiting the following behavior:

- Automatically sent by the browser (*Cookie* storage).
- Retrieved even if the browser is restarted (Use of browser *localStorage* container).
- Retrieved in case of [XSS](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) issue (Cookie accessible to JavaScript code or Token stored in browser local/session storage).

### How to prevent

1.  Store the token using the browser *sessionStorage* container.
2.  Add it as a *Bearer* with JavaScript when calling services.
3.  Add [fingerprint](JSON_Web_Token_Cheat_Sheet_for_Java.md#token-sidejacking) information to the token.

By storing the token in browser *sessionStorage* container it expose the token to being stolen by through an XSS attack. However, fingerprints added to the token prevent reuse of the stolen token by the attacker on their machine. To close a maximum of exploitation surfaces for an attacker, add a browser [Content Security Policy](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#csp) to harden the execution context.

*Note:*

- The remaining case is when a attacker use the user browsing context as a proxy to use the target application through the legitimate user but the Content Security Policy can prevent communication with non expected domains.
- It's also possible to implements the authentication service in a way that the token is issued within a hardened cookie, but in this case, a protection against [Cross-Site Request Forgery](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) attack must be implemented.

### Implementation example

JavaScript code to store the token after authentication.

``` javascript
 /* Handle request for JWT token and local storage*/
 function getToken(){
     var login = $("#login").val();
     var postData = "login=" + encodeURIComponent(login) + "&password=test";

     $.post("/services/authenticate", postData,function (data){
         if(data.status == "Authentication successful !"){
             ...
             sessionStorage.setItem("token", data.token);
         }else{
             ...
             sessionStorage.removeItem("token");
         }
     })
     .fail(function(jqXHR, textStatus, error){
             ...
         sessionStorage.removeItem("token");
     });
 }
```

JavaScript code to add the token as *Bearer* when calling a service, for example a service to validate token here.

``` javascript
 /* Handle request for JWT token validation */
 function validateToken(){
     var token = sessionStorage.getItem("token");

     if(token == undefined || token == ""){
         $("#infoZone").removeClass();
         $("#infoZone").addClass("alert alert-warning");
         $("#infoZone").text("Obtain a JWT token first :)");
         return;
     }

     $.ajax({
         url: "/services/validate",
         type: "POST",
         beforeSend: function(xhr) {
             xhr.setRequestHeader("Authorization", "bearer " + token);
         },
         success: function(data) {
           ...
         },
         error: function(jqXHR, textStatus, error) {
           ...
         },
     });
 }
```

## Weak Token Secret

### Symptom

When the token is protected using a HMAC based algorithm, the security of the token is entirely dependent on the strength of the secret used with the HMAC. If an attacker can obtain a valid JWT they can then carry out an offline attack and attempt to crack the secret using tools such as [John the Ripper](https://github.com/magnumripper/JohnTheRipper) or [Hashcat](https://github.com/hashcat/hashcat).

If they are successful, they would then be able to modify the token and re-sign it with the key they had obtained. This could let them escalate their privileges, compromise other users accounts, or perform other actions depending on the contents of the JWT.

There are a number of [guides](https://www.notsosecure.com/crafting-way-json-web-tokens/) that document this process in greater detail.

### How to prevent

The simplest way to prevent this attack is to ensure that the secret used to sign the JWTs is strong and unique, in order to make it harder for an attacker to crack. As this secret would never need to be typed by a human, it should be at least 64 characters, and generated using a [secure source of randomness](Cryptographic_Storage_Cheat_Sheet.html#rule---use-cryptographically-secure-pseudo-random-number-generators-csprng).

Alternatively, consider the use of tokens that are signed with RSA rather than using a HMAC and secret key.

### Further Reading

- [{JWT}.{Attack}.Playbook](https://github.com/ticarpi/jwt_tool/wiki) - A project documents the known attacks and potential security vulnerabilities and misconfigurations of JSON Web Tokens.
- [JWT Best Practices Internet Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/)
