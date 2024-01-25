---
search:
  exclude: true
---

# Verification

## `None` Examples

### Java

<!-- --8<-- [start:java] -->
```
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;

...

//Create a verification context for the token requesting
//explicitly the use of the HMAC-256 hashing algorithm
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC)).build();

//Verify the token, if the verification fail then a exception is thrown
DecodedJWT decodedToken = verifier.verify(token);
```
<!-- --8<-- [end:java] -->

### Python:pyjwt

<!-- --8<-- [start:pyjwt] -->
```
try:
    pyjwt.decode(encoded, key, algorithms=["HS256","ES256"])
except Exception as error:
    # handle exception here
    raise error
else:
    continue
```
<!-- --8<-- [end:pyjwt] -->

### NodeJS:Jose

<!-- --8<-- [start:jose] -->
```
const { payload, protectedHeader } = await jose.jwtVerify(jwt, secret, {
  algorithms: "HS256"
})

console.log(protectedHeader)
console.log(payload)
```
<!-- --8<-- [end:jose] -->
