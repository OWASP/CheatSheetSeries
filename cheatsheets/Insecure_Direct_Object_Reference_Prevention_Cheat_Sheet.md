# Insecure Direct Object Reference Prevention Cheat Sheet

## Introduction

**I**nsecure **D**irect **O**bject **R**eference (called **IDOR** from here) occurs when a application exposes a reference to an internal implementation object. Using this way, it reveals the real identifier and format/pattern used of the element in the storage backend side. The most common example of it (although is not limited to this one) is a record identifier in a storage system (database, filesystem and so on).

IDOR is referenced in element [A4](https://wiki.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References) of the OWASP Top 10 in the 2013 edition.

## Context

IDOR do not bring a direct security issue because, by itself, it reveals only the format/pattern used for the object identifier. IDOR bring, depending on the format/pattern in place, a capacity for the attacker to mount a enumeration attack in order to try to probe access to the associated objects.

Enumeration attack can be described in the way in which the attacker build a collection of valid identifiers using the discovered format/pattern and test them against the application.

**For example:**

Imagine an HR application exposing a service accepting employee ID in order to return the employee information and for which the format/pattern of the employee ID is the following:

```text
EMP-00000
EMP-00001
EMP-00002
...
```

Based on this, an attacker can build a collection of valid ID from *EMP-00000* to *EMP-99999*.

To be exploited, an IDOR issue must be combined with an [Access Control](Access_Control_Cheat_Sheet.md) issue because it's the Access Control issue that "allows" the attacker to access the object for which they have guessed the identifier through the enumeration attack.

## Additional remarks

**From Jeff Williams**:

Direct Object Reference is fundamentally a Access Control problem. We split it out to emphasize the difference between URL access control and data layer access control. You can't do anything about the data-layer problems with URL access control. And they're not really input validation problems either. But we see DOR manipulation all the time. If we list only "Messed-up from the Floor-up Access Control" then people will probably only put in SiteMinder or JEE declarative access control on URLs and call it a day. That's what we're trying to avoid.

**From Eric Sheridan**:

An object reference map is first populated with a list of authorized values which are temporarily stored in the session. When the user requests a field (ex: color=654321), the application does a lookup in this map from the session to determine the appropriate column name. If the value does not exist in this limited map, the user is not authorized. Reference maps should not be global (i.e. include every possible value), they are temporary maps/dictionaries that are only ever populated with authorized values.

"A direct object reference occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, database record, or key, as a URL or form parameter."

I'm "down" with DOR's for files, directories, etc. But not so much for ALL databases primary keys. That's just insane, like you are suggesting. I think that anytime database primary keys are exposed, an access control rule is required. There is no way to practically DOR all database primary keys in a real enterprise or post-enterprise system.

But, suppose a user has a list of accounts, like a bank where database ID 23456 is their checking account. I'd DOR that in a heartbeat. You need to be prudent about this.

## Objective

This article propose an idea to prevent the exposure of real identifier in a simple, portable and stateless way because the proposal need to handle Session and Session-less application topologies.

## Proposition

The proposal use a hash to replace the direct identifier. This hash is salted with a value defined at application level in order support topology in which the application is deployed in multi-instances mode (case for production).

Using a hash allow the following properties:

- Do not require to maintain a mapping table (real ID vs front end ID) in user session or application level cache.
- Makes creation of a collection a enumeration values more difficult to achieve because, even if attacker can guess the hash algorithm from the ID size, it cannot reproduce value due to the salt that is not tied to the hidden value.

This is the implementation of the utility class that generate the identifier to use for exchange with the front end side:

``` java
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Handle the creation of ID that will be send to front end side
 * in order to prevent IDOR
 */

public class IDORUtil {
    /**
     * SALT used for the generation of the HASH of the real item identifier
     * in order to prevent to forge it on front end side.
     */
    private static final String SALT = "[READ_IT_FROM_APP_CONFIGURATION]";

    /**
     * Compute a identifier that will be send to the front end and be used as item
     * unique identifier on client side.
     *
     * @param realItemBackendIdentifier Identifier of the item on the backend storage
     *                                  (real identifier)
     * @return A string representing the identifier to use
     * @throws UnsupportedEncodingException If string's byte cannot be obtained
     * @throws NoSuchAlgorithmException If the hashing algorithm used is not
     *                                  supported is not available
     */
    public static String computeFrontEndIdentifier(String realItemBackendIdentifier)
     throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String frontEndId = null;
        if (realItemBackendIdentifier != null && !realItemBackendIdentifier.trim().isEmpty()) {
            //Prefix the value with the SALT
            String tmp = SALT + realItemBackendIdentifier;
            //Get and configure message digester
            //We use SHA1 here for the following reason even if SHA1 have now potential collision:
            //1. We do not store sensitive information, just technical ID
            //2. We want that the ID stay short but not guessable
            //3. We want that a maximum of backend storage support the algorithm used in order to compute it in selection query/request
            //If your backend storage supports SHA256 so use it instead of SHA1
            MessageDigest digester = MessageDigest.getInstance("sha1");
            //Compute the hash
            byte[] hash = digester.digest(tmp.getBytes("utf-8"));
            //Encode is in HEX
            frontEndId = DatatypeConverter.printHexBinary(hash);
        }
        return frontEndId;
    }
}
```

This is the example of services using the front identifier:

``` java
/**
 * Service to list all available movies
 *
 * @return The collection of movies ID and name as JSON response
 */
@RequestMapping(value = "/movies", method = GET, produces = {MediaType.APPLICATION_JSON_VALUE})
public Map<String, String> listAllMovies() {
    Map<String, String> result = new HashMap<>();

    try {
        this.movies.forEach(m -> {
            try {
                //Compute the front end ID for the current element
                String frontEndId = IDORUtil.computeFrontEndIdentifier(m.getBackendIdentifier());
                //Add the computed ID and the associated item name to the result map
                result.put(frontEndId, m.getName());
            } catch (Exception e) {
                LOGGER.error("Error during ID generation for real ID {}: {}", m.getBackendIdentifier(),
                             e.getMessage());
            }
        });
    } catch (Exception e) {
        //Ensure that in case of error no item is returned
        result.clear();
        LOGGER.error("Error during processing", e);
    }

    return result;
}

/**
 * Service to obtain the information on a specific movie
 *
 * @param id Movie identifier from a front end point of view
 * @return The movie object as JSON response
 */
@RequestMapping(value = "/movies/{id}", method = GET, produces = {MediaType.APPLICATION_JSON_VALUE})
public Movie obtainMovieName(@PathVariable("id") String id) {

    //Search for the wanted movie information using Front End Identifier
    Optional<Movie> movie = this.movies.stream().filter(m -> {
        boolean match;
        try {
            //Compute the front end ID for the current element
            String frontEndId = IDORUtil.computeFrontEndIdentifier(m.getBackendIdentifier());
            //Check if the computed ID match the one provided
            match = frontEndId.equals(id);
        } catch (Exception e) {
            //Ensure that in case of error no item is returned
            match = false;
            LOGGER.error("Error during processing", e);
        }
        return match;
    }).findFirst();

    //We have marked the Backend Identifier class field as excluded
    //from the serialization
    //So we can send the object to front end through the serializer
    return movie.get();
}
```

This is the value object used:

``` java
public class Movie {
    /**
     * We indicate to serializer that this field must never be serialized
     *
     * @see "https://fasterxml.github.io/jackson-annotations/javadoc/2.5/com/fasterxml/
     *       jackson/annotation/JsonIgnore.html"
     */
    @JsonIgnore
    private String backendIdentifier;
...
}
```

## Sources of the prototype

[GitHub repository](https://github.com/righettod/poc-idor).
