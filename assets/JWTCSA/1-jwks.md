# JWKS

## Generating a JWKS Key

### Python:jwcrypto

<!-- --8<-- [start:jwcrypto] -->

```python
import uuid
from jwcrypto import jwk, jwt

unique_kid = uuid.uuid4()

this_nodes_jwk = jwk.JWK.generate(kty="RSA", size=4096, kid=str(unique_kid))

public_key = this_nodes_jwk.export_public()

# Publish to Datastore in Multinode system

this_token = jwt.JWT(header={"alg": "RS256"},
                     claims={"name": "example_system"}
                     )

this_token.make_signed_token(this_nodes_jwk)

# For validation on jwt.io as an example
encoded_token = this_token.serialize()
public_key = this_node_jwk.export_public()
private_key = this_node_jwk.export_private()
```

<!-- --8<-- [end:jwcrypto] -->
