# go-jwk-pem
Simple CLI to retrieve PEM from JWK keys URL or from JWT itself ( JWKs are then autodiscovered )

# Examples

## Retrieve public key from JWT ( Okta )
This is quite nice options - allows the CLI to discover your JWT kid and to query your issuing provider ( Okta ) for jwks and to return you associated public key
```
> [SHELL]  RafPe $ go-jwk-pem from-token --token "eyJraWQiOiJYcFpicVE2TTh0MHhsMWZVNkM2TExoc0cxQjhEVG9jN2pDWlhfeVJuVm9FI.....<REMOVED-FOR-OBVIOUS-REASONS>......HE-A"
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsRZb8c/pEW4BCbzSs5r7
................................................................
8ad8e6hM8uVJGt0MBA0psiWrv5FpJYFqAXzInrYaZegnQzR3Wq9KGdaZsjSShsd3
-----END RSA PUBLIC KEY-----
```

## Retrieve pubic key from server
By providing URL with `keys` you can obtain certificate which you need for your tokens.
### Query for all keys
```
> [SHELL]  RafPe $ go-jwk-pem from-server --url https://some.url.com/oath/v1/keys
```
### Query for all keys with showing their `kid`
```
> [SHELL]  RafPe $ go-jwk-pem from-server --url https://some.url.com/oath/v1/keys --show-kid
```
### Query for specific `kid`
```
> [SHELL]  RafPe $ go-jwk-pem from-server --url https://some.url.com/oath/v1/keys --kid 123121jkdfhsdkf
```
### Output to single line ?
```
> [SHELL]  RafPe $ go-jwk-pem from-token --token | /usr/bin/env ruby -e 'p ARGF.read'
```

# JWK format
Tool have been build with support of the following format
```
{
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "DW55A7aX59z8891ZHdFnR9oXU0gMdMqaZt5emFen0V0",
            "kty": "RSA",
            "n": "unANczoCQf16tcmS1o-EeciLoyQkMQdhOeKb7mm9dWZunA-EIbEbqLlEEfdD1kZDFh3aDzT4OYdHyHW_x8IaRhHCHFHKPUV4KLOX1GqOem0umJqwm77v0uKM9B--Hd4lkLwb70aPVeFubtmocx70AiaemoqOzv_lkNxJDuGgpt_aWucxyvtazSeCgEgIHWGGer7TmDPNqSqMHOVCj0mfTYDg0hAFKRB93aAQ",
            "use": "sig"
        }
    ]
}
```

# Why this tool ?
Simple - for purposes of setting up related automations and being lazy to retrieve this info using different frameworks.