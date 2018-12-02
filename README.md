# go-jwk-pem
Simple CLI to retrieve PEM from JWK keys URL ( which can be autodiscovered )

# Examples
With simple command to be executed ( as shown below ) we receive PEM with `KID` information as well.

## Retrieve PEM
```
go-jwk-pem pubkey --id https://some.url.com/oath/v1/keys
```

## Retrieve PEM and create JSON friendly string
The following command will produce friendly single line result ready to be used in other places ;) 
```
go-jwk-pem pubkey --id https://some.url.com/oath/v1/keys | /usr/bin/env ruby -e 'p ARGF.read'
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