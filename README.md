# jwt-assertion
kong plugin to generate/verify jwt assertion token based on the config.


        {
            "config": {
                "action": "verify",
                "algorithm": "RS256",
                "assertion_header": "x-jws-signature",
                "clock_skew": 60, //in seconds
                "include": {
                    "delimiter": "|",
                    "hash_claim": "payload_hash",
                    "headers": [
                        "x-client-id",
                        "x-partner_id"
                    ],
                    "method": true,
                    "payload": true,
                    "uri": true
                },
                "jwks_uri": "http://host.docker.internal:8080/access-management/.well-known/jwks.json",
                "keyset": "nexus",
                "leeway": 60
            },
            "enabled": true,
            "name": "jwt-assertion",
            "protocols": [
                "http",
                "https"
            ]
        }
