import jwt
import hashlib
import requests
import time, json
from base64 import b64decode
from datetime import datetime
from diverify.scope_providers.scope_provider_loader import load_scope_provider
from diverify.util import perf_utils

DEVICE_FINGERPRINT = load_scope_provider("device_fingerprint").verify()
PIV_ATTESTATION = load_scope_provider("security_key").verify()
ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "sigstore"

@perf_utils.measure_latency
def get_scopes(req_scopes):
    """Get the scopes for the requested authentication methods."""
    scopes = {}
    limit_scope_flag = False
    for auth in req_scopes:
        if auth == "oidc":
            token = get_identity_token()
            claims = jwt.decode(token, options={"verify_signature": False})
            scopes[auth] = {
                "sub": "https://github.com/" + claims.get('job_workflow_ref'),
                "iss": claims.get('iss'),
                "token_hash": hashlib.sha256(token.encode()).hexdigest()
                }
        
        elif auth == "device_fingerprint":
            scopes[auth] = DEVICE_FINGERPRINT
        elif auth == "security_key":
            piv_attestation = PIV_ATTESTATION or load_scope_provider(auth).verify()
            scopes[auth] = piv_attestation
        elif auth == "source_local_scope":
            limit_scope_flag = True
            scopes[auth] = True
        elif auth == "attestation":
            scopes[auth] = True #the mode handles this
        else:
            raise ValueError(f"Unknown authentication type: {auth}")
    return scopes, token

def get_identity_token() -> str:
    url = "https://raw.githubusercontent.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/current-token/oidc-token.txt"
    while True:
        token = requests.get(url).text.strip()
        p = token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)
        if datetime.now().timestamp() + 5 < json.loads(b64decode(p))["exp"]:
            return token
        time.sleep(5)

def validate_scopes(auth_result: dict) -> bool:
    # Client verifies only the validity of the oidc token. The rest are validated by the verifier
    for auth_type, value in auth_result.items():
        if auth_type == "oidc":
            try:
                claims = verify_github_oidc_token(value)
            except Exception as e:
                raise Exception(f"OIDC verification error: {e}")
            break
    return claims, True

def verify_github_oidc_token(token):
    try:
        jwks_uri = "https://token.actions.githubusercontent.com/.well-known/jwks"
        jwks_response = requests.get(jwks_uri)
        jwks_response.raise_for_status()
        jwks = jwks_response.json()
        
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        public_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                break
        
        if public_key is None:
            raise Exception("Public key not found for the given kid")
        
        decoded_token = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER
        )
        
        decoded_token["exp"] > time.time()
        
        return decoded_token
    
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None
    
if __name__ == "__main__":

    print(get_identity_token())