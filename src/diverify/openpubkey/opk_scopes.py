import jwt
import hashlib
import base64
import json
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from diverify.scope_providers.scope_provider_loader import load_scope_provider
from diverify.openpubkey.op_provider import MockOpenIDProvider

DEVICE_FINGERPRINT = load_scope_provider("device_fingerprint").verify()

def generate_key_pair():
    return ec.generate_private_key(ec.SECP256R1())

class OPKScopeService:
    def __init__(self):
        self.device_fingerprint = load_scope_provider("device_fingerprint").verify()
        self.op_provider = MockOpenIDProvider()
        
    def generate_cic(self, public_key, claims=None):
        claims = claims or {}
        cic = {
            "typ": "CIC",
            "alg": "ES256",
            "upk": public_key,
            "rz": secrets.token_hex(32)
        }
        cic.update(claims)
        return cic

    def generate_nonce_from_cic(self, cic):
        cic_json = json.dumps(cic, separators=(',', ':'), sort_keys=True)
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(base64.b64encode(cic_json.encode()))
        return base64.urlsafe_b64encode(digest.finalize()).decode().rstrip('=')

    def create_pk_token(self, claims=None, audience="opk-diverify"):
        claims = claims or {}
        claims["aud"] = audience
        self.signer_key = generate_key_pair()
        pub = {
            "alg": "ES256",
            "pem": self.signer_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        }
        cic = self.generate_cic(pub, claims)
        nonce = self.generate_nonce_from_cic(cic)
        id_token = self.op_provider.create_id_token(nonce)
        self.id_token = id_token
        payload = jwt.decode(id_token, options={"verify_signature": False})
        cic_token = jwt.encode(payload, self.signer_key, algorithm="ES256", headers=cic)
        # PK token format: payload.header.signature.cic_header.cic_signature  
        pk_token = f"{id_token.split('.')[1]}.{id_token.split('.')[0]}.{id_token.split('.')[2]}.{cic_token.split('.')[0]}.{cic_token.split('.')[2]}"
        return pk_token

    def get_opk_scopes(self, req_scopes):
        scopes = {}
        for auth in req_scopes:
            if auth == "oidc":
                try:
                    pk_token = self.create_pk_token({}, "opk-diverify")
                    self.pk_token = pk_token
                    parts = pk_token.split('.')
                    claims = jwt.decode(f"{parts[1]}.{parts[0]}.{parts[2]}", options={"verify_signature": False})
                    scopes[auth] = {
                        "sub": claims.get('sub'),
                        "iss": claims.get('iss'),
                        "token_hash": hashlib.sha256(pk_token.encode()).hexdigest(),
                        "pk_token": pk_token
                    }
                except Exception as e:
                    raise e
            elif auth == "device_fingerprint":
                scopes[auth] = self.device_fingerprint
            elif auth == "security_key":
                scopes[auth] = load_scope_provider(auth).verify()
            elif auth == "attestation":
                scopes[auth] = True
            else:
                raise ValueError(f"Unknown authentication type: {auth}")
        self.scopes = scopes
        return scopes

if __name__ == "__main__":
    req_scopes = {'oidc': True, 'device_fingerprint': True}
    svc = OPKScopeService()
    print(svc.get_opk_scopes(req_scopes))