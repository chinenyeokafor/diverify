import os
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

def generate_key_pair():
    return ec.generate_private_key(ec.SECP256R1())

class MockOpenIDProvider:
    def __init__(self, issuer="https://accounts.opk_diverify.test"):
        self.issuer = issuer
        self.key_file = "/home/diverify/src/diverify/openpubkey/mock_provider_key.pem"
        self.pub_key_file = "src/diverify/openpubkey/mock_provider_public_key.pem"
        if os.path.exists(self.key_file):
            self._load_key()
        else:
            self.op_provider_key = generate_key_pair()
            self._save_key()
    
    def _save_key(self):
        """Save private and public keys to files"""
        with open(self.key_file, 'wb') as f:
            f.write(self.op_provider_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        with open(self.pub_key_file, 'wb') as f:
            f.write(self.op_provider_key.public_key().public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))
    
    def _load_key(self):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        with open(self.key_file, 'rb') as f:
            self.op_provider_key = load_pem_private_key(f.read(), password=None)
    
    def get_public_key_pem(self):
        with open(self.pub_key_file, 'r') as f:
            return f.read()
    
    def create_id_token(self, nonce, audience="opk-diverify"):
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "sub": "user@opk_diverify.test",
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
        }
        return jwt.encode(payload, self.op_provider_key, algorithm="ES256")