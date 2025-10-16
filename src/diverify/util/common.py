
import base64
import json
from cryptography.x509 import load_pem_x509_certificate

def process_daemon_signature_material(raw_material: str, mode: str) -> dict:
    """Process signature material from daemon - eliminates duplication in test files"""
    decoded = json.loads(base64.b64decode(raw_material).decode('utf-8'))
    
    base_material = {
        "hashed_input": Hashed.from_dict(decoded["hashed_input"]),
        "artifact_signature": base64.b64decode(decoded["artifact_signature"]),
    }
    
    if mode == "b":
        base_material["signing_cert"] = load_pem_x509_certificate(
            decoded["signing_cert"].encode('utf-8')
        )
    elif mode == "c":
        base_material["diverify_proof"] = decoded["diverify_proof"]
    
    return base_material

class Hashed:
    def __init__(self, algorithm: str, digest: bytes):
        self.algorithm = algorithm
        self.digest = digest
    
    @classmethod
    def from_dict(cls, data):
        algorithm = data["algorithm"]
        digest = base64.b64decode(data["digest"])
        return cls(algorithm, digest)
