
import base64
class Hashed:
    def __init__(self, algorithm: str, digest: bytes):
        self.algorithm = algorithm
        self.digest = digest
    
    @classmethod
    def from_dict(cls, data):
        algorithm = data["algorithm"]
        digest = base64.b64decode(data["digest"])
        return cls(algorithm, digest)
    