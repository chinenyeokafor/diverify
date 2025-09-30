import platform
import socket
import hashlib
from diverify.scope_providers.base_verifier import ScopeProvider

class DeviceFingerprintScopeProvider(ScopeProvider):
    def verify(self) -> str:
        
        # Gather underlying platform’s identifying data
        system = platform.system()
        node = platform.node()
        release = platform.release()
        version = platform.version()
        machine = platform.machine()
        processor = platform.processor()
        hostname = socket.gethostname()
        cpu_architecture = platform.architecture()
        
        fingerprint = (
            f"{system} {node} {release} {version} {machine} {processor} {hostname} {cpu_architecture}"
        )
        
        fingerprint_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
        
        return fingerprint_hash 

if __name__ == "__main__":
    fingerprint_hash = DeviceFingerprintScopeProvider().verify()
    print(f"Device Fingerprint Hash: {fingerprint_hash}")
