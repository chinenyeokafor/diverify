import jwt
import json
import base64
import hashlib
import logging
import requests
import configparser
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer
from diverify.sigstore import SigstoredSigner 
from diverify.rekor import submit_to_tlog
from diverify.verifier import verify_signature, verify_quote_and_signature
from cryptography.x509 import load_pem_x509_certificate
from diverify.util import perf_utils
from diverify.scope_providers.scope_provider_loader import load_scope_provider

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('stack_config.ini')
DiVerify_Daemon_URL = config['settings']['diverify-url']


TEST_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/"
    "workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)
TEST_ISSUER = "https://token.actions.githubusercontent.com"
PAYLOAD = b"data"

class Hashed:
    def __init__(self, algorithm: str, digest: bytes):
        self.algorithm = algorithm
        self.digest = digest
    
    @classmethod
    def from_dict(cls, data):
        algorithm = data["algorithm"]
        digest = base64.b64decode(data["digest"])
        return cls(algorithm, digest)
    
def daemon_sign_artifact(payload, level, mode):
    response = requests.post(
        f"{DiVerify_Daemon_URL}/daemon/sign",
        json={"payload": payload, "level": level, "mode": mode}
    )
    if not response.ok:
        raise RuntimeError(f"Daemon failed to sign payload: {response.text}")
    return response.json()

def verify_scope(auth):
    return load_scope_provider(auth).verify()

def run_mode_a(policy=None):
    SIGNER_FOR_URI_SCHEME[SigstoredSigner.SCHEME] = SigstoredSigner

    uri, public_key=SigstoredSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=True)
    
    with open("config.json", 'r') as file:
        config = json.load(file)
    required_auth = config["levels"].get(str(LEVEL), {}).get("identity", {})
    signer, token =Signer.from_priv_key_uri(uri, public_key)

    @perf_utils.measure_latency
    def sign(required_auth):
        proofs = {}
        limit_scope_flag = False
        for auth in required_auth:
            if auth == "device_fingerprint":
                fingerprint = verify_scope(auth)
                proofs[auth] = fingerprint
                logger.debug(f"Device Fingerprint is: {fingerprint}")
            elif auth == "security_key":
                piv_attestation = verify_scope(auth)
                proofs[auth] = piv_attestation
            elif auth == "source_local_scope":
                limit_scope_flag = True
                proofs[auth] = True
            elif auth == "attestation":
                proofs[auth] = True

        claims = jwt.decode(token, options={"verify_signature": False})
        proofs["oidc"] = {
                "sub": "https://github.com/" + claims.get('job_workflow_ref'),
                "iss": claims.get('iss'),
                "token_hash": hashlib.sha256(token.encode()).hexdigest()
                }
        
        diverify_proof = {"level": LEVEL, "identity": proofs}
        return signer, signer.sign(PAYLOAD, diverify_proof)
    signer, signature_material = sign(required_auth)
    sig = submit_to_tlog(signature_material)
    

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        verify_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)

    # Successful verification
    verify_sig(sig, policy)


def run_mode_b(policy=None):
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact(payload, LEVEL, mode)
    signature_material = sign(payload, mode="b")
    signature_material = json.loads(base64.b64decode(signature_material).decode('utf-8'))
    signature_material = {
        "hashed_input": Hashed.from_dict(signature_material["hashed_input"]),
        "artifact_signature": base64.b64decode(signature_material["artifact_signature"]),
        "signing_cert": load_pem_x509_certificate(signature_material["signing_cert"].encode('utf-8')),
    }
    sig = submit_to_tlog(signature_material)

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        verify_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)
    
    # Successful verification
    verify_sig(sig, policy)

def run_mode_c(policy=None):
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact(payload, LEVEL, mode)
    signature_material = sign(payload, mode="c")
    signature_material = json.loads(base64.b64decode(signature_material).decode('utf-8'))
    signature_material = {
        "hashed_input": Hashed.from_dict(signature_material["hashed_input"]),
        "artifact_signature": base64.b64decode(signature_material["artifact_signature"]),
        "diverify_proof": signature_material["diverify_proof"],
    }

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        verify_quote_and_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)
    
    # Successful verification
    verify_sig(signature_material, policy)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the script in different modes: a, b, or c.")
    parser.add_argument("--mode", choices=["a", "b", "c"], required=True, help="Mode to run: a, b, or c")
    parser.add_argument("--level", type=int, default=1, help="Optional level parameter (default: 1)")
    args = parser.parse_args()

    LEVEL = args.level
    perf_utils.set_test_mode(args.mode, args.level)
    if args.mode == "a":
        policy = f"policy_a{args.level}.json"
        run_mode_a(policy)
    elif args.mode == "b":
        policy = f"policy_{args.level}.json"
        run_mode_b(policy)
    elif args.mode == "c":
        policy = f"policy_{args.level}.json"
        run_mode_c(policy)
