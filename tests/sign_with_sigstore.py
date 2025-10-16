import jwt
import json
import hashlib
import logging
import requests
import base64
from diverify.util.config import Config
from securesystemslib.signer import SIGNER_FOR_URI_SCHEME, Signer
from diverify.sigstore.signer import SigstoredSigner 
from diverify.sigstore.rekor import submit_to_tlog
from diverify.sigstore.verifier import verify_signature, verify_quote_and_signature
from cryptography.x509 import load_pem_x509_certificate
from diverify.util import perf_utils
from diverify.scope_providers.scope_provider_loader import load_scope_provider
from diverify.util.common import Hashed
from diverify.util.common import process_daemon_signature_material

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

config = Config('config/stack_config.conf')
DiVerify_Daemon_URL = config.get_diverify_url()
usecase = "Sigstore"


TEST_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/"
    "workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)
TEST_ISSUER = "https://token.actions.githubusercontent.com"
PAYLOAD = b"data"


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
    with open("config.json", 'r') as file:
        config = json.load(file)
    import uuid
    nonce = str(uuid.uuid4())

    SIGNER_FOR_URI_SCHEME[SigstoredSigner.SCHEME] = SigstoredSigner
    uri, public_key=SigstoredSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=True, nonce=nonce)
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


def run_mode_b(policy, mode="b"):
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact(payload, LEVEL, mode)
    signature_material = sign(payload, mode)
    signature_material = process_daemon_signature_material(signature_material, mode)
    sig = submit_to_tlog(signature_material)

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        verify_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)
    
    # Successful verification
    verify_sig(sig, policy)

def run_mode_c(policy, mode="c"):
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact(payload, LEVEL, mode)
    signature_material = sign(payload, mode)
    signature_material = process_daemon_signature_material(signature_material, mode)


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
        policy = f"{usecase.lower()}/policy_a{args.level}.json"
        run_mode_a(policy)
    elif args.mode == "b":
        policy = f"{usecase.lower()}/policy_{args.level}.json"
        run_mode_b(policy)
    elif args.mode == "c":
        policy = f"{usecase.lower()}/policy_{args.level}.json"
        run_mode_c(policy)
