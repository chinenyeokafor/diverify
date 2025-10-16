import json
import base64
import logging
import jwt
import requests
from diverify.daemon.sigstore_signer import DiVerifyDaemonSigner
from diverify.openpubkey.opk_scopes import OPKScopeService
from diverify.util.config import Config
from diverify.util import perf_utils
from diverify.util.common import Hashed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from diverify.openpubkey.verifier import verify_pktoken
from diverify.sigstore.verifier import verify_quote_and_signature

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

config = Config('config/stack_config.conf')
DiVerify_Daemon_URL = config.get_diverify_url()

usecase = "OpenPubkey"
TEST_IDENTITY = "user@opk_diverify.test"
TEST_ISSUER = "https://accounts.opk_diverify.test"
PAYLOAD = b"data"
LEVEL = 1

def daemon_sign_artifact_openpubkey(payload, level, mode):
    """Sign artifact using OpenPubkey via DiVerify daemon."""
    response = requests.post(
        f"{DiVerify_Daemon_URL}/daemon/sign",
        json={
            "payload": payload, 
            "level": level, 
            "mode": mode,
            "use_openpubkey": True
        }
    )
    if not response.ok:
        raise RuntimeError(f"Daemon failed to sign: {response.text}")
    return response.json()

def verify_openpubkey_signature(signature_material, payload):    
    diverify_proof = signature_material.get("diverify_proof", {})
    quote = diverify_proof.get("quote")
    mode = diverify_proof.get("mode")
    pk_token = diverify_proof.get("identity", {}).get("oidc", {}).get("pk_token")
    if mode == "a":
        verify_pktoken(pk_token) 
        # step 4: verify that the signature was signed by the public key in the diverify proof.
        parts = pk_token.split(".")
        cic_token = f"{parts[3]}.{parts[0]}.{parts[4]}"
        try:
            from cryptography.hazmat.primitives import serialization
            pem_str = jwt.get_unverified_header(cic_token).get("upk").get("pem")
            signing_key = serialization.load_pem_public_key(
                pem_str.encode("utf-8")
            )
            signing_key.verify(
                signature_material["artifact_signature"],
                signature_material["hashed_input"].digest,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            raise InvalidSignature("Signature is invalid for input")
        logger.debug("Successfully verified signature...")
    else:
        if not quote:
            raise ValueError("Missing TEE quote in Mode C")
        verify_pktoken(pk_token) 
        # Verify quote, report data, diverify_proof, and artifact signature
        verify_quote_and_signature(signature_material, payload, TEST_IDENTITY, TEST_ISSUER, policy)

def run_mode_a(policy=None):
    """Test Mode A with OpenPubkey."""
    logger.info("Testing OpenPubkey Mode A")

    # step 1: generate cic claims and nonce


    # step 2:retrieve required scopes
    with open("config.json", 'r') as file:
        config = json.load(file)
    req_scopes = config["levels"].get(str(LEVEL), {}).get("identity", {})
    opk_service = OPKScopeService()
    scopes = opk_service.get_opk_scopes(req_scopes)
    token = opk_service.id_token

    # step 3: assembly diverify proof
    diverify_proof = {"mode": "a", "level": LEVEL, "identity": scopes}

    # sign artifact
    signer = DiVerifyDaemonSigner(opk_service.signer_key)
    hashed_input, artifact_signature = signer.sign_artifact(PAYLOAD)
    signature_material = {
    "hashed_input": hashed_input,
    "artifact_signature": artifact_signature,
    "diverify_proof": diverify_proof
    }

    verify_openpubkey_signature(signature_material, PAYLOAD)
    logger.info("Mode A OpenPubkey test successful")

def run_mode_c(policy=None):
    """Test Mode C with OpenPubkey and TEE attestation."""
    logger.info("Testing OpenPubkey Mode C with TEE attestation")
    
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact_openpubkey(payload, LEVEL, mode)
    
    signature_material = sign(payload, mode="c")
    signature_material = json.loads(base64.b64decode(signature_material).decode('utf-8'))
    signature_material = {
        "hashed_input": Hashed.from_dict(signature_material["hashed_input"]),
        "artifact_signature": base64.b64decode(signature_material["artifact_signature"]),
        "diverify_proof": signature_material["diverify_proof"],
    }
    
    verify_openpubkey_signature(signature_material, PAYLOAD)
    logger.info("Mode C OpenPubkey test successful")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the script in different modes: a or c.")
    parser.add_argument("--mode", choices=["a", "c"], required=True, help="Mode to run: a or c")
    parser.add_argument("--level", type=int, default=1, help="Optional level parameter (default: 1)")
    args = parser.parse_args()

    LEVEL = args.level
    perf_utils.set_test_mode(args.mode, args.level)
    if args.mode == "a":
        policy = f"{usecase.lower()}/policy_a{args.level}.json"
        run_mode_a(policy)
    elif args.mode == "c":
        policy = f"{usecase.lower()}/policy_{args.level}.json"
        run_mode_c(policy)