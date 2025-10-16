import json
import base64
import logging
import jwt
import requests
from diverify.daemon.signer import DiVerifyDaemonSigner
from diverify.openpubkey.opk_scopes import OPKScopeService
from diverify.util.config import Config
from diverify.util import perf_utils
from cryptography.hazmat.primitives import serialization
from diverify.openpubkey.verifier import verify_pktoken
from diverify.sigstore.verifier import verify_quote_and_signature
from diverify.verifier import validate_policy, validate_signature
from diverify.util.common import process_daemon_signature_material

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

def verify_openpubkey_signature(signature_material, payload, policy):    
    diverify_proof = signature_material.get("diverify_proof", {})
    quote = diverify_proof.get("quote")
    mode = diverify_proof.get("mode")
    pk_token = diverify_proof.get("identity", {}).get("oidc", {}).get("pk_token")
    if mode == "a":        
        parts = pk_token.split(".")
        cic_token = f"{parts[3]}.{parts[0]}.{parts[4]}"
        verify_pktoken(pk_token) 
        validate_policy(policy, diverify_proof)
        pem_str = jwt.get_unverified_header(cic_token).get("upk").get("pem")
        signing_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
        validate_signature(signing_key, signature_material["hashed_input"], signature_material["artifact_signature"])
    else:
        if not quote:
            raise ValueError("Missing TEE quote in Mode C")
        verify_pktoken(pk_token) 
        # Verify quote, report data, diverify_proof, and artifact signature
        verify_quote_and_signature(signature_material, payload, TEST_IDENTITY, TEST_ISSUER, policy)

def run_mode_a(policy=None):
    """Test Mode A with OpenPubkey."""
    logger.info("Testing OpenPubkey Mode A")

    # step 1:retrieve required scopes
    with open("config.json", 'r') as file:
        config = json.load(file)
    req_scopes = config["levels"].get(str(LEVEL), {}).get("identity", {})
    opk_service = OPKScopeService()
    scopes = opk_service.get_opk_scopes(req_scopes)

    # step 2: assembly diverify proof
    diverify_proof = {"mode": "a", "level": LEVEL, "identity": scopes, "public_key": opk_service.signer_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')}

    # step 3: sign artifact
    signer = DiVerifyDaemonSigner(opk_service.signer_key)
    hashed_input, artifact_signature = signer.sign_artifact(PAYLOAD)
    signature_material = {
    "hashed_input": hashed_input,
    "artifact_signature": artifact_signature,
    "diverify_proof": diverify_proof
    }
    # step 4: verify signature against policy
    verify_openpubkey_signature(signature_material, PAYLOAD, policy)
    logger.info("Mode A OpenPubkey test successful")

def run_mode_c(policy, mode="c"):
    """Test Mode C with OpenPubkey and TEE attestation."""
    logger.info("Testing OpenPubkey Mode C with TEE attestation")
    
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    # step 1: forward to the Daemon to retrive scope, get attestation, bundle diverify proof, and sign
    signature_material = daemon_sign_artifact_openpubkey(payload, LEVEL, mode)
    signature_material = process_daemon_signature_material(signature_material, mode)
    # step 2: verify signature against policy
    verify_openpubkey_signature(signature_material, PAYLOAD, policy)
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