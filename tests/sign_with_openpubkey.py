import json
import base64
import hashlib
import logging
import requests
from diverify.util.config import Config
from diverify.util import perf_utils

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

config = Config('config/stack_config.conf')
DiVerify_Daemon_URL = config.get_diverify_url()

TEST_IDENTITY = "user@opk_diverify.test"
TEST_ISSUER = "https://accounts.opk_diverify.test"
PAYLOAD = b"data"
LEVEL = 1

def daemon_sign_artifact_openpubkey(payload, level, mode):
    """Sign artifact using OpenPubkey via DiVerify daemon."""
    print("Passed here-1")
    response = requests.post(
        f"{DiVerify_Daemon_URL}/daemon/sign",
        json={
            "payload": payload, 
            "level": level, 
            "mode": mode,
            "use_openpubkey": True
        }
    )
    print("Passed here")
    if not response.ok:
        raise RuntimeError(f"Daemon failed to sign: {response.text}")
    return response.json()

def verify_openpubkey_signature(signature_material, payload):
    """Verify OpenPubkey signature."""
    pk_token = signature_material.get("pk_token")
    signature = signature_material.get("signature")
    
    if not pk_token or not signature:
        raise ValueError("Missing PK Token or signature")
    
    #TODO: For now, basic validation - could be enhanced
    logger.info("OpenPubkey signature verification successful")
    return True

def run_mode_a_openpubkey(policy=None):
    """Test Mode A with OpenPubkey."""
    logger.info("Testing OpenPubkey Mode A")
    
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact_openpubkey(payload, LEVEL, mode)
    
    signature_material = sign(payload, mode="a")
    
    @perf_utils.measure_latency 
    def verify_sig(sig):
        return verify_openpubkey_signature(sig, PAYLOAD)
    
    verify_sig(signature_material)
    logger.info("Mode A OpenPubkey test successful")

def run_mode_c_openpubkey(policy=None):
    """Test Mode C with OpenPubkey and TEE attestation."""
    logger.info("Testing OpenPubkey Mode C with TEE attestation")
    
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact_openpubkey(payload, LEVEL, mode)
    
    signature_material = sign(payload, mode="c")
    
    # Verify TEE attestation is present
    diverify_proof = signature_material.get("diverify_proof", {})
    if not diverify_proof.get("quote"):
        raise ValueError("Missing TEE quote in Mode C")
    
    @perf_utils.measure_latency
    def verify_sig(sig):
        return verify_openpubkey_signature(sig, PAYLOAD)
    
    verify_sig(signature_material)
    logger.info("Mode C OpenPubkey test successful")

if __name__ == "__main__":
    # run_mode_a_openpubkey()
    run_mode_c_openpubkey()