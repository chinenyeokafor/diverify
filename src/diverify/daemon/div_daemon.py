from fastapi import FastAPI, HTTPException
import uvicorn
from typing import Dict
import uuid
from diverify.daemon.scopes import get_scopes
from diverify.daemon.sigstore_signer import DiVerifyDaemonSigner
from diverify.openpubkey.opk_scopes import OPKScopeService
import base64
import json
import os
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")

# using the absolute path so enclave can find it
if os.path.exists("/dev/sgx_enclave"):
    TRUST_CONFIG_FILE = "/home/diverify/config/trust_config.json"
else:
    TRUST_CONFIG_FILE = "config/trust_config.json"


app = FastAPI()
nonce_store: Dict[str, Dict[str, str]] = {}

def load_trust_config():
    try:
        with open(TRUST_CONFIG_FILE, 'r') as file:
            policy = json.load(file)
        return policy
    except FileNotFoundError:
        raise RuntimeError(f"Metadata file {TRUST_CONFIG_FILE} not found.")
    except json.JSONDecodeError:
        raise RuntimeError("Failed to decode metadata file.")

diverify_config = load_trust_config()


@app.post("/daemon/sign")
def sign_artifact(params: Dict):
    try:
        trust_level = params["level"]
        payload = params["payload"]
        mode = params["mode"]
        use_openpubkey = params.get("use_openpubkey", False)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing parameter: {str(e)}")

    req_scopes = get_auth_requirements(trust_level)["auth_requirements"]
    if use_openpubkey:
        print("Using OpenPubKey flow for signing artifact")
        # Step 1: Collect user scopes
        opk_service = OPKScopeService()
        scopes = opk_service.get_opk_scopes(req_scopes)
        token = opk_service.id_token
        # Step 2: Generate diverify proof
        diverify_proof = {"level": trust_level, "identity": scopes}
        breakpoint()
        # Step 3: Request signing certificate if mode is "c"
        if "attestation" in req_scopes or mode == "b" or mode == "c":
            payload = base64.b64decode(payload)
            signer = DiVerifyDaemonSigner(opk_service.signer_key)
            signature_material = signer.sign(payload, token, diverify_proof, trust_level, mode=mode)

            return signature_material
    else:
        # Step 1: Collect user scopes
        scopes, token = get_scopes(req_scopes)
        # Step 2: Generate diverify proof
        diverify_proof = {"level": trust_level, "identity": scopes}
        # Step 3: Request signing certificate if mode is "c"
        if "attestation" in req_scopes or mode == "b" or mode == "c":
                payload = base64.b64decode(payload)
                signer = DiVerifyDaemonSigner(opk_service.signer_key)
                signature_material = signer.sign(payload, token, diverify_proof, trust_level, mode=mode)

                return signature_material

@app.get("/auth/requirements")
def get_auth_requirements(level: int):
    """Generate nonces for required auth types for the given level."""
    try:
        level_str = str(level)
        required_scopes = diverify_config["levels"].get(level_str, {}).get("identity", {})
        if not required_scopes:
            raise HTTPException(status_code=404, detail="Level not found")
        
        nonces, request_state = request_session(required_scopes)
        
        return {"auth_requirements": required_scopes, "nonces": nonces, "request_state": request_state}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def request_session(required_scopes):
    """Generate unique request state and nonces for each identity type"""
    request_state = str(uuid.uuid4())
    nonces = {identity: str(uuid.uuid4()) for identity in required_scopes}

    nonce_store[request_state] = nonces
    return nonces, request_state

def verify_session(request_state, scopes):
    """validate nonces for each identity type by extracting from the scopes"""
    stored_nonces = nonce_store.get(request_state)

    if not stored_nonces:
        raise HTTPException(status_code=400, detail="Invalid request state")
    
    for identity, stored_nonce in stored_nonces.items():
        client_nonce = scopes.get(f"{identity}_nonce")
        if not client_nonce or client_nonce != stored_nonce:
            raise HTTPException(status_code=400, detail=f"Invalid or expired nonce for {identity}")
    del nonce_store[request_state]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")