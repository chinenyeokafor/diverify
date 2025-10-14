from diverify.openpubkey_bridge import OpenPubkeyBridge

def sign_with_openpubkey(payload: bytes, token, diverify_proof: Dict, trust_level, mode=None) -> dict[str, Any]:
    """ Enhanced to support OpenPubkey integration """
    perf_utils.set_test_mode(mode, trust_level)

   
    nonce = hashlib.sha256(json.dumps(diverify_proof).encode()).hexdigest()
    
    # Prepare extra claims for OpenPubkey
    extra_claims = {
        "diverify_mode": mode,
        "trust_level": str(trust_level),
        "sub": "diverify-daemon",
        "email": "daemon@diverify.local"
    }
    
    # Get PK Token from OpenPubkey
    bridge = OpenPubkeyBridge()
    result = bridge.get_pk_token(
        nonce=nonce,
        extra_claims=extra_claims,
        message=payload.decode('utf-8') if isinstance(payload, bytes) else str(payload)
    )
    
    pk_token = result["pk_token"]
    signature = result.get("signature", "")
    
    if mode == "c":
        # Mode C: Include PK Token in DiVerify proof with TEE attestation
        diverify_proof["oidc"] = pk_token
        
        # Get TEE attestation
        quote = get_remote_attestation(diverify_proof)
        diverify_proof["quote"] = base64.b64encode(quote).decode()
        
        return {
            "pk_token": pk_token,
            "signature": signature,
            "diverify_proof": diverify_proof,
            "payload_hash": hashlib.sha256(payload).hexdigest()
        }
    else:
        # Mode A/B: Use PK Token as OIDC component
        return {
            "pk_token": pk_token,
            "signature": signature,
            "diverify_proof": diverify_proof
        }