import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from diverify.openpubkey.opk_scopes import MockOpenIDProvider, OPKScopeService

class OpenPubKeyVerificationError(Exception): pass

def verify_OP_signature(id_token: str) -> bool:
    try:
        pk = load_pem_public_key(MockOpenIDProvider().get_public_key_pem().encode())
        jwt.decode(id_token, pk, algorithms=['ES256'], audience="opk-diverify")
        return True
    except (jwt.InvalidSignatureError, jwt.InvalidTokenError) as e:
        raise OpenPubKeyVerificationError(f"OP signature verification failed: {e}")

def validate_cic_commitment(cic_token: str, nonce_from_token: str) -> bool:
    """Validate that the CIC commits to the nonce in the ID token."""
    try:
        cic_header = jwt.get_unverified_header(cic_token)
        if nonce_from_token != OPKScopeService().generate_nonce_from_cic(cic_header):
            raise OpenPubKeyVerificationError("Commitment verification failed: nonce mismatch")
        signer_pk = cic_header.get('upk', {}).get('pem')
        if not signer_pk: raise OpenPubKeyVerificationError("Missing signer public key in CIC")
        jwt.decode(cic_token, load_pem_public_key(signer_pk.encode()), algorithms=['ES256'], audience="opk-diverify")
        return True
    except (jwt.InvalidSignatureError, jwt.InvalidTokenError) as e:
        raise OpenPubKeyVerificationError(f"CIC validation failed: {e}")

def verify_pktoken(pk_token: str) -> bool:
    try:
        # Parse PK token format: payload.header.signature.cic_header.cic_signature
        parts = pk_token.split('.')
        if len(parts) != 5: raise OpenPubKeyVerificationError("Invalid PK token format")
        id_token = f"{parts[1]}.{parts[0]}.{parts[2]}" # header.payload.signature
        cic_token = f"{parts[3]}.{parts[0]}.{parts[4]}" # cic_header.payload.cic_signature
        verify_OP_signature(id_token)
        nonce = jwt.decode(id_token, options={"verify_signature": False}).get('nonce')
        validate_cic_commitment(cic_token, nonce)
        return True
    except OpenPubKeyVerificationError: raise
    except Exception as e: raise OpenPubKeyVerificationError(f"Unexpected verification error: {e}")
