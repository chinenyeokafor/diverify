import jwt
import json
import base64
import hashlib
import logging
import requests
from dataclasses import dataclass
from typing import Tuple, Any, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    CertificateSigningRequestBuilder, Name, NameAttribute, BasicConstraints,
    ObjectIdentifier, UnrecognizedExtension)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from diverify.daemon.quote import get_quote, get_user_data
from diverify.util import perf_utils
from diverify.util.config import Config


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# provide enclave the absolute path
config = Config('/home/diverify/config/stack_config.conf')
DEFAULT_FULCIO_URL = config.get_fulcio_service_url()

SIGNING_CERT_ENDPOINT = "/api/v2/signingCert"
TRUST_BUNDLE_ENDPOINT = "/api/v2/trustBundle"

def generate_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an EC key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

# @perf_utils.measure_latency
def sign(payload: bytes, token, diverify_proof: Dict, trust_level, mode=None, iteration=0) -> dict[str, Any]:
    """ We only sign in daemon if mode b or c is selected 
    We want to do the following:
    1. Generate a key pair  
    2a. If it is mode b, we need to embed the quote in the signing certificate.
    2b. If it is mode c, we don't need a certificate. We just embed the signing key 
        in DiVerify proof that is embedded in the quote
    """
    private_key = generate_key_pair()
    
    _decoded_token = jwt.decode(token, options={"verify_signature": False})
    try:
        email_address = _decoded_token['email']
    except:
        email_address = _decoded_token['sub']
    
    @perf_utils.measure_latency
    def set_and_get_quote(user_report):
        user_data = get_user_data(user_report)
        quote = get_quote(user_data)
        return quote
    
    def get_remote_attestation(diverify_proof):
        dvp_hash = hashlib.sha256(json.dumps(diverify_proof).encode()).digest()
        dvp_sig = private_key.sign(dvp_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        quote = set_and_get_quote(dvp_sig)
        return quote

    
    if mode == "c":
        # Add signing key to diverify proof
        diverify_proof["public_key"] = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        quote = get_remote_attestation(diverify_proof)
        diverify_proof["quote"] = base64.b64encode(quote).decode()
        # Sign the payload
        hashed_input, artifact_signature = sign_artifact(private_key, payload)

        signature_material = {
        "hashed_input": hashed_input.to_dict(),
        "artifact_signature": base64.b64encode(artifact_signature).decode('utf-8'),
        "diverify_proof": diverify_proof
        }
    else:
        # We assume identity token is valid and send CSR to Fulcio
        quote = get_remote_attestation(diverify_proof)
        diverify_proof["quote"] = base64.b64encode(quote).decode()
        csr = create_csr(email_address, json.dumps(diverify_proof).encode()).sign(private_key, hashes.SHA256())
        certificate_response = get_fulcio_cert(csr, token)

        # Sign the payload
        hashed_input, artifact_signature = sign_artifact(private_key, payload)

        signature_material = {
        "hashed_input": hashed_input.to_dict(),
        "artifact_signature": base64.b64encode(artifact_signature).decode('utf-8'),
        "signing_cert": certificate_response.cert.public_bytes(
            encoding=serialization.Encoding.PEM  
        ).decode('utf-8')
        }
        cert_bytes = certificate_response.cert.public_bytes(
                            encoding=serialization.Encoding.PEM
                        )
        print(f"mode {mode}, level {trust_level} Certificate size: {len(cert_bytes)} bytes")

    json_bytes = json.dumps(diverify_proof).encode('utf-8')
    print(f"mode {mode}, level {trust_level} DiVerify proof size: {len(json_bytes)}")
    signature_material_bytes = json.dumps(signature_material).encode('utf-8')
    encoded_signature_material = base64.b64encode(signature_material_bytes).decode('utf-8')

    return encoded_signature_material

def create_csr(email_address: str, diverify_proof: bytes) -> CertificateSigningRequestBuilder:
    DIVERIFY_PROOF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.23")

    csr_builder = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.EMAIL_ADDRESS, email_address)]))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            UnrecognizedExtension(DIVERIFY_PROOF_OID, diverify_proof),
            critical=False
            )
        )
    return csr_builder

@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    from typing import List
    cert: object
    chain: List[object]

@perf_utils.measure_latency
def get_fulcio_cert( csr, identity):
    from cryptography.x509 import load_pem_x509_certificate
    import os
    fulcio_url = (DEFAULT_FULCIO_URL.replace('//'+DEFAULT_FULCIO_URL.split('//')[1].split(':')[0], '//sigstore-fulcio', 1) 
             if os.path.exists('/.dockerenv') else DEFAULT_FULCIO_URL) + SIGNING_CERT_ENDPOINT
    logger.debug(f"Fulcio URL: {fulcio_url}")

    certificate_request = json.dumps({"certificateSigningRequest": base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode()})
    headers = {
        "Authorization": f"Bearer {identity}",
        "Content-Type": "application/json",
        "Accept": "application/pem-certificate-chain",
    }
    resp = requests.post(fulcio_url, certificate_request, headers=headers)
    if not resp.ok:
        raise Exception(resp.json().get("message", "Fulcio request failed"))
    
    certs = resp.json().get("signedCertificateEmbeddedSct", {}).get("chain", {}).get("certificates", [])
    if len(certs) < 2:
        raise Exception("Certificate chain is too short")
    
    return FulcioCertificateSigningResponse(
        load_pem_x509_certificate(certs[0].encode()),
        [load_pem_x509_certificate(c.encode()) for c in certs[1:]]
    )    

class Hashed:
    def __init__(self, algorithm: str, digest: bytes):
        # To conform to Rekor submission code expected type, we use 1 ->> sha256 algorithm mapping
        self.algorithm = 1 if algorithm == "sha256" else 0
        self.digest = digest

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "digest": base64.b64encode(self.digest).decode('utf-8')
        }
    
def sign_artifact(private_key, input_: bytes | Hashed) -> tuple[bytes, bytes]:
    """Sign an artifact and return the hashed input and signature."""
    hashed_input = input_ if isinstance(input_, Hashed) else Hashed("sha256", hashlib.sha256(input_).digest())
    return hashed_input, private_key.sign(hashed_input.digest, ec.ECDSA(Prehashed(hashes.SHA256())))
