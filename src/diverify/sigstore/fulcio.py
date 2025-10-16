import base64
import json
from dataclasses import dataclass
from typing import Dict, List
from urllib import parse
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    BasicConstraints, CertificateSigningRequestBuilder, Name, NameAttribute,
    ObjectIdentifier, UnrecognizedExtension, load_pem_x509_certificate
)
from cryptography.x509.oid import NameOID
from diverify.util import perf_utils
from diverify.sigstore import DEFAULT_FULCIO_URL

SIGNING_CERT_ENDPOINT = "/api/v2/signingCert"


@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    """Response from Fulcio certificate signing request."""
    cert: object
    chain: List[object]


class FulcioClient:
    """Client for interacting with Fulcio Certificate Authority."""
    
    # DiVerify proof extension OID
    DIVERIFY_PROOF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.23")
    
    def __init__(self, fulcio_url: str = DEFAULT_FULCIO_URL):
        self.fulcio_url = fulcio_url
    
    def create_csr(self, email_address: str, private_key, diverify_proof: Dict) -> bytes:
        """Create a Certificate Signing Request with DiVerify proof extension.
        
        Args:
            email_address: Subject email address
            private_key: Private key to sign the CSR
            diverify_proof: DiVerify attestation proof to embed
            
        Returns:
            DER-encoded CSR bytes
        """
        diverify_proof_bytes = json.dumps(diverify_proof).encode()
        
        csr_builder = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.EMAIL_ADDRESS, email_address)]))
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                UnrecognizedExtension(self.DIVERIFY_PROOF_OID, diverify_proof_bytes),
                critical=False
            )
        )
        
        return csr_builder.sign(private_key, hashes.SHA256())
    
    @perf_utils.measure_latency
    def get_certificate(self, csr_der: bytes, identity_token: str) -> FulcioCertificateSigningResponse:
        """Request a certificate from Fulcio.
        
        Args:
            csr_der: DER-encoded Certificate Signing Request
            identity_token: OIDC identity token
            
        Returns:
            Certificate and chain from Fulcio
        """
        fulcio_url = parse.urljoin(self.fulcio_url, SIGNING_CERT_ENDPOINT)
        
        # Convert CSR to PEM and base64 encode
        csr_pem = csr_der.public_bytes(serialization.Encoding.PEM)
        csr_b64 = base64.b64encode(csr_pem).decode()
        
        certificate_request = json.dumps({
            "certificateSigningRequest": csr_b64
        })
        
        headers = {
            "Authorization": f"Bearer {identity_token}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        
        resp = requests.post(fulcio_url, certificate_request, headers=headers)
        if not resp.ok:
            try:
                msg = resp.json().get("message", resp.text)
            except ValueError:
                msg = resp.text
            raise Exception(f"Fulcio request failed: {msg}")
        
        response_data = resp.json()
        certs = response_data.get("signedCertificateEmbeddedSct", {}).get("chain", {}).get("certificates", [])
        
        if len(certs) < 2:
            raise Exception("Certificate chain is too short")
        
        return FulcioCertificateSigningResponse(
            cert=load_pem_x509_certificate(certs[0].encode()),
            chain=[load_pem_x509_certificate(c.encode()) for c in certs[1:]]
        )
