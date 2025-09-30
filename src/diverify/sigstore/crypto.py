"""
DiVerify Cryptographic Operations

Handles key generation and artifact signing for DiVerify.
"""

from typing import Tuple, Union
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from securesystemslib.exceptions import UnsupportedLibraryError

IMPORT_ERROR = "sigstore library required for artifact signing"


class CryptoProvider:
    """Provides cryptographic operations for DiVerify signing."""
    
    @staticmethod
    def generate_ec_key_pair() -> ec.EllipticCurvePrivateKey:
        """Generate an ECDSA key pair using P-256 curve.
        
        Returns:
            EC private key (public key accessible via .public_key())
        """
        return ec.generate_private_key(ec.SECP256R1())
    
    @staticmethod
    def sign_artifact(
        private_key: ec.EllipticCurvePrivateKey,
        input_: Union[bytes, "sigstore_hashes.Hashed"],
    ) -> Tuple["sigstore_hashes.Hashed", bytes]:
        """Sign an artifact and return the hashed input and signature.
        
        Args:
            private_key: ECDSA private key for signing
            input_: Data to sign (bytes or pre-hashed)
            
        Returns:
            Tuple of (hashed_input, signature_bytes)
        """
        try:
            from sigstore._utils import sha256_digest
            import sigstore.hashes as sigstore_hashes
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        # Hash the input if it's raw bytes
        if isinstance(input_, bytes):
            hashed_input = sha256_digest(input_)
        else:
            hashed_input = input_

        # Sign the hash
        signature = private_key.sign(
            hashed_input.digest, 
            ec.ECDSA(hashed_input._as_prehashed())
        )

        return hashed_input, signature
