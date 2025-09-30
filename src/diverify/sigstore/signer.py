"""
DiVerify Sigstore Signer

Main signer implementation that orchestrates OIDC authentication, certificate signing,
and artifact signing with DiVerify attestation proofs.
"""

import jwt
from typing import Any, Dict, Tuple
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._signer import Key, SecretsHandler, Signature, Signer

from .key import SigstoredKey
from .oidc import OIDCAuthenticator
from .fulcio import FulcioClient
from .crypto import CryptoProvider

IMPORT_ERROR = "sigstore library required to use 'sigstore-oidc' keys"


class SigstoredSigner(Signer):
    """DiVerify-enhanced Sigstore signer with attestation capabilities."""

    SCHEME = "diverify"

    def __init__(self, token: str, decoded_token: Dict, public_key: Key):
        self._public_key = public_key
        self._token = token
        self._decoded_token = decoded_token
        
        # Initialize component clients
        self._oidc_client = OIDCAuthenticator()
        self._fulcio_client = FulcioClient()
        self._crypto_provider = CryptoProvider()

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> Tuple["SigstoredSigner", str]:
        """Create signer from private key URI.
        
        Returns:
            Tuple of (signer, token)
        """
        try:
            from sigstore.oidc import detect_credential
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        if not isinstance(public_key, SigstoredKey):
            raise ValueError(f"expected SigstoredKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)
        if uri.scheme != cls.SCHEME:
            raise ValueError(f"SigstoredSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))
        ambient = params.get("ambient", "true") == "true"

        # Get identity token
        if not ambient:
            oidc_client = OIDCAuthenticator()
            token, decoded_token = oidc_client.get_identity_token(limit_scope=bool(secrets_handler))
        else:
            credential = detect_credential()
            if not credential:
                try:
                    from diverify.daemon.scopes import get_identity_token
                    credential = get_identity_token()
                except Exception:
                    raise RuntimeError("Failed to detect credentials")
            token, decoded_token = credential, jwt.decode(credential, options={"verify_signature": False})

        # Validate token against key
        cls._validate_token_identity(public_key, decoded_token, ambient)

        return cls(token, decoded_token, public_key), token

    @classmethod
    def _validate_token_identity(cls, public_key: SigstoredKey, decoded_token: Dict, ambient: bool) -> None:
        """Validate that the token identity matches the public key."""
        key_identity = public_key.keyval["identity"]
        key_issuer = public_key.keyval["issuer"]
        
        if key_issuer != decoded_token["iss"]:
            raise ValueError(
                f"Signer identity issuer {decoded_token['iss']} "
                f"did not match key: {key_issuer}"
            )
        
        # Get identity from token
        try:
            token_identity = decoded_token['email']
        except KeyError:
            token_identity = decoded_token['sub']
        
        if not ambient and key_identity != token_identity:
            raise ValueError(
                f"Signer identity {token_identity} did not match key: {key_identity}"
            )

    @classmethod
    def _get_uri(cls, ambient: bool) -> str:
        """Generate private key URI for this signer."""
        return f"{cls.SCHEME}:{'' if ambient else '?ambient=false'}"

    @classmethod
    def import_(
        cls, identity: str, issuer: str, ambient: bool = True
    ) -> Tuple[str, SigstoredKey]:
        """Create public key and signer URI.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Args:
            identity: The OIDC identity to use when verifying a signature.
            issuer: The OIDC issuer to use when verifying a signature.
            ambient: Toggle usage of ambient credentials in returned URI.
            
        Returns:
            Tuple of (private_key_uri, public_key)
        """
        keyid, key = SigstoredKey.create_key(identity, issuer)
        uri = cls._get_uri(ambient)
        return uri, key 

    def sign(self, payload: bytes, diverify_proof: Dict) -> Dict[str, Any]:
        """Sign payload with DiVerify attestation proof.
        
        Args:
            payload: Bytes to be signed
            diverify_proof: DiVerify attestation proof to embed in certificate
            
        Returns:
            Signature material including hashed input, signature, and certificate
        """
        # Generate ephemeral key pair
        private_key = self._crypto_provider.generate_ec_key_pair()
        
        # Get email from token
        try:
            email_address = self._decoded_token['email']
        except KeyError:
            email_address = self._decoded_token['sub']
        
        # Create CSR with DiVerify proof
        csr = self._fulcio_client.create_csr(email_address, private_key, diverify_proof)
        
        # Get certificate from Fulcio
        cert_response = self._fulcio_client.get_certificate(csr, self._token)
        
        # Sign the payload
        hashed_input, artifact_signature = self._crypto_provider.sign_artifact(private_key, payload)
        
        return {
            "hashed_input": hashed_input,
            "artifact_signature": artifact_signature,
            "signing_cert": cert_response.cert
        }
