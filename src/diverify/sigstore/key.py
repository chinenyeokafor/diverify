"""
DiVerify Sigstore Key Management

Handles key representation and validation for DiVerify-enhanced Sigstore keys.
"""

from typing import Any
from securesystemslib.signer._signer import Key, Signature
from securesystemslib.signer._utils import compute_default_keyid


class SigstoredKey(Key):
    """Sigstore OIDC key with DiVerify attestation capabilities."""
    
    DEFAULT_KEY_TYPE = "sigstore-oidc"
    DEFAULT_SCHEME = "Fulcio"

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        for content in ["identity", "issuer"]:
            if content not in keyval or not isinstance(keyval[content], str):
                raise ValueError(f"{content} string required for scheme {scheme}")
        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> "SigstoredKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        """Signature verification is handled by the DiVerify verifier module."""
        pass

    @classmethod
    def create_key(cls, identity: str, issuer: str) -> tuple[str, "SigstoredKey"]:
        """Create a new SigstoredKey with computed keyid.
        
        Returns:
            Tuple of (keyid, SigstoredKey)
        """
        keytype = cls.DEFAULT_KEY_TYPE
        scheme = cls.DEFAULT_SCHEME
        keyval = {"identity": identity, "issuer": issuer}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        key = cls(keyid, keytype, scheme, keyval)
        return keyid, key
