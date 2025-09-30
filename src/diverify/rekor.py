import rekor_types
from sigstore.models import LogEntry
import base64
import json
from typing import Dict
from urllib.parse import urljoin
import requests
from cryptography.hazmat.primitives import serialization
from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer import Signature
from sigstore.models import Bundle
from sigstore_protobuf_specs.dev.sigstore.common.v1 import (
    HashOutput, MessageSignature
)
from diverify.sigstore import DEFAULT_REKOR_URL

def submit_to_tlog(signature_material: Dict) -> Bundle:
    """
    Submits the artifact signature to the Rekor log and returns a `Bundle`.

    Args:
        signature_material (Dict): Contains 'signing_cert', 'hashed_input', 
        and 'artifact_signature'.

    Returns:
        Bundle: The signed result from the transparency log.

    Raises:
        UnsupportedLibraryError: If required libraries are missing.
        requests.exceptions.RequestException: For HTTP request errors.
    """
    cert = signature_material['signing_cert']
    hashed_input = signature_material["hashed_input"]
    artifact_signature = signature_material["artifact_signature"]

    b64_cert = base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.PEM))

    content = MessageSignature(
        message_digest=HashOutput(
            algorithm=hashed_input.algorithm,
            digest=hashed_input.digest,
        ),
        signature=artifact_signature,
    )
    # If the signing was done by diverify deamon enclave, then it doesnt have _as_hashedrekord_algorithm method
    if hasattr(hashed_input, "_as_hashedrekord_algorithm"):
        algorithm = hashed_input._as_hashedrekord_algorithm()
    elif hashed_input.algorithm == 1:
        algorithm = "sha256"
    else:
        raise ValueError(f"Unknown hash algorithm: {hashed_input.algorithm}")
    proposed_entry = rekor_types.Hashedrekord(
        spec=rekor_types.hashedrekord.HashedrekordV001Schema(
            signature=rekor_types.hashedrekord.Signature(
                content=base64.b64encode(artifact_signature).decode(),
                public_key=rekor_types.hashedrekord.PublicKey(
                    content=b64_cert.decode()
                ),
            ),
            data=rekor_types.hashedrekord.Data(
                hash=rekor_types.hashedrekord.Hash(
                    algorithm=algorithm,
                    value=hashed_input.digest.hex(),
                )
            ),
        ),
    )
    payload = proposed_entry.model_dump(mode="json", by_alias=True)
    rekor_url = urljoin(DEFAULT_REKOR_URL, "/api/v1/log/entries/")
    resp = requests.post(rekor_url, json=payload)
    resp.raise_for_status()

    entry = LogEntry._from_response(resp.json())
    bundle = Bundle._from_parts(cert, content, entry)

    bundle_json = json.loads(bundle.to_json())
    keyid=bundle_json["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"]
    return Signature(keyid, bundle_json["messageSignature"]["signature"], {"bundle": bundle_json})

