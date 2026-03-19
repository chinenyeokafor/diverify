import os
import json
import logging
import requests
import traceback
from pathlib import Path
from hashlib import sha256
import tempfile, subprocess
import hashlib, base64, json
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from securesystemslib.exceptions import VerificationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from diverify.daemon.quote import validate_user_data
from diverify.util import perf_utils
from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.ngclient import Updater, UpdaterConfig
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, SigstoreKey
KEY_FOR_TYPE_AND_SCHEME.update({("sigstore-oidc", "Fulcio"): SigstoreKey,})

logger = logging.getLogger(__name__)

class PolicyEvaluator:
    def __init__(
        self,
        policy_file: str = None,
        policy_meta_file: str = None,
        policy_pubkey_file: str = None,
        state_file: str = None,
    ):
        """
        Native DiVerify policy lifecycle:
        - load local policy bundle
        - verify signed metadata
        - verify policy hash
        - reject rollback using locally stored latest-seen state
        """
        

        self.policy_dir = Path(os.path.dirname(__file__)) / "policies"
        self.metadata_dir = Path(__file__).resolve().parents[2] / "metadata" / "policies"

        self.policy_file = policy_file or "policy_a1.json"
        self.policy_meta_file = policy_meta_file or self._default_meta_name(self.policy_file)
        self.policy_pubkey_file = policy_pubkey_file or "policy_pub.pem"
        self.state_file = state_file or ".policy_state.json"

        self.policy_path = self._resolve_policy_path(self.policy_file)
        self.meta_path = self._resolve_metadata_path(self.policy_meta_file)
        self.pubkey_path = self._resolve_metadata_path(self.policy_pubkey_file)
        self.state_path = self._resolve_metadata_path(self.state_file)
        print(f"Using state path: {self.state_path}")

        self.policy = self._load_verified_policy_bundle()

    def _resolve_policy_path(self, filename: str) -> Path:
        path = Path(filename)
        if path.is_absolute() or path.exists():
            if not path.exists():
                raise FileNotFoundError(f"Policy file not found: {path}")
            return path

        path = self.policy_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        return path


    def _resolve_metadata_path(self, filename: str) -> Path:
        path = Path(filename)
        if path.is_absolute() or path.exists():
            return path

        return self.metadata_dir / filename

    def _default_meta_name(self, policy_file: str) -> str:
        if policy_file.endswith(".json"):
            return policy_file[:-5] + ".meta.json"
        return policy_file + ".meta.json"

    def _read_json(self, path: Path) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write_json(self, path: Path, obj: dict) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, sort_keys=True)

    def _canonical_json_bytes(self, obj: dict) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _load_pubkey(self) -> Ed25519PublicKey:
        with open(self.pubkey_path, "rb") as f:
            pem = f.read()
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise VerificationError("Policy public key must be an Ed25519 public key")
        return key

    def _verify_metadata_signature(self, metadata: dict) -> None:
        if "signature" not in metadata:
            raise VerificationError("Policy metadata missing 'signature'")

        sig_hex = metadata["signature"]
        signed_fields = dict(metadata)
        del signed_fields["signature"]

        pubkey = self._load_pubkey()
        try:
            pubkey.verify(bytes.fromhex(sig_hex), self._canonical_json_bytes(signed_fields))
        except InvalidSignature as e:
            raise VerificationError("Invalid policy metadata signature") from e

    def _verify_policy_hash(self, metadata: dict, policy_bytes: bytes) -> None:
        expected = metadata.get("policy_hash")
        actual = sha256(policy_bytes).hexdigest()
        if expected != actual:
            raise VerificationError(
                f"Policy hash mismatch: expected {expected}, got {actual}"
            )

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return {}
        return self._read_json(self.state_path)

    def _save_state(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)

    def _check_and_update_state(self, metadata: dict) -> None:
        policy_id = metadata["policy_id"]
        new_version = int(metadata["version"])
        new_epoch = int(metadata["epoch"])

        state = self._load_state()
        current = state.get(policy_id)

        # First time seeing this policy
        if current is None:
            logger.info(f"Initializing policy state for {policy_id} at version={new_version}, epoch={new_epoch}")
            state[policy_id] = {"version": new_version, "epoch": new_epoch}
            self._save_state(state)
            return

        # Existing policy: enforce monotonicity
        seen_version = int(current["version"])
        seen_epoch = int(current["epoch"])

        if new_version < seen_version:
            raise VerificationError(
                f"Policy rollback detected: version {new_version} < {seen_version}"
            )

        if new_version == seen_version and new_epoch < seen_epoch:
            raise VerificationError(
                f"Policy rollback detected: epoch {new_epoch} < {seen_epoch}"
            )

        # update state
        state[policy_id] = {"version": new_version, "epoch": new_epoch}
        self._save_state(state)

    @perf_utils.measure_latency
    def _load_verified_policy_bundle(self) -> dict:
        metadata = self._read_json(self.meta_path)

        with open(self.policy_path, "rb") as f:
            policy_bytes = f.read()

        self._verify_metadata_signature(metadata)
        self._verify_policy_hash(metadata, policy_bytes)
        self._check_and_update_state(metadata)

        return json.loads(policy_bytes.decode("utf-8"))

    def load_policy(self, file_path: str) -> dict:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def build_context(self, diverify_proof, mrenclave) -> dict:
        _key = False
        if diverify_proof.get('identity').get("security_key"):
            slot9a_public_key = self.policy.get("security_key").get("slot9a_public_key")
            slot9a_intermediate_cert = self.policy.get("security_key").get("slotf9_attestation_cert")
            piv_attestation = diverify_proof.get('identity').get("security_key")
            _key = self.verify_piv_attestation(slot9a_intermediate_cert, slot9a_public_key, piv_attestation) 
        _key = True
        return {
            "identity": diverify_proof.get('identity').get("oidc").get("sub") == self.policy.get("identity"),
            "provider": diverify_proof.get('identity').get("oidc").get("iss") == self.policy.get("provider"),
            "device_fingerprint": diverify_proof.get('identity').get("device_fingerprint") == self.policy.get("device_fingerprint"),
            "security_key": _key,
            "signer_measurement": mrenclave == self.policy.get("signer_measurement"),
            "ra_required": diverify_proof.get('identity').get("ra_required"), # this should be false by default
        }
    @perf_utils.measure_latency
    def evaluate(self, trust_material) -> bool:
        cert = trust_material.get("cert")
        diverify_proof = trust_material.get("diverify_proof")
        if cert:
            quote, diverify_proof = self.retrieve_quote(cert)
            key = cert.public_key()
            # self.show_cert(cert)
        elif diverify_proof:   
            quote = base64.b64decode(diverify_proof.pop("quote"))
            key = diverify_proof.get("public_key")
            key = serialization.load_pem_public_key(
                        key.encode('utf-8'),
                        backend=default_backend()
                    )
        try:
            mrenclave = None
            if self.policy.get("signer_measurement"):
                proof_hash = hashlib.sha256(json.dumps(diverify_proof).encode()).digest()
                if quote and not validate_user_data(quote, proof_hash, key):
                    raise InvalidSignature
                mrenclave = self.inspect_quote(quote)
            context = self.build_context(diverify_proof, mrenclave)
            rule = self.policy["rule"].replace("AND", "and").replace("OR", "or")
            return eval(rule, {}, context)
        except InvalidSignature as e:
            raise VerificationError(f"Invalid quote user data signature: {str(e)}")
        except ValueError as e:
            raise VerificationError(f"Error retrieving quote frm cert: {str(e)}")
        
    def retrieve_quote(self, cert):
        diverify_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.23")
        try:
            ext = cert.extensions.get_extension_for_oid(diverify_OID)
            data = ext.value.value
            json_start = data.find(b"{")
            if json_start == -1:
                raise ValueError("Invalid diverify_OID content")
            proof_without_quote = json.loads(data[json_start:].decode())
            try:
                quote = base64.b64decode(proof_without_quote.pop("quote"))
            except KeyError:
                # Mode A is used
                quote = ""
            return quote, proof_without_quote
        except x509.ExtensionNotFound:
            raise ValueError(f"Extension with OID {diverify_OID} not found.")
    
    def inspect_quote(self, quote):
        # Reference: Intel version 3 SGX ECDSA quote
        # https://download.01.org/intel-sgx/sgx-dcap/1.3/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#page=37
        try:
            mrenclave, mrsigner = quote[112:144].hex(), quote[176:208].hex()
            return mrenclave
        except Exception as e:
            print(f"Verification failed: {e}")

    def verify_piv_attestation(self, slot9a_attestation_cert, slot9a_public_key, piv_attestation):
        def run(cmd):
            return subprocess.run(cmd, check=True, stdout=subprocess.PIPE).stdout

        try:
            CA_URL = "https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem"

            if not slot9a_attestation_cert or not slot9a_public_key:
                print("Missing attestation certificate or slot9a public_key in policy.")
                return False
            if not piv_attestation:
                print("Missing PIV attestation in DiVerify proof")
                return False

            with tempfile.NamedTemporaryFile("w+", delete=True) as f9_cert, \
                tempfile.NamedTemporaryFile("w+", delete=True) as pubkey, \
                tempfile.NamedTemporaryFile("w+", delete=True) as attest_cert, \
                tempfile.NamedTemporaryFile("wb+", delete=True) as ca_cert:

                f9_cert.write(slot9a_attestation_cert); f9_cert.flush()
                pubkey.write(slot9a_public_key); pubkey.flush()
                attest_cert.write(piv_attestation); attest_cert.flush()

                ca_cert.write(requests.get(CA_URL).content); ca_cert.flush()

                run([
                    "openssl", "verify",
                    "-CAfile", ca_cert.name,
                    "-untrusted", f9_cert.name,
                    attest_cert.name
                ])

                attested_pub = run(["openssl", "x509", "-in", attest_cert.name, "-pubkey", "-noout"])
                saved_pub = Path(pubkey.name).read_bytes()

                if attested_pub.strip() != saved_pub.strip():
                    raise ValueError("Public key mismatch — attestation invalid.")

            return True
        except Exception as e:
            print(f"PIV Attestation verification failed: {e}")
            return False

    def show_cert(self, signing_certificate):
        """Display the signing certificate in text format."""
        from OpenSSL import crypto
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = crypto.load_certificate(
            crypto.FILETYPE_ASN1,
            signing_certificate.public_bytes(Encoding.DER)
        )

        text_output = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
        logging.info(f"Signing Certificate: {text_output.decode('utf-8')}")

if __name__ == "__main__":
    from pathlib import Path

    policy_dir = Path("src/diverify/policies")
    metadata_dir = Path("metadata/policies")

    for p in policy_dir.glob("*.json"):
        try:
            PolicyEvaluator(
                policy_file=str(p),
                policy_meta_file=str(metadata_dir / f"{p.stem}.meta.json"),
                policy_pubkey_file=str(metadata_dir / "policy_pub.pem"),
            )
            print(f"[OK] {p.name}")
        except Exception as e:
            print(f"[FAIL] {p.name}: {e}")