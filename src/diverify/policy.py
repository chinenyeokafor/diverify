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
from diverify.daemon.quote import validate_user_data
from diverify.util import perf_utils
from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.ngclient import Updater, UpdaterConfig
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, SigstoreKey
KEY_FOR_TYPE_AND_SCHEME.update({("sigstore-oidc", "Fulcio"): SigstoreKey,})

logger = logging.getLogger(__name__)

class PolicyEvaluator:
    def __init__(self, policy_file: str = None):
        """Initialize with a policy file using TUF, or fall back to local for other debug tests"""
        # self.policy = self.get_policy_from_tuf(policy_file)
        self.policy = None
        if not self.policy:
            policy_path = self.get_policy_path(policy_file)
            self.policy = self.load_policy(policy_path)
        
    
    @perf_utils.measure_latency
    def get_policy_from_tuf(self, target = "policy_a1.json"):

        base_url = "http://diverify_web:8083"
        DOWNLOAD_DIR = "/home"

        metadata_dir = self.build_metadata_dir(base_url)

        if not os.path.isfile(f"{metadata_dir}/root.json"):
            print(
                "Trusted local root not found. Use 'tofu' command to "
                "Trust-On-First-Use or copy trusted root metadata to "
                f"{metadata_dir}/root.json"
            )
            return False

        logger.debug(f"Using trusted root in {metadata_dir}")

        if not os.path.isdir(DOWNLOAD_DIR):
            os.mkdir(DOWNLOAD_DIR)

        updater_config = UpdaterConfig(
            prefix_targets_with_hash=False
        )
        try:

            metadata_base_url='http://tuf-metadata:8082'
            updater = Updater(
                metadata_dir=metadata_dir,
                metadata_base_url=metadata_base_url,
                target_base_url=base_url,
                target_dir=DOWNLOAD_DIR,
                config=updater_config,

            )
            updater.refresh()
            
            info = updater.get_targetinfo(target)

            if info is None:
                print(f"Target {target} not found")
                return self.load_policy(path)

            path = updater.find_cached_target(info)
            if path:
                logger.debug(f"Target is available in {path}")
                return self.load_policy(path)

            path = updater.download_target(info)
            # print(f"Target downloaded and available in {path}")

        except (OSError, RepositoryError, DownloadError) as e:
            print(f"Failed to download target {target}: {e}")
            if logging.root.level < logging.ERROR:
                traceback.print_exc()
            return ""
        return self.load_policy(path)
        

    def build_metadata_dir(self, base_url: str) -> str:
        """build a unique and reproducible directory name for the repository url"""
        name = sha256(base_url.encode()).hexdigest()[:8]
        # TODO: Make this not windows hostile?
        return "./tuf-metadata"

    def get_policy_path(self, policy_file) -> str:
        policy_path = Path(os.path.join(os.path.dirname(__file__), 'policies', policy_file))
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        return policy_path

    def load_policy(self, file_path: str) -> dict:
        with open(file_path, "r") as f:
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
            quote_b64 = diverify_proof.pop("quote", None)
            quote = base64.b64decode(quote_b64) if quote_b64 else None
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

