import subprocess
import os
import tempfile
import logging
import tempfile
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
logger = logging.getLogger(__name__)

def verify(quote_path):
    try:
        logger.debug("Starting SGX quote verification process")
        
        base_dir = "/home/SGXDataCenterAttestationPrimitives/SampleCode/QuoteVerificationSample"
        verification_app = os.path.join(base_dir, "app")
        
        if not os.path.exists(verification_app):
            logging.error(f"Verification tool not found at {verification_app}.")
            return False
            
        if not os.path.exists(quote_path):
            logging.error(f"Quote file not found at {quote_path}")
            return False
        result = subprocess.run([verification_app, "-quote", quote_path],cwd=base_dir,capture_output=True,text=True,check=False)
        
        if "Verification completed successfully" in result.stdout:
            logging.info("Quote verification succeeded")
            logging.debug(f"Verification output:\n{result.stdout}")
            return True
        elif "Warning: App: Verification completed, but collateral is out of date based " in result.stdout:
            return True
        else:
            logging.error("Quote verification failed")
            if result.stderr:
                logging.error(f"Error output:\n{result.stderr}")
            else:
                logging.error(f"Tool output:\n{result.stdout}")
            return False
            
    except subprocess.CalledProcessError as e:
        logging.error(f"Verification process failed with exit code {e.returncode}")
        logging.debug(f"Process output:\n{e.stderr if e.stderr else e.stdout}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during verification: {str(e)}", exc_info=True)
        return False
    
def verify_quote(quote_data):
    """Verify a quote received as byte data."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as temp_file:
            temp_file.write(quote_data)
            temp_path = temp_file.name
        return verify(temp_path)
    except Exception as e:
        print(f"Verification failed: {e}")
        return False
    finally:
        os.unlink(temp_path) if 'temp_path' in locals() and os.path.exists(temp_path) else None

def get_quote(user_data: bytes) -> bytes:
    set_user_data(user_data)
    try:
        with open("/dev/attestation/quote", "rb") as f:
            quote = f.read()
        logging.info("Quote retrieved successfully")
        return quote
    except Exception as e:
        raise RuntimeError("Failed to get quote. Ensure this is running in an enclave.") from e

def set_user_data(user_data):
    """
    Set the user data for the SGX quote.
    """
    try:
        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(user_data)
        logging.info("User data set successfully")
    except Exception as e:
        raise RuntimeError("Failed to set user data. Ensure this is running in an enclave.") from e

def get_user_data(dvp_sig: bytes) -> bytes:
        r, s = decode_dss_signature(dvp_sig)
        r_bytes = r.to_bytes(32, byteorder="big")
        s_bytes = s.to_bytes(32, byteorder="big")
        raw_sig = r_bytes + s_bytes
        return raw_sig

def validate_user_data(quote: bytes, hashed_dvp, public_key=None) -> bool:
        rcvd_user_data = quote[368:432]
        if public_key is None:
            # we didn't sign in the enclave, so we don't have a public key. 
            # User data contains hashed_dv followed by padding.
            return hashed_dvp == rcvd_user_data[:len(hashed_dvp)]
        else:
            # Split into r and s (each 32 bytes for SECP256K1/SECP256R1)
            r = int.from_bytes(rcvd_user_data[:32], byteorder="big")
            s = int.from_bytes(rcvd_user_data[32:], byteorder="big")
            der_signature = encode_dss_signature(r, s)
            try:
                public_key.verify(
                    der_signature, 
                    hashed_dvp, 
                    ec.ECDSA(Prehashed(hashes.SHA256())))
                logger.debug("Signature verified successfully!")
                return True
            except Exception as e:
                logger.error(f"Signature verification failed: {e}")
                return False
        