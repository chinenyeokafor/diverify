
import logging
from typing import cast
from diverify.policy import PolicyEvaluator
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from securesystemslib.exceptions import VerificationError
logger = logging.getLogger(__name__)

def validate_signature(public_key, hashed_input, artifact_signature):
    try:
        signing_key = cast(ec.EllipticCurvePublicKey, public_key)
        signing_key.verify(
            artifact_signature,
            hashed_input.digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    except InvalidSignature:
        raise VerificationError("Signature is invalid for input")

    logger.debug("Successfully verified signature...")

def validate_policy(policy, proof, type="diverify_proof"):
    policy_evaluator = PolicyEvaluator(policy) 

    result = policy_evaluator.evaluate({type: proof})
    if not result:
        raise VerificationError("The signature does not meet the policy constraints.")
    logger.info("Policy evaluation passed")
