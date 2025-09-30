"""
DiVerify Sigstore Integration

This module provides enhanced Sigstore integration with DiVerify attestation capabilities.
"""

from .signer import SigstoredSigner
from .key import SigstoredKey

# Configuration constants
import configparser

config = configparser.ConfigParser()
config.read('stack_config.ini')

DEFAULT_FULCIO_URL = config['settings']['fulcio-url']
DEFAULT_REKOR_URL = config['settings']['rekor-url']
DEFAULT_OAUTH_ISSUER_URL = config['settings']['oauth_issuer-url']

__all__ = [
    "SigstoredSigner", 
    "SigstoredKey", 
    "DEFAULT_REKOR_URL", 
    "DEFAULT_FULCIO_URL", 
    "DEFAULT_OAUTH_ISSUER_URL"
]
