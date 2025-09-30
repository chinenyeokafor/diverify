import json
import requests
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import base64
import configparser


config = configparser.ConfigParser()
config.read('stack_config.ini')

DEFAULT_FULCIO_URL = config['settings']['fulcio-url']
DEFAULT_REKOR_URL = config['settings']['rekor-url']
DEFAULT_OAUTH_ISSUER_URL = config['settings']['oauth_issuer-url']
CTFE_PUBKEY_PATH = "ctfe_public.pem" 

def get_tlog_public_key():
    response = requests.get(DEFAULT_REKOR_URL + "/api/v1/log/publicKey")
    response.raise_for_status()
    key_pem = response.content
    public_key = serialization.load_pem_public_key(key_pem)

    # Convert PEM to DER
    der_data = key_pem.replace(b'-----BEGIN PUBLIC KEY-----', b'') \
                     .replace(b'-----END PUBLIC KEY-----', b'') \
                     .replace(b'\n', b'')
    der_data = base64.b64decode(der_data)
    
    if isinstance(public_key, rsa.RSAPublicKey):
        hash_algorithm = "SHA2_256" 
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        hash_algorithm = {
            "secp256r1": "SHA2_256",
            "secp384r1": "SHA2_384",
            "secp521r1": "SHA2_512"
        }.get(curve_name, "Unknown")
    else:
        hash_algorithm = "Unknown"

    return {
        "rawBytes": base64.b64encode(der_data).decode(),
        "hashAlgorithm": hash_algorithm,
        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
    }


def get_ca_cert():
    response = requests.get(DEFAULT_FULCIO_URL + "/api/v1/rootCert")
    response.raise_for_status()
    cert_pem = response.content
    
    # Convert PEM to DER
    der_data = cert_pem.replace(b'-----BEGIN CERTIFICATE-----', b'') \
                       .replace(b'-----END CERTIFICATE-----', b'') \
                       .replace(b'\n', b'')
    der_data = base64.b64decode(der_data)
    cert = x509.load_der_x509_certificate(der_data)
    
    validity = get_validity(cert)
    
    org_name = None
    common_name = None
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.ORGANIZATION_NAME:
            org_name = attribute.value
        if attribute.oid == x509.NameOID.COMMON_NAME:
            common_name = attribute.value
    
    signature_oid = cert.signature_algorithm_oid
    hash_algorithm = "Unknown"

    sig_hash_mapping = {
        "1.2.840.10045.4.3.2": "SHA2_256",
        "1.2.840.10045.4.3.3": "SHA2_384",
        "1.2.840.10045.4.3.4": "SHA2_512",
        "1.2.840.113549.1.1.11": "SHA2_256", 
        "1.2.840.113549.1.1.12": "SHA2_384", 
        "1.2.840.113549.1.1.13": "SHA2_512", 
    }
    hash_algorithm = sig_hash_mapping.get(signature_oid.dotted_string, "Unknown")

    return {
        "rawBytes": base64.b64encode(der_data).decode(),  # Return DER bytes encoded as base64
        "validFor": validity,
        "subject": {
            "organization": org_name,
            "commonName": common_name
        }
    }
def get_ca_cert_pem():
    response = requests.get(DEFAULT_FULCIO_URL + "/api/v1/rootCert")
    response.raise_for_status()
    cert_pem = response.content
    cert = x509.load_pem_x509_certificate(cert_pem)
    validity = get_validity(cert)
    
    org_name = None
    common_name = None
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.ORGANIZATION_NAME:
            org_name = attribute.value
        if attribute.oid == x509.NameOID.COMMON_NAME:
            common_name = attribute.value
    
    signature_oid = cert.signature_algorithm_oid
    hash_algorithm = "Unknown"

    sig_hash_mapping = {
        "1.2.840.10045.4.3.2": "SHA2_256",
        "1.2.840.10045.4.3.3": "SHA2_384",
        "1.2.840.10045.4.3.4": "SHA2_512",
        "1.2.840.113549.1.1.11": "SHA2_256",  
        "1.2.840.113549.1.1.12": "SHA2_384",
        "1.2.840.113549.1.1.13": "SHA2_512",
    }
    hash_algorithm = sig_hash_mapping.get(signature_oid.dotted_string, "Unknown")

    return {
        "rawBytes": base64.b64encode(cert_pem).decode(),
        "validFor": validity,
        "subject": {
            "organization": org_name,
            "commonName": common_name
        }
    }


def get_ctfe_public_key():
    with open(CTFE_PUBKEY_PATH, "rb") as f:
        key_pem = f.read()
    
    # Load the public key to get its properties
    public_key = serialization.load_pem_public_key(key_pem)
    
    # Convert PEM to DER
    der_data = key_pem.replace(b'-----BEGIN PUBLIC KEY-----', b'') \
                     .replace(b'-----END PUBLIC KEY-----', b'') \
                     .replace(b'\n', b'')
    der_data = base64.b64decode(der_data)
    
    if isinstance(public_key, rsa.RSAPublicKey):
        hash_algorithm = "SHA2_256" 
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        hash_algorithm = {
            "secp256r1": "SHA2_256",
            "secp384r1": "SHA2_384",
            "secp521r1": "SHA2_512"
        }.get(curve_name, "Unknown")
    else:
        hash_algorithm = "Unknown"

    return {
        "rawBytes": base64.b64encode(der_data).decode(),  
        "hashAlgorithm": hash_algorithm,
        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
    }

def get_validity(cert):
    return {
        "start": cert.not_valid_before_utc.isoformat(),
        "end": cert.not_valid_after_utc.isoformat()
    }

def generate_clienttrustconfig():
    trusted_root = {
        "mediaType": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
        "trustedRoot": {
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [
                {
                    "baseUrl": DEFAULT_REKOR_URL,
                    "hashAlgorithm": get_tlog_public_key()["hashAlgorithm"],
                    "publicKey": {
                        "rawBytes": get_tlog_public_key()["rawBytes"],
                        "keyDetails": get_tlog_public_key()["keyDetails"],
                        "validFor": {"start": "2021-01-12T11:53:27.000Z"}
                    },
                    "logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="}
                }
            ],
            "certificateAuthorities": [
                {
                    "subject": get_ca_cert()["subject"],
                    "uri": DEFAULT_FULCIO_URL,
                    "certChain": {
                        "certificates": [{"rawBytes": get_ca_cert()["rawBytes"]}]
                    },
                    "validFor": get_ca_cert()["validFor"],
                    "hashAlgorithm": get_ca_cert()["hashAlgorithm"]
                }
            ],
            "ctlogs": [
                {
                    "baseUrl": "",
                    "hashAlgorithm": get_ctfe_public_key()["hashAlgorithm"], 
                    "publicKey": {
                        "rawBytes": get_ctfe_public_key()["rawBytes"],
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                        "validFor": {"start": "2021-03-14T00:00:00.000Z"}
                    },
                    "logId": {"keyId": "CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I="}
                }
            ]
        },
        "signingConfig": {
            "caUrl": DEFAULT_FULCIO_URL,
            "oidcUrl": DEFAULT_OAUTH_ISSUER_URL,
            "tlogUrls": [
                DEFAULT_REKOR_URL
            ],
            "tsaUrls": [
                ""
            ]
        }
    }
    return trusted_root

def generate_trusted_root():
    trusted_root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "baseUrl": DEFAULT_REKOR_URL,
                "hashAlgorithm": get_tlog_public_key()["hashAlgorithm"],
                "publicKey": {
                    "rawBytes": get_tlog_public_key()["rawBytes"],
                    "keyDetails": get_tlog_public_key()["keyDetails"],
                    "validFor": {"start": "2021-01-12T11:53:27.000Z"}
                },
                "logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="}
            }
        ],
        "certificateAuthorities": [
            {
                "subject": get_ca_cert()["subject"],
                "uri": DEFAULT_FULCIO_URL,
                "certChain": {
                    "certificates": [{"rawBytes": get_ca_cert()["rawBytes"]}]
                },
                "validFor": get_ca_cert()["validFor"]
            }
        ],
        "ctlogs": [
            {
                "baseUrl": "",
                "hashAlgorithm": get_ctfe_public_key()["hashAlgorithm"], 
                "publicKey": {
                    "rawBytes": get_ctfe_public_key()["rawBytes"],
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": "2021-03-14T00:00:00.000Z"}
                },
                "logId": {"keyId": "CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I="}
            }
        ]
    }
    return trusted_root

def save_trusted_root(filename="diverify/trusted_root.json"):
    data = generate_trusted_root()
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Trusted root configuration saved to {filename}")

def save_clienttrustconfig(filename="config.v1_mine.json.json"):
    data = generate_trusted_root()
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Client Trust configuration saved to {filename}")

if __name__ == "__main__":
    save_trusted_root()
