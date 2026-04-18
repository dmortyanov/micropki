from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import logging

logger = logging.getLogger(__name__)

class PolicyError(Exception):
    pass

def verify_key_policy(public_key, min_rsa=2048, min_ecc=256):
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < min_rsa:
            raise PolicyError(f"RSA key size must be at least {min_rsa} bits, got {public_key.key_size}")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.key_size < min_ecc:
            raise PolicyError(f"ECC key size must be at least {min_ecc} bits, got {public_key.key_size}")
    else:
        raise PolicyError(f"Unsupported public key type: {type(public_key)}")

def verify_validity_policy(validity_days: int, max_days=398):
    if validity_days > max_days:
        raise PolicyError(f"Validity period of {validity_days} days exceeds the maximum policy limit of {max_days} days")

def verify_san_policy(san_extension: x509.SubjectAlternativeName | None, allow_wildcard=False):
    if not san_extension:
        return
        
    for name in san_extension:
        if isinstance(name, x509.DNSName):
            if not allow_wildcard and name.value.startswith("*."):
                raise PolicyError(f"Wildcard certificates are not allowed by policy: {name.value}")
