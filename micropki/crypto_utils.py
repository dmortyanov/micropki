"""Cryptographic utility functions — key generation, PEM I/O, DN parsing."""

from __future__ import annotations

import os
import platform
import re
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


_ECC_CURVES: dict[int, ec.EllipticCurve] = {
    256: ec.SECP256R1(),
    384: ec.SECP384R1(),
}


def generate_key(key_type: str, key_size: int) -> PrivateKeyTypes:
    """Generate an RSA or ECC private key.

    Args:
        key_type: ``'rsa'`` or ``'ecc'``.
        key_size: RSA bit length (>= 2048) or ECC curve size (256 or 384).

    Returns:
        A private key object.
    """
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ecc":
        curve = _ECC_CURVES.get(key_size)
        if curve is None:
            raise ValueError(f"Unsupported ECC curve size: {key_size}")
        return ec.generate_private_key(curve)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")


def serialize_private_key(key: PrivateKeyTypes, passphrase: bytes) -> bytes:
    """Serialize a private key to encrypted PEM (PKCS#8)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def serialize_private_key_unencrypted(key: PrivateKeyTypes) -> bytes:
    """Serialize a private key to unencrypted PEM (PKCS#8)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem_data: bytes, passphrase: bytes) -> PrivateKeyTypes:
    """Load an encrypted PEM private key."""
    return serialization.load_pem_private_key(pem_data, password=passphrase)


def save_private_key(pem_data: bytes, path: str) -> None:
    """Write PEM data to *path* with restricted permissions (0o600)."""
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)

    if platform.system() != "Windows":
        os.chmod(parent, 0o700)

    with open(path, "wb") as f:
        f.write(pem_data)

    if platform.system() != "Windows":
        os.chmod(path, 0o600)


def parse_subject_dn(dn_string: str) -> dict[str, str]:
    """Parse a Distinguished Name string into a dict.

    Supports slash notation (``/CN=.../O=...``) and comma-separated
    (``CN=...,O=...``).
    """
    dn_string = dn_string.strip()

    if dn_string.startswith("/"):
        parts = dn_string.lstrip("/").split("/")
    else:
        parts = [p.strip() for p in dn_string.split(",")]

    result: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Invalid DN component (missing '='): '{part}'")
        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()
        if not value:
            raise ValueError(f"Empty value for DN attribute '{key}'")
        result[key] = value

    if "CN" not in result:
        raise ValueError("Subject DN must contain at least a CN (Common Name)")

    return result

def load_certificates_from_pem(pem_path: str):
    """Load one or more certificates from a PEM file."""
    import cryptography.x509 as x509
    from cryptography.hazmat.backends import default_backend
    
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    
    # cryptography doesn't natively parse a bundle of certs reliably, so we split by CERTIFICATE exactly
    certs = []
    lines = pem_data.decode("utf-8").splitlines()
    current_cert = []
    in_cert = False
    
    for line in lines:
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            current_cert = [line]
        elif "-----END CERTIFICATE-----" in line and in_cert:
            current_cert.append(line)
            in_cert = False
            cert_content = "\n".join(current_cert).encode("utf-8")
            certs.append(x509.load_pem_x509_certificate(cert_content, default_backend()))
        elif in_cert:
            current_cert.append(line)
            
    return certs
