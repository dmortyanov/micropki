"""CSR (Certificate Signing Request) generation and verification."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import serialization

from .certificates import build_x509_name
from .crypto_utils import parse_subject_dn


def generate_csr(
    private_key: PrivateKeyTypes,
    subject_str: str,
    is_ca: bool = False,
    path_length: int | None = None,
) -> x509.CertificateSigningRequest:
    """Generate a PKCS#10 Certificate Signing Request.

    Args:
        private_key: The requester's private key.
        subject_str: Distinguished Name string.
        is_ca: Whether to include BasicConstraints CA=TRUE.
        path_length: Path length constraint (only meaningful when *is_ca* is True).

    Returns:
        A signed CSR object.
    """
    dn = parse_subject_dn(subject_str)
    name = build_x509_name(dn)

    if isinstance(private_key, rsa.RSAPrivateKey):
        sign_algo = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        sign_algo = hashes.SHA384()
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")

    builder = x509.CertificateSigningRequestBuilder().subject_name(name)

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

    return builder.sign(private_key, sign_algo)


def serialize_csr(csr: x509.CertificateSigningRequest) -> bytes:
    """Serialize a CSR to PEM format."""
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr(path: str) -> x509.CertificateSigningRequest:
    """Load a PEM-encoded CSR from disk."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())


def verify_csr(csr: x509.CertificateSigningRequest) -> bool:
    """Verify that the CSR is properly self-signed."""
    return csr.is_signature_valid
