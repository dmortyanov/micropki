"""X.509 certificate generation for MicroPKI."""

from __future__ import annotations

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

from .crypto_utils import parse_subject_dn

_OID_MAP = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
}


def build_x509_name(dn: dict[str, str]) -> x509.Name:
    """Convert a parsed DN dict into an :class:`x509.Name`."""
    attrs = []
    for key, value in dn.items():
        oid = _OID_MAP.get(key)
        if oid is None:
            raise ValueError(f"Unsupported DN attribute: {key}")
        attrs.append(x509.NameAttribute(oid, value))
    return x509.Name(attrs)


def create_self_signed_cert(
    private_key: PrivateKeyTypes,
    subject_str: str,
    validity_days: int,
) -> x509.Certificate:
    """Create a self-signed Root CA certificate (X.509 v3).

    Extensions:
    - BasicConstraints(CA=TRUE, critical)
    - KeyUsage(keyCertSign, cRLSign, digitalSignature, critical)
    - SubjectKeyIdentifier
    - AuthorityKeyIdentifier (= SKI for self-signed)
    """
    dn = parse_subject_dn(subject_str)
    name = build_x509_name(dn)
    public_key = private_key.public_key()

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)

    if isinstance(private_key, rsa.RSAPrivateKey):
        sign_algo = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        sign_algo = hashes.SHA384()
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
    )

    return builder.sign(private_key, sign_algo)


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)


def save_certificate(pem_data: bytes, path: str) -> None:
    """Write certificate PEM to *path*, creating parent dirs as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_data)


def load_certificate(path: str) -> x509.Certificate:
    """Load a PEM certificate from disk."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())
