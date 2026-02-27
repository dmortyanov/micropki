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
from .templates import (
    CertificateTemplate,
    ParsedSAN,
    build_key_usage,
    build_san_extension,
)

_OID_MAP = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "EMAIL": NameOID.EMAIL_ADDRESS,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
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


def _pick_hash(signing_key: PrivateKeyTypes) -> hashes.HashAlgorithm:
    """Choose the hash algorithm based on the signing key type."""
    if isinstance(signing_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    elif isinstance(signing_key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384()
    raise ValueError(f"Unsupported key type: {type(signing_key)}")


def sign_intermediate_certificate(
    csr: x509.CertificateSigningRequest,
    root_key: PrivateKeyTypes,
    root_cert: x509.Certificate,
    validity_days: int,
    path_length: int = 0,
) -> x509.Certificate:
    """Sign an Intermediate CA CSR with the Root CA.

    The resulting certificate includes:
    - BasicConstraints(CA=TRUE, pathLenConstraint), critical
    - KeyUsage(keyCertSign, cRLSign), critical
    - SKI from the CSR public key
    - AKI from the Root CA's SKI
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    public_key = csr.public_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)

    root_ski = root_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
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
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                root_ski.value
            ),
            critical=False,
        )
    )

    return builder.sign(root_key, _pick_hash(root_key))


def sign_end_entity_certificate(
    public_key,
    subject_name: x509.Name,
    ca_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    template: CertificateTemplate,
    parsed_san: ParsedSAN,
    validity_days: int,
) -> x509.Certificate:
    """Sign an end-entity certificate using the CA key.

    Extensions are determined by the template and SAN configuration.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    ca_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )

    is_rsa = isinstance(public_key, rsa.RSAPublicKey)
    key_usage = build_key_usage(template, is_rsa)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(template.extended_key_usage),
            critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_ski.value
            ),
            critical=False,
        )
    )

    san_ext = build_san_extension(parsed_san)
    if san_ext is not None:
        builder = builder.add_extension(san_ext, critical=False)

    return builder.sign(ca_key, _pick_hash(ca_key))
