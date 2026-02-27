"""CA operations: Root CA init, Intermediate CA issuance, certificate issuance.

Orchestrates key generation, certificate creation, key storage,
policy document writing, and logging.
"""

from __future__ import annotations

import datetime
import logging
import os
import re

from .certificates import (
    build_x509_name,
    create_self_signed_cert,
    load_certificate,
    save_certificate,
    serialize_certificate,
    sign_end_entity_certificate,
    sign_intermediate_certificate,
)
from .csr import generate_csr, serialize_csr
from .crypto_utils import (
    generate_key,
    load_private_key,
    parse_subject_dn,
    save_private_key,
    serialize_private_key,
    serialize_private_key_unencrypted,
)
from .templates import (
    ParsedSAN,
    get_template,
    parse_san_strings,
    validate_san_for_template,
)


def init_root_ca(
    subject_str: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: str,
    validity_days: int,
    logger: logging.Logger,
) -> None:
    """Create a self-signed Root CA: key pair, certificate, policy file.

    Args:
        subject_str: Distinguished Name string.
        key_type: ``'rsa'`` or ``'ecc'``.
        key_size: 4096 (RSA) or 384 (ECC).
        passphrase: Passphrase bytes for private key encryption.
        out_dir: Output directory.
        validity_days: Certificate validity in days.
        logger: Logger instance.
    """
    key_path = os.path.join(out_dir, "private", "ca.key.pem")
    cert_path = os.path.join(out_dir, "certs", "ca.cert.pem")
    policy_path = os.path.join(out_dir, "policy.txt")

    logger.info("Starting key generation (%s, %d bits)...", key_type.upper(), key_size)
    private_key = generate_key(key_type, key_size)
    logger.info("Key generation completed successfully.")

    logger.info("Starting certificate signing (self-signed Root CA)...")
    cert = create_self_signed_cert(private_key, subject_str, validity_days)
    logger.info("Certificate signing completed successfully.")

    key_pem = serialize_private_key(private_key, passphrase)
    save_private_key(key_pem, key_path)
    logger.info("Private key saved to %s", os.path.abspath(key_path))

    cert_pem = serialize_certificate(cert)
    save_certificate(cert_pem, cert_path)
    logger.info("Certificate saved to %s", os.path.abspath(cert_path))

    _write_policy(cert, key_type, key_size, policy_path)
    logger.info("Policy document saved to %s", os.path.abspath(policy_path))

    logger.info("Root CA initialisation completed successfully.")


def _write_policy(
    cert,
    key_type: str,
    key_size: int,
    path: str,
) -> None:
    """Write a human-readable policy.txt."""
    subject = cert.subject.rfc4514_string()
    serial_hex = format(cert.serial_number, "X")
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    algo_label = f"{key_type.upper()}-{key_size}"
    creation_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    content = (
        "========================================\n"
        "  MicroPKI — Certificate Policy Document\n"
        "========================================\n"
        "\n"
        f"CA Name (Subject DN): {subject}\n"
        f"Certificate Serial Number: {serial_hex}\n"
        f"Validity Period:\n"
        f"  Not Before: {not_before}\n"
        f"  Not After:  {not_after}\n"
        f"Key Algorithm and Size: {algo_label}\n"
        "\n"
        "Purpose:\n"
        "  Root CA for MicroPKI demonstration.\n"
        "  This certificate is the trust anchor for the entire PKI hierarchy.\n"
        "\n"
        f"Policy Version: 1.0\n"
        f"Creation Date: {creation_date}\n"
    )

    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def issue_intermediate_ca(
    root_cert_path: str,
    root_key_path: str,
    root_passphrase: bytes,
    subject_str: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: str,
    validity_days: int,
    path_length: int,
    logger: logging.Logger,
) -> None:
    """Generate an Intermediate CA signed by the Root CA."""
    root_cert = load_certificate(root_cert_path)

    with open(root_key_path, "rb") as f:
        root_key = load_private_key(f.read(), root_passphrase)

    logger.info(
        "Generating Intermediate CA key pair (%s, %d bits)...",
        key_type.upper(),
        key_size,
    )
    inter_key = generate_key(key_type, key_size)
    logger.info("Intermediate CA key generation completed.")

    logger.info("Generating Intermediate CA CSR...")
    csr = generate_csr(
        inter_key, subject_str, is_ca=True, path_length=path_length
    )
    logger.info("Intermediate CA CSR generated for subject: %s", subject_str)

    csr_dir = os.path.join(out_dir, "csrs")
    os.makedirs(csr_dir, exist_ok=True)
    csr_path = os.path.join(csr_dir, "intermediate.csr.pem")
    with open(csr_path, "wb") as f:
        f.write(serialize_csr(csr))
    logger.info("CSR saved to %s", os.path.abspath(csr_path))

    logger.info("Root CA signing Intermediate CA certificate...")
    inter_cert = sign_intermediate_certificate(
        csr, root_key, root_cert, validity_days, path_length
    )
    logger.info(
        "Intermediate CA certificate signed. Serial: %s",
        format(inter_cert.serial_number, "X"),
    )

    key_pem = serialize_private_key(inter_key, passphrase)
    key_path = os.path.join(out_dir, "private", "intermediate.key.pem")
    save_private_key(key_pem, key_path)
    logger.info("Intermediate CA private key saved to %s", os.path.abspath(key_path))

    cert_pem = serialize_certificate(inter_cert)
    cert_path = os.path.join(out_dir, "certs", "intermediate.cert.pem")
    save_certificate(cert_pem, cert_path)
    logger.info(
        "Intermediate CA certificate saved to %s", os.path.abspath(cert_path)
    )

    _append_intermediate_policy(
        inter_cert, root_cert, key_type, key_size, path_length,
        os.path.join(out_dir, "policy.txt"),
    )
    logger.info("Policy document updated with Intermediate CA info.")
    logger.info("Intermediate CA issuance completed successfully.")


def _append_intermediate_policy(
    inter_cert,
    root_cert,
    key_type: str,
    key_size: int,
    path_length: int,
    policy_path: str,
) -> None:
    """Append Intermediate CA information to the policy document."""
    subject = inter_cert.subject.rfc4514_string()
    serial_hex = format(inter_cert.serial_number, "X")
    not_before = inter_cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = inter_cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    issuer = root_cert.subject.rfc4514_string()
    algo_label = f"{key_type.upper()}-{key_size}"

    section = (
        "\n"
        "========================================\n"
        "  Intermediate CA\n"
        "========================================\n"
        "\n"
        f"Subject DN: {subject}\n"
        f"Certificate Serial Number: {serial_hex}\n"
        f"Validity Period:\n"
        f"  Not Before: {not_before}\n"
        f"  Not After:  {not_after}\n"
        f"Key Algorithm and Size: {algo_label}\n"
        f"Path Length Constraint: {path_length}\n"
        f"Issuer (Root CA) DN: {issuer}\n"
    )

    with open(policy_path, "a", encoding="utf-8") as f:
        f.write(section)


def _safe_filename(subject_str: str) -> str:
    """Derive a safe filename from the CN of a subject DN."""
    dn = parse_subject_dn(subject_str)
    cn = dn.get("CN", "certificate")
    safe = re.sub(r"[^\w.\-]", "_", cn).strip("_")
    return safe if safe else "certificate"


def issue_certificate(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase: bytes,
    template_name: str,
    subject_str: str,
    san_strings: list[str],
    out_dir: str,
    validity_days: int,
    logger: logging.Logger,
) -> None:
    """Issue an end-entity certificate signed by the given CA."""
    template = get_template(template_name)

    parsed_san = parse_san_strings(san_strings) if san_strings else ParsedSAN()
    san_errors = validate_san_for_template(template, parsed_san)
    if san_errors:
        for err in san_errors:
            logger.error(err)
        raise ValueError("; ".join(san_errors))

    ca_cert = load_certificate(ca_cert_path)
    with open(ca_key_path, "rb") as f:
        ca_key = load_private_key(f.read(), ca_passphrase)

    key_type = "rsa"
    key_size = 2048
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    if isinstance(ca_key, _ec.EllipticCurvePrivateKey):
        key_type = "ecc"
        key_size = 256

    logger.info(
        "Generating end-entity key pair (%s, %d bits)...",
        key_type.upper(),
        key_size,
    )
    ee_key = generate_key(key_type, key_size)
    logger.info("End-entity key generation completed.")

    dn = parse_subject_dn(subject_str)
    subject_name = build_x509_name(dn)

    logger.info(
        "Issuing %s certificate for subject: %s",
        template_name,
        subject_str,
    )
    cert = sign_end_entity_certificate(
        public_key=ee_key.public_key(),
        subject_name=subject_name,
        ca_key=ca_key,
        ca_cert=ca_cert,
        template=template,
        parsed_san=parsed_san,
        validity_days=validity_days,
    )

    san_desc = ", ".join(san_strings) if san_strings else "none"
    logger.info(
        "Certificate issued. Serial: %s, Template: %s, Subject: %s, SANs: %s",
        format(cert.serial_number, "X"),
        template_name,
        subject_str,
        san_desc,
    )

    base_name = _safe_filename(subject_str)
    os.makedirs(out_dir, exist_ok=True)

    cert_path = os.path.join(out_dir, f"{base_name}.cert.pem")
    save_certificate(serialize_certificate(cert), cert_path)
    logger.info("Certificate saved to %s", os.path.abspath(cert_path))

    key_pem = serialize_private_key_unencrypted(ee_key)
    key_path = os.path.join(out_dir, f"{base_name}.key.pem")
    save_private_key(key_pem, key_path)
    logger.warning(
        "WARNING: End-entity private key saved UNENCRYPTED to %s",
        os.path.abspath(key_path),
    )

    logger.info("End-entity certificate issuance completed successfully.")
