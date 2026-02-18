"""Root CA initialisation logic.

Orchestrates key generation, certificate creation, key storage,
policy document writing, and logging.
"""

from __future__ import annotations

import datetime
import logging
import os

from .certificates import create_self_signed_cert, serialize_certificate, save_certificate
from .crypto_utils import generate_key, serialize_private_key, save_private_key


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
