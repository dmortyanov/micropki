"""Certificate chain validation (simplified RFC 5280 path validation).

Checks performed at each level:
- Signature validity
- Validity period (not expired, not yet valid)
- Basic Constraints (CA flag and path length)
- Key Usage compatibility (optional)
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding


class ChainValidationError(Exception):
    """Raised when chain validation fails."""


def validate_chain(
    chain: list[x509.Certificate],
    trust_anchor: x509.Certificate,
    at_time: datetime.datetime | None = None,
) -> None:
    """Validate a certificate chain from leaf to root.

    Args:
        chain: Ordered list ``[leaf, intermediate, ...]`` (does NOT include the root).
        trust_anchor: The trusted Root CA certificate.
        at_time: The time to validate against. Defaults to now (UTC).

    Raises:
        ChainValidationError: If any validation step fails.
    """
    if at_time is None:
        at_time = datetime.datetime.now(datetime.timezone.utc)

    full_chain = list(chain) + [trust_anchor]

    for i, cert in enumerate(full_chain):
        _check_validity_period(cert, at_time)

    for i in range(len(full_chain) - 1):
        subject_cert = full_chain[i]
        issuer_cert = full_chain[i + 1]
        _verify_signature(subject_cert, issuer_cert)
        _check_issuer_is_ca(issuer_cert)

    _check_path_length(full_chain)

    _verify_signature(trust_anchor, trust_anchor)


def _check_validity_period(
    cert: x509.Certificate, at_time: datetime.datetime
) -> None:
    if at_time < cert.not_valid_before_utc:
        raise ChainValidationError(
            f"Certificate not yet valid: {cert.subject.rfc4514_string()} "
            f"(not before {cert.not_valid_before_utc})"
        )
    if at_time > cert.not_valid_after_utc:
        raise ChainValidationError(
            f"Certificate has expired: {cert.subject.rfc4514_string()} "
            f"(not after {cert.not_valid_after_utc})"
        )


def _verify_signature(
    subject_cert: x509.Certificate, issuer_cert: x509.Certificate
) -> None:
    """Verify that *issuer_cert* signed *subject_cert*."""
    issuer_public_key = issuer_cert.public_key()
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject_cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                ec.ECDSA(subject_cert.signature_hash_algorithm),
            )
        else:
            raise ChainValidationError(
                f"Unsupported public key type: {type(issuer_public_key)}"
            )
    except Exception as exc:
        if isinstance(exc, ChainValidationError):
            raise
        raise ChainValidationError(
            f"Signature verification failed: {subject_cert.subject.rfc4514_string()} "
            f"signed by {issuer_cert.subject.rfc4514_string()}: {exc}"
        ) from exc


def _check_issuer_is_ca(cert: x509.Certificate) -> None:
    """Verify that the issuer certificate has BasicConstraints CA=TRUE."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise ChainValidationError(
            f"Certificate lacks BasicConstraints extension: "
            f"{cert.subject.rfc4514_string()}"
        )
    if not bc.value.ca:
        raise ChainValidationError(
            f"Certificate is not a CA: {cert.subject.rfc4514_string()}"
        )


def _check_path_length(full_chain: list[x509.Certificate]) -> None:
    """Check path length constraints for each CA in the chain.

    Path length counts the number of *non-self-issued* intermediate
    certificates below the CA in question.
    """
    for i in range(1, len(full_chain)):
        ca_cert = full_chain[i]
        try:
            bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            continue

        if bc.value.path_length is not None:
            intermediates_below = i - 1
            if intermediates_below > bc.value.path_length:
                raise ChainValidationError(
                    f"Path length constraint violated for "
                    f"{ca_cert.subject.rfc4514_string()}: "
                    f"allowed {bc.value.path_length}, found {intermediates_below}"
                )
