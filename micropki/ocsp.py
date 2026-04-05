"""
OCSP module for MicroPKI.

Implements RFC 6960 OCSP request parsing, certificate status determination,
and signed OCSP response generation.

Uses the ``cryptography`` library's ``x509.ocsp`` sub-package.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)

# OCSP Response status codes (RFC 6960 Section 4.2.1)
OCSP_RESPONSE_STATUS_SUCCESSFUL = 0
OCSP_RESPONSE_STATUS_MALFORMED_REQUEST = 1
OCSP_RESPONSE_STATUS_INTERNAL_ERROR = 2
OCSP_RESPONSE_STATUS_TRY_LATER = 3
OCSP_RESPONSE_STATUS_SIG_REQUIRED = 5
OCSP_RESPONSE_STATUS_UNAUTHORIZED = 6


def parse_ocsp_request(der_data: bytes) -> x509_ocsp.OCSPRequest:
    """Parse a DER-encoded OCSP request.

    Args:
        der_data: DER-encoded OCSP request bytes.

    Returns:
        Parsed OCSPRequest object.

    Raises:
        ValueError: If the request is malformed or cannot be parsed.
    """
    try:
        ocsp_req = x509_ocsp.load_der_ocsp_request(der_data)
    except Exception as exc:
        raise ValueError(f"Failed to parse OCSP request: {exc}") from exc

    return ocsp_req


def extract_request_nonce(ocsp_req: x509_ocsp.OCSPRequest) -> Optional[bytes]:
    """Extract the nonce extension from an OCSP request, if present.

    Returns:
        The nonce bytes, or None if no nonce extension is present.
    """
    try:
        nonce_ext = ocsp_req.extensions.get_extension_for_class(x509.OCSPNonce)
        return nonce_ext.value.nonce
    except x509.ExtensionNotFound:
        return None


def compute_issuer_hashes(
    ca_cert: x509.Certificate,
    hash_algo: hashes.HashAlgorithm = hashes.SHA1(),
) -> Tuple[bytes, bytes]:
    """Compute the issuer name hash and issuer key hash for a CA certificate.

    These values are used to match OCSP CertID fields against the configured CA.

    Args:
        ca_cert: The CA certificate.
        hash_algo: Hash algorithm (default: SHA-1 for OCSP compatibility).

    Returns:
        Tuple of (issuer_name_hash, issuer_key_hash).
    """
    # Issuer Name Hash: hash of the DER-encoded issuer Name
    issuer_name_der = ca_cert.subject.public_bytes()
    if isinstance(hash_algo, hashes.SHA1):
        name_hash = hashlib.sha1(issuer_name_der).digest()
    elif isinstance(hash_algo, hashes.SHA256):
        name_hash = hashlib.sha256(issuer_name_der).digest()
    else:
        name_hash = hashlib.sha1(issuer_name_der).digest()

    # Issuer Key Hash: hash of the BIT STRING value of the issuer's public key
    pub_key_der = ca_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Extract the actual key bits from SubjectPublicKeyInfo
    # The public key bytes in the SubjectPublicKeyInfo are what we need to hash
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw_pub_key = ca_cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    # For OCSP, we hash the BIT STRING content of subjectPublicKey
    # The cryptography library provides this via SubjectKeyIdentifier
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key())
    # SKI is the SHA-1 hash of the public key BIT STRING, which is exactly
    # what OCSP uses for issuer key hash when hash_algo is SHA-1
    if isinstance(hash_algo, hashes.SHA1):
        key_hash = ski.digest
    else:
        # For other algos, compute manually
        from pyasn1.codec.der import decoder as asn1_decoder
        key_hash = hashlib.sha256(raw_pub_key).digest()

    return name_hash, key_hash


def verify_issuer_match(
    ocsp_req: x509_ocsp.OCSPRequest,
    ca_cert: x509.Certificate,
) -> bool:
    """Verify that the OCSP request's CertID matches the configured CA.

    Compares issuer name hash and issuer key hash from the request
    against computed values from the CA certificate.

    Args:
        ocsp_req: Parsed OCSP request.
        ca_cert: The issuer CA certificate.

    Returns:
        True if the issuer in the request matches the CA, False otherwise.
    """
    # Get the hash algorithm used in the request
    req_hash_algo = ocsp_req.hash_algorithm

    # Compute expected hashes
    expected_name_hash, expected_key_hash = compute_issuer_hashes(ca_cert, req_hash_algo)

    # Compare with the request values
    return (
        ocsp_req.issuer_name_hash == expected_name_hash
        and ocsp_req.issuer_key_hash == expected_key_hash
    )


def determine_cert_status(
    db, serial_hex: str
) -> Tuple[str, Optional[datetime], Optional[str]]:
    """Determine the OCSP status of a certificate by querying the database.

    Args:
        db: CertificateDatabase instance (connected).
        serial_hex: Certificate serial number in hex.

    Returns:
        Tuple of (status, revocation_date, revocation_reason) where:
        - status is 'good', 'revoked', or 'unknown'
        - revocation_date is set only for revoked certificates
        - revocation_reason is set only for revoked certificates
    """
    record = db.get_certificate_by_serial(serial_hex)

    if record is None:
        return ("unknown", None, None)

    db_status = record.get("status", "unknown")

    if db_status == "valid":
        return ("good", None, None)
    elif db_status == "revoked":
        rev_date = None
        rev_date_str = record.get("revocation_date")
        if rev_date_str:
            try:
                if rev_date_str.endswith("Z"):
                    rev_date_str = rev_date_str[:-1] + "+00:00"
                rev_date = datetime.fromisoformat(rev_date_str)
                if rev_date.tzinfo is None:
                    rev_date = rev_date.replace(tzinfo=timezone.utc)
            except ValueError:
                rev_date = datetime.now(timezone.utc)
        else:
            rev_date = datetime.now(timezone.utc)

        rev_reason = record.get("revocation_reason", "unspecified")
        return ("revoked", rev_date, rev_reason)
    else:
        # expired or other — treat as good per RFC recommendation
        return ("good", None, None)


def _map_revocation_reason(reason_str: str) -> x509.ReasonFlags:
    """Map a string revocation reason to x509.ReasonFlags for OCSP response."""
    from .revocation import REASON_MAPPING
    clean = reason_str.lower()
    return REASON_MAPPING.get(clean, x509.ReasonFlags.unspecified)


def build_ocsp_response(
    target_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key: PrivateKeyTypes,
    cert_status: str,
    revocation_time: Optional[datetime] = None,
    revocation_reason: Optional[str] = None,
    nonce: Optional[bytes] = None,
    cache_ttl: int = 60,
) -> bytes:
    """Build a signed OCSP response.

    Args:
        target_cert: The certificate being queried (loaded from DB).
        ca_cert: The issuer CA certificate.
        responder_cert: The OCSP responder's signing certificate.
        responder_key: The OCSP responder's private key.
        cert_status: One of 'good', 'revoked', or 'unknown'.
        revocation_time: Revocation timestamp (required for 'revoked').
        revocation_reason: Revocation reason string (for 'revoked').
        nonce: Nonce bytes to echo (from the request), or None.
        cache_ttl: Cache TTL in seconds for nextUpdate.

    Returns:
        DER-encoded OCSP response bytes.
    """
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(seconds=cache_ttl)

    # Pick the hash algorithm for signing
    if isinstance(responder_key, rsa.RSAPrivateKey):
        sign_hash = hashes.SHA256()
    elif isinstance(responder_key, ec.EllipticCurvePrivateKey):
        sign_hash = hashes.SHA384()
    else:
        sign_hash = hashes.SHA256()

    # Build the response — cert and issuer must be x509.Certificate objects
    if cert_status == "good":
        builder = x509_ocsp.OCSPResponseBuilder().add_response(
            cert=target_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=x509_ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )
    elif cert_status == "revoked":
        reason_flag = None
        if revocation_reason:
            reason_flag = _map_revocation_reason(revocation_reason)

        builder = x509_ocsp.OCSPResponseBuilder().add_response(
            cert=target_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=x509_ocsp.OCSPCertStatus.REVOKED,
            this_update=now,
            next_update=next_update,
            revocation_time=revocation_time or now,
            revocation_reason=reason_flag,
        )
    else:
        # unknown — still need a cert object; use a synthetic approach
        builder = x509_ocsp.OCSPResponseBuilder().add_response(
            cert=target_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=x509_ocsp.OCSPCertStatus.UNKNOWN,
            this_update=now,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )

    # Add responder ID (by key hash for anonymity)
    builder = builder.responder_id(
        x509_ocsp.OCSPResponderEncoding.HASH, responder_cert
    )

    # Echo nonce if present (OCSP-4)
    if nonce is not None:
        builder = builder.add_extension(
            x509.OCSPNonce(nonce), critical=False
        )

    # Sign and encode
    response = builder.sign(responder_key, sign_hash)
    return response.public_bytes(serialization.Encoding.DER)


def build_error_response(status_code: int) -> bytes:
    """Build an OCSP error response (no BasicOCSPResponse body).

    Args:
        status_code: One of the OCSP response status codes:
            1 = malformedRequest
            2 = internalError
            3 = tryLater
            5 = sigRequired
            6 = unauthorized

    Returns:
        DER-encoded OCSP error response bytes.
    """
    status_map = {
        OCSP_RESPONSE_STATUS_MALFORMED_REQUEST: x509_ocsp.OCSPResponseStatus.MALFORMED_REQUEST,
        OCSP_RESPONSE_STATUS_INTERNAL_ERROR: x509_ocsp.OCSPResponseStatus.INTERNAL_ERROR,
        OCSP_RESPONSE_STATUS_TRY_LATER: x509_ocsp.OCSPResponseStatus.TRY_LATER,
        OCSP_RESPONSE_STATUS_SIG_REQUIRED: x509_ocsp.OCSPResponseStatus.SIG_REQUIRED,
        OCSP_RESPONSE_STATUS_UNAUTHORIZED: x509_ocsp.OCSPResponseStatus.UNAUTHORIZED,
    }

    resp_status = status_map.get(status_code, x509_ocsp.OCSPResponseStatus.INTERNAL_ERROR)
    response = x509_ocsp.OCSPResponseBuilder.build_unsuccessful(resp_status)
    return response.public_bytes(serialization.Encoding.DER)


def _build_unknown_cert_for_serial(
    serial_number: int,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    """Build a minimal synthetic certificate for 'unknown' OCSP responses.

    The cryptography library's OCSPResponseBuilder.add_response() requires
    actual Certificate objects. For unknown serials (not in DB), we create
    a minimal self-signed cert with the correct serial and issuer name
    so the response CertID matches the request.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    dummy_key = _rsa.generate_private_key(65537, 2048)
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "unknown")]))
        .issuer_name(ca_cert.subject)
        .public_key(dummy_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(dummy_key, hashes.SHA256())
    )
    return cert


def process_ocsp_request(
    der_data: bytes,
    db,
    ca_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key: PrivateKeyTypes,
    cache_ttl: int = 60,
) -> bytes:
    """Full OCSP request processing pipeline.

    Parses, validates, queries, and builds the signed response.

    Args:
        der_data: Raw DER-encoded OCSP request.
        db: CertificateDatabase instance (connected).
        ca_cert: The issuer CA certificate.
        responder_cert: The OCSP responder certificate.
        responder_key: The OCSP responder private key.
        cache_ttl: Cache TTL in seconds.

    Returns:
        DER-encoded OCSP response bytes.
    """
    # Step 1: Parse
    try:
        ocsp_req = parse_ocsp_request(der_data)
    except ValueError as exc:
        logger.error("Malformed OCSP request: %s", exc)
        return build_error_response(OCSP_RESPONSE_STATUS_MALFORMED_REQUEST)

    # Step 2: Extract nonce
    nonce = extract_request_nonce(ocsp_req)

    # Step 3: Verify issuer match
    if not verify_issuer_match(ocsp_req, ca_cert):
        logger.warning("OCSP request issuer mismatch — returning unauthorized")
        return build_error_response(OCSP_RESPONSE_STATUS_UNAUTHORIZED)

    # Step 4: Determine certificate status
    serial_number = ocsp_req.serial_number
    serial_hex = format(serial_number, "X")

    try:
        cert_status, rev_time, rev_reason = determine_cert_status(db, serial_hex)
    except Exception as exc:
        logger.error("Database error during OCSP status lookup: %s", exc)
        return build_error_response(OCSP_RESPONSE_STATUS_INTERNAL_ERROR)

    logger.info(
        "OCSP status for serial %s: %s", serial_hex, cert_status
    )

    # Step 5: Load the target certificate
    # For good/revoked: load from DB; for unknown: build a synthetic cert
    target_cert = None
    if cert_status in ("good", "revoked"):
        record = db.get_certificate_by_serial(serial_hex)
        if record and record.get("cert_pem"):
            try:
                target_cert = x509.load_pem_x509_certificate(
                    record["cert_pem"].encode("utf-8")
                )
            except Exception:
                pass

    if target_cert is None:
        # Unknown or failed to load — build synthetic cert for the response
        target_cert = _build_unknown_cert_for_serial(serial_number, ca_cert)
        if cert_status != "unknown":
            cert_status = "unknown"

    # Step 6: Build signed response
    try:
        response_der = build_ocsp_response(
            target_cert=target_cert,
            ca_cert=ca_cert,
            responder_cert=responder_cert,
            responder_key=responder_key,
            cert_status=cert_status,
            revocation_time=rev_time,
            revocation_reason=rev_reason,
            nonce=nonce,
            cache_ttl=cache_ttl,
        )
    except Exception as exc:
        logger.error("Failed to build OCSP response: %s", exc)
        return build_error_response(OCSP_RESPONSE_STATUS_INTERNAL_ERROR)

    return response_der
