"""
Revocation module for MicroPKI.

Implements logic for revoking certificates, including mapping string reason
codes from CLI to RFC 5280 ASN.1 enumerations.
"""

import logging
from cryptography import x509
from typing import Optional

logger = logging.getLogger(__name__)

# Map string reason codes (case-insensitive in CLI, so map from lowercase strings) to x509.ReasonFlags
REASON_MAPPING = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keycompromise": x509.ReasonFlags.key_compromise,
    "cacompromise": x509.ReasonFlags.ca_compromise,
    "affiliationchanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
    "certificatehold": x509.ReasonFlags.certificate_hold,
    "removefromcrl": x509.ReasonFlags.remove_from_crl,
    "privilegewithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aacompromise": x509.ReasonFlags.aa_compromise
}

def get_reason_flag(reason_str: str) -> x509.ReasonFlags:
    """Map string reason to x509.ReasonFlags. Raise ValueError if invalid."""
    clean_reason = reason_str.lower()
    if clean_reason not in REASON_MAPPING:
        valid_reasons = ", ".join(REASON_MAPPING.keys())
        raise ValueError(f"Invalid revocation reason '{reason_str}'. Supported: {valid_reasons}")
    return REASON_MAPPING[clean_reason]

def revoke_certificate(db, serial_hex: str, reason_str: str = "unspecified") -> bool:
    """
    Revoke a certificate in the database.
    
    Args:
        db: CertificateDatabase instance.
        serial_hex: serial number in hex.
        reason_str: Revocation reason string.
        
    Returns:
        True if successfully revoked, False if it was already revoked.
    """
    # Just to validate reason string before DB hit
    get_reason_flag(reason_str)

    # update_certificate_status checks if it exists, raises ValueError if not.
    # Returns False if it is ALREADY revoked, True if successfully changed to revoked.
    updated = db.update_certificate_status(serial_hex, "revoked", reason_str)
    
    if updated:
        logger.info("Certificate %s revoked successfully with reason: %s", serial_hex, reason_str)
    else:
        logger.warning("Certificate %s is already revoked.", serial_hex)
        
    return updated
