"""
CRL Generation module for MicroPKI.

Builds X.509 CRL v2 files with standard extensions and revocation reason codes.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
import micropki.crypto_utils as cu
from micropki.revocation import get_reason_flag

logger = logging.getLogger(__name__)

def generate_crl(
    ca_name: str,
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase: str,
    out_dir: str,
    next_update_days: int,
    db,
    out_file: str = None
) -> str:
    """
    Generate a CRL for a given CA, sign it, and save it.
    
    Args:
        ca_name: "root", "intermediate", or custom string used for DB tracking.
        ca_cert_path: Path to CA cert.
        ca_key_path: Path to CA private key.
        ca_passphrase: Passphrase for CA private key.
        out_dir: The directory where crl/ subgroup will be created.
        next_update_days: Number of days valid.
        db: CertificateDatabase instance.
        out_file: Override for CRL output path (default is out_dir/crl/<ca_name>.crl.pem).
        
    Returns:
        Path to the generated CRL file.
    """
    logger.info("Starting CRL generation for CA: %s", ca_name)
    
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
        
    with open(ca_key_path, "rb") as f:
        ca_key_pem = f.read()
    ca_key = cu.load_private_key(ca_key_pem, ca_passphrase)
    
    # Subject of this CA to query db
    ca_subject_dn = ca_cert.subject.rfc4514_string()
    
    # Tracking next CRL number
    metadata = db.get_crl_metadata(ca_subject_dn)
    if metadata:
        crl_number = metadata["crl_number"] + 1
    else:
        crl_number = 1
        
    # Get all revoked certificates from this issuer
    revoked_certs_data = db.list_certificates(status="revoked", issuer=ca_subject_dn)
    
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=next_update_days)
    
    builder = builder.last_update(now)
    builder = builder.next_update(next_update)
    
    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False
    )
    
    # Find AKI from the CA cert. We can use SubjectKeyIdentifier if it exists
    # as the AuthorityKeyIdentifier for the CRL.
    try:
        ski_ext = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value),
            critical=False
        )
    except x509.ExtensionNotFound:
        pass
        
    count = 0
    for record in revoked_certs_data:
        serial_int = int(record["serial_hex"], 16)
        rev_date_iso = record.get("revocation_date")
        if rev_date_iso:
            try:
                # remove Z if present for fromisoformat compatibility or deal with naive parser
                if rev_date_iso.endswith("Z"):
                     rev_date_iso = rev_date_iso[:-1] + "+00:00"
                rev_date = datetime.fromisoformat(rev_date_iso).replace(tzinfo=timezone.utc)
            except ValueError:
                rev_date = now
        else:
            rev_date = now
            
        revoked_cert_builder = x509.RevokedCertificateBuilder()
        revoked_cert_builder = revoked_cert_builder.serial_number(serial_int)
        revoked_cert_builder = revoked_cert_builder.revocation_date(rev_date)
        
        reason_str = record.get("revocation_reason")
        if reason_str:
            try:
                reason_flag = get_reason_flag(reason_str)
                revoked_cert_builder = revoked_cert_builder.add_extension(
                    x509.CRLReason(reason_flag),
                    critical=False
                )
            except ValueError:
                logger.warning("Unknown revocation reason '%s' for serial %s, omitting extension.", reason_str, record["serial_hex"])
                
        revoked_cert = revoked_cert_builder.build()
        builder = builder.add_revoked_certificate(revoked_cert)
        count += 1
        
    # Choose hash according to key type
    if isinstance(ca_key, ec.EllipticCurvePrivateKey):
        hash_alg = hashes.SHA384()
    else:
        hash_alg = hashes.SHA256()

    crl = builder.sign(
        private_key=ca_key, algorithm=hash_alg
    )
    
    # Save to disk
    if out_file:
        crl_path = out_file
        crl_dir = os.path.dirname(os.path.abspath(crl_path))
        if crl_dir:
            os.makedirs(crl_dir, exist_ok=True)
    else:
        crl_dir = os.path.join(out_dir, "crl")
        os.makedirs(crl_dir, exist_ok=True)
        crl_path = os.path.join(crl_dir, f"{ca_name}.crl.pem")
        
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(encoding=serialization.Encoding.PEM))
        
    # Update metadata
    try:
        rel_crl_path = os.path.relpath(crl_path, start=out_dir)
    except ValueError:
        rel_crl_path = crl_path
        
    db.upsert_crl_metadata(
        ca_subject=ca_subject_dn,
        crl_number=crl_number,
        last_generated=now.isoformat(),
        next_update=next_update.isoformat(),
        crl_path=rel_crl_path
    )
    
    logger.info("CRL generation complete. CA: %s, Number: %d, Revoked Count: %d, Path: %s", ca_name, crl_number, count, crl_path)
    return crl_path
