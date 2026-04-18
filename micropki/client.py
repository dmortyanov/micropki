import argparse
import logging
import os
import sys
import json
import requests
from datetime import timezone

from cryptography import x509

from micropki.crypto_utils import generate_key, parse_subject_dn, serialize_private_key_unencrypted
from micropki.csr import generate_csr, serialize_csr, load_csr
from micropki.certificates import load_certificate
from micropki.chain import validate_chain, ChainValidationError
from micropki.revocation_check import check_status

logger = logging.getLogger(__name__)

def handle_client_gen_csr(args: argparse.Namespace) -> int:
    logger.info("Generating key pair (%s, %d bits) for CSR...", args.key_type.upper(), args.key_size)
    try:
        private_key = generate_key(args.key_type, args.key_size)
    except ValueError as e:
        logger.error("Failed to generate key: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1
        
    logger.info("Generating CSR for subject: %s", args.subject)
    
    # Parse SANs if provided
    # The requirement is "--san dns:app.example.com", same format as Sprint 2
    # But generate_csr accepts subject_str, is_ca, path_length, and standard cryptography extensions are added inside if we pass parsed_san?
    # Wait, `generate_csr` in micropki/csr.py just takes (private_key, subject_str, is_ca, path_length).
    # Let's import from templates and manually create SAN extension if needed? Or modify `csr.py`?
    # Let's look at `generate_csr` in `csr.py` shortly. We will pass san_strings manually or update `generate_csr`.
    # Let's import templates to build parsed san
    from micropki.templates import parse_san_strings, build_san_extension
    parsed_san = parse_san_strings(args.san) if args.san else None
    
    from cryptography.x509.oid import NameOID
    from micropki.certificates import build_x509_name
    subject_name = build_x509_name(parse_subject_dn(args.subject))
    
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)
    if parsed_san:
        san_ext = build_san_extension(parsed_san)
        if san_ext is not None:
             builder = builder.add_extension(san_ext, critical=False)
             
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    if isinstance(private_key, rsa.RSAPrivateKey):
        sign_hash = hashes.SHA256()
    else:
        sign_hash = hashes.SHA384()
        
    csr = builder.sign(private_key, sign_hash)
    
    out_key_path = args.out_key
    out_csr_path = args.out_csr
    
    os.makedirs(os.path.dirname(os.path.abspath(out_key_path)) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(out_csr_path)) or ".", exist_ok=True)
    
    key_pem = serialize_private_key_unencrypted(private_key)
    with open(out_key_path, "wb") as f:
        f.write(key_pem)
        
    # Attempt to set 600 permissions if supported
    try:
        os.chmod(out_key_path, 0o600)
    except Exception:
        pass
        
    print(f"WARNING: Private key saved UNENCRYPTED to {out_key_path}", file=sys.stderr)
    logger.warning("Private key saved UNENCRYPTED with 0600 permissions to %s", out_key_path)
    
    csr_pem = serialize_csr(csr)
    with open(out_csr_path, "wb") as f:
        f.write(csr_pem)
        
    logger.info("CSR saved to %s", out_csr_path)
    print("CSR and private key generated successfully.")
    
    return 0


def handle_client_request_cert(args: argparse.Namespace) -> int:
    csr_path = args.csr
    template = args.template
    ca_url = args.ca_url.rstrip("/")
    out_cert_path = args.out_cert
    
    if not os.path.isfile(csr_path):
        print(f"Error: CSR file not found: {csr_path}", file=sys.stderr)
        return 1
        
    with open(csr_path, "rb") as f:
        csr_data = f.read()
        
    url = f"{ca_url}/request-cert?template={template}"
    logger.info("Submitting CSR to %s", url)
    
    try:
        resp = requests.post(
            url,
            data=csr_data,
            headers={"Content-Type": "application/x-pem-file", "X-API-Key": "changeme"},
            timeout=10,
        )
        if resp.status_code == 201:
            cert_pem = resp.content
            os.makedirs(os.path.dirname(os.path.abspath(out_cert_path)) or ".", exist_ok=True)
            with open(out_cert_path, "wb") as f:
                f.write(cert_pem)
            logger.info("Certificate successfully received and saved to %s", out_cert_path)
            print(f"Certificate successfully requested and saved to {out_cert_path}")
            return 0
        else:
            logger.error("HTTP %d: %s", resp.status_code, resp.text)
            print(f"Error requesting certificate: {resp.status_code} - {resp.text}", file=sys.stderr)
            return 1
    except Exception as exc:
        logger.error("Failed to connect to CA repository: %s", exc)
        print(f"Error connecting to CA: {exc}", file=sys.stderr)
        return 1


def handle_client_validate(args: argparse.Namespace) -> int:
    try:
        leaf = load_certificate(args.cert)
        
        untrusted_certs = []
        if args.untrusted:
            for p in args.untrusted:
                if os.path.isfile(p):
                    # We may need to load multiple certs if bundled
                    from micropki.crypto_utils import load_certificates_from_pem
                    untrusted_certs.extend(load_certificates_from_pem(p))
                    
        trusted_certs = []
        if args.trusted:
            from micropki.crypto_utils import load_certificates_from_pem
            trusted_certs.extend(load_certificates_from_pem(args.trusted))
            
    except Exception as exc:
        logger.error("Failed to load certificates: %s", exc)
        print(f"Error: Failed to load certificates: {exc}", file=sys.stderr)
        return 1

    # Attempt to build chain from leaf to trusted root using untrusted
    # We will do a simple chain builder here
    chain = []
    current_cert = leaf
    
    # Very simplified path builder
    while True:
        # Check if current_cert is issued by any trusted root
        root = next((c for c in trusted_certs if current_cert.issuer == c.subject), None)
        if root:
            # We found a trusted root!
            # It could also be self-signed leaf, but let's assume PKI.
            break
            
        # Look in untrusted
        intermediate = next((c for c in untrusted_certs if current_cert.issuer == c.subject), None)
        if intermediate:
            # Avoid loop
            if intermediate.subject == current_cert.subject:
                print("Error: Chain loop detected or root not in trusted store.", file=sys.stderr)
                return 1
            chain.append(intermediate)
            current_cert = intermediate
        else:
            print("Error: Could not build chain to a trusted root.", file=sys.stderr)
            return 1
            
    if not root:
         print("Error: Trusted root not found for chain.", file=sys.stderr)
         return 1

    # Now we have chain: [intermediate1, intermediate2] and a root
    # validate_chain expects [leaf, intermediate1, ...]
    full_path = [leaf] + chain
    
    try:
        validate_chain(full_path, root)
    except ChainValidationError as exc:
        logger.error("Path validation FAILED: %s", exc)
        print(f"FAIL: Path validation: {exc}", file=sys.stderr)
        return 1
        
    print("Path validation: OK")
    
    if args.mode == "full":
         # Check revocation for the leaf cert
         issuer = chain[0] if chain else root
         
         status, reason, dt = check_status(
             cert=leaf,
             issuer=issuer,
             crl_path_or_url=args.crl,
             ocsp_url=getattr(args, "ocsp", None) if getattr(args, "ocsp_url", None) else None
         )
         
         if status == "revoked":
             dt_str = dt.isoformat() if dt else "unknown"
             print(f"FAIL: Certificate is REVOKED since {dt_str} (reason: {reason})", file=sys.stderr)
             return 1
         elif status == "good":
             print("Revocation check: OK (good)")
         else:
             print("Warning: Revocation status is UNKNOWN.")
             
    print("Certificate validation completed successfully.")
    return 0


def handle_client_check_status(args: argparse.Namespace) -> int:
    try:
        cert = load_certificate(args.cert)
        ca_cert = load_certificate(args.ca_cert)
    except Exception as exc:
        logger.error("Failed to load certificates for status check: %s", exc)
        print(f"Error loading certificates: {exc}", file=sys.stderr)
        return 1
        
    status, reason, dt = check_status(
        cert=cert,
        issuer=ca_cert,
        crl_path_or_url=args.crl,
        ocsp_url=args.ocsp_url
    )
    
    if status == "revoked":
        dt_str = dt.isoformat() if dt else "unknown time"
        print(f"Status: REVOKED (Reason: {reason}, Date: {dt_str})")
        return 2
    elif status == "good":
        print("Status: GOOD")
        return 0
    else:
        print("Status: UNKNOWN")
        return 0
