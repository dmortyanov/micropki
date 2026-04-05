"""CLI argument parser for MicroPKI.

Provides the ``micropki`` entry point with subcommands:
- ``ca init``              — create a self-signed Root CA
- ``ca issue-intermediate`` — create an Intermediate CA signed by Root
- ``ca issue-cert``         — issue an end-entity certificate
- ``ca validate-chain``     — validate a certificate chain
- ``ca issue-ocsp-cert``   — issue an OCSP responder certificate (Sprint 5)
- ``ocsp serve``           — start the OCSP responder (Sprint 5)
"""

from __future__ import annotations

import argparse
import os
import sys

# Import database and repository modules for Sprint 3
from .database import CertificateDatabase
from .repository import RepositoryServer, RepositoryHandler
from .serial import SerialNumberGenerator
from .config import Config
from .config import Config
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI — a minimal Public Key Infrastructure tool.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- ca commands ---
    ca_parser = subparsers.add_parser("ca", help="Certificate Authority operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_action", help="CA actions")

    # --- db commands ---
    db_parser = subparsers.add_parser("db", help="Database operations")
    db_sub = db_parser.add_subparsers(dest="db_action", help="DB actions")

    db_init_parser = db_sub.add_parser("init", help="Initialize the certificate database")
    db_init_parser.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database file (default: ./pki/micropki.db)")
    db_init_parser.add_argument("--log-file", default=None, help="Path to a log file. If omitted, logs go to stderr")

    # --- repo commands ---
    repo_parser = subparsers.add_parser("repo", help="Certificate repository server")
    repo_sub = repo_parser.add_subparsers(dest="repo_action", help="Repository actions")

    repo_serve_parser = repo_sub.add_parser("serve", help="Start the HTTP repository server")
    repo_serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address for the server (default: 127.0.0.1)")
    repo_serve_parser.add_argument("--port", type=int, default=8080, help="TCP port for the server (default: 8080)")
    repo_serve_parser.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database (default: ./pki/micropki.db)")
    repo_serve_parser.add_argument("--cert-dir", default="./pki/certs", help="Directory containing PEM certificates (default: ./pki/certs)")
    repo_serve_parser.add_argument("--log-file", default=None, help="Path to a log file. If omitted, logs go to stderr")

    # --- repo status ---
    repo_status_parser = repo_sub.add_parser("status", help="Check whether the repository server is reachable")
    repo_status_parser.add_argument("--host", default="127.0.0.1", help="Host to check (default: 127.0.0.1)")
    repo_status_parser.add_argument("--port", type=int, default=8080, help="TCP port to check (default: 8080)")

    # --- ca init ---
    init_parser = ca_sub.add_parser("init", help="Initialise a self-signed Root CA")
    init_parser.add_argument(
        "--subject", required=True,
        help="Distinguished Name (e.g., 'CN=My Root CA,O=Demo,C=US')",
    )
    init_parser.add_argument(
        "--key-type", choices=["rsa", "ecc"], default="rsa",
        help="Key algorithm: rsa or ecc (default: rsa)",
    )
    init_parser.add_argument(
        "--key-size", type=int, default=None,
        help="Key size in bits. RSA must be 4096, ECC must be 384",
    )
    init_parser.add_argument(
        "--passphrase-file", required=True,
        help="Path to a file containing the passphrase for private key encryption",
    )
    init_parser.add_argument(
        "--out-dir", default="./pki",
        help="Output directory (default: ./pki)",
    )
    init_parser.add_argument(
        "--validity-days", type=int, default=3650,
        help="Validity period in days (default: 3650)",
    )
    init_parser.add_argument(
        "--log-file", default=None,
        help="Path to a log file. If omitted, logs go to stderr",
    )
    init_parser.add_argument(
        "--force", action="store_true",
        help="Overwrite existing files without confirmation",
    )

    # --- ca issue-intermediate ---
    inter_parser = ca_sub.add_parser(
        "issue-intermediate",
        help="Create an Intermediate CA signed by the Root CA",
    )
    inter_parser.add_argument("--root-cert", required=True, help="Root CA certificate (PEM)")
    inter_parser.add_argument("--root-key", required=True, help="Root CA encrypted private key (PEM)")
    inter_parser.add_argument("--root-pass-file", required=True, help="File with Root CA key passphrase")
    inter_parser.add_argument("--subject", required=True, help="Intermediate CA Distinguished Name")
    inter_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa", help="Key algorithm (default: rsa)")
    inter_parser.add_argument("--key-size", type=int, default=None, help="Key size: 4096 (RSA) or 384 (ECC)")
    inter_parser.add_argument("--passphrase-file", required=True, help="Passphrase file for Intermediate CA key")
    inter_parser.add_argument("--out-dir", default="./pki", help="Output directory (default: ./pki)")
    inter_parser.add_argument("--validity-days", type=int, default=1825, help="Validity period in days (default: 1825)")
    inter_parser.add_argument("--pathlen", type=int, default=0, help="Path length constraint (default: 0)")
    inter_parser.add_argument("--log-file", default=None, help="Log file path")

    # --- ca issue-cert ---
    cert_parser = ca_sub.add_parser(
        "issue-cert",
        help="Issue an end-entity certificate from a CA",
    )
    cert_parser.add_argument("--ca-cert", required=True, help="CA certificate (PEM)")
    cert_parser.add_argument("--ca-key", required=True, help="CA encrypted private key (PEM)")
    cert_parser.add_argument("--ca-pass-file", required=True, help="File with CA key passphrase")
    cert_parser.add_argument(
        "--template", required=True, choices=["server", "client", "code_signing"],
        help="Certificate template: server, client, or code_signing",
    )
    cert_parser.add_argument("--subject", required=True, help="Certificate Distinguished Name")
    cert_parser.add_argument("--san", action="append", default=[], help="SAN entry (e.g., dns:example.com). Repeatable.")
    cert_parser.add_argument("--csr", default=None, help="Path to an externally generated CSR (PEM). If provided, no new key pair is generated.")
    cert_parser.add_argument("--out-dir", default="./pki/certs", help="Output directory (default: ./pki/certs)")
    cert_parser.add_argument("--validity-days", type=int, default=365, help="Validity period in days (default: 365)")
    cert_parser.add_argument("--log-file", default=None, help="Log file path")

    # --- ca validate-chain ---
    val_parser = ca_sub.add_parser(
        "validate-chain",
        help="Validate a certificate chain (leaf → intermediate → root)",
    )
    val_parser.add_argument("--cert", required=True, help="Leaf certificate (PEM)")
    val_parser.add_argument("--intermediate", required=True, help="Intermediate CA certificate (PEM)")
    val_parser.add_argument("--root", required=True, help="Root CA certificate (PEM)")
    val_parser.add_argument("--log-file", default=None, help="Log file path")

    # --- ca list-certs ---
    list_parser = ca_sub.add_parser(
        "list-certs",
        help="List issued certificates from the database",
    )
    list_parser.add_argument(
        "--status",
        choices=["valid", "revoked", "expired"],
        default=None,
        help="Filter by certificate status",
    )
    list_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    # --- ca show-cert ---
    show_parser = ca_sub.add_parser(
        "show-cert",
        help="Fetch a certificate by serial number and print PEM",
    )
    show_parser.add_argument("serial", help="Certificate serial number in hex")
    show_parser.add_argument(
        "--format",
        choices=["pem"],
        default="pem",
        help="Output format (default: pem)",
    )

    # --- ca revoke ---
    revoke_parser = ca_sub.add_parser("revoke", help="Revoke a certificate")
    revoke_parser.add_argument("serial", help="Certificate serial number in hex")
    revoke_parser.add_argument("--reason", default="unspecified", help="Revocation reason code (default: unspecified)")
    revoke_parser.add_argument("--crl", help="Path to CRL file to update (optional)")
    revoke_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    # --- ca gen-crl ---
    gen_crl_parser = ca_sub.add_parser("gen-crl", help="Generate or regenerate a CRL")
    gen_crl_parser.add_argument("--ca", required=True, help="'root', 'intermediate', or path to CA cert")
    gen_crl_parser.add_argument("--next-update", type=int, default=7, help="Days until next CRL update (default: 7)")
    gen_crl_parser.add_argument("--out-file", help="Output file path (default: <out-dir>/crl/<ca>.crl.pem)")
    gen_crl_parser.add_argument("--out-dir", default="./pki", help="PKI base directory (default: ./pki)")
    gen_crl_parser.add_argument("--ca-pass-file", help="Passphrase file for CA key (overrides defaults)")

    # --- ca check-revoked ---
    check_parser = ca_sub.add_parser("check-revoked", help="Check revocation status of a certificate")
    check_parser.add_argument("serial", help="Certificate serial number in hex")

    # --- ca issue-ocsp-cert (Sprint 5) ---
    ocsp_cert_parser = ca_sub.add_parser(
        "issue-ocsp-cert",
        help="Issue an OCSP responder signing certificate",
    )
    ocsp_cert_parser.add_argument("--ca-cert", required=True, help="Issuing CA certificate (PEM)")
    ocsp_cert_parser.add_argument("--ca-key", required=True, help="Issuing CA encrypted private key (PEM)")
    ocsp_cert_parser.add_argument("--ca-pass-file", required=True, help="File with CA key passphrase")
    ocsp_cert_parser.add_argument("--subject", required=True, help="OCSP Responder Distinguished Name")
    ocsp_cert_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa", help="Key algorithm (default: rsa)")
    ocsp_cert_parser.add_argument("--key-size", type=int, default=2048, help="Key size (default: 2048)")
    ocsp_cert_parser.add_argument("--san", action="append", default=[], help="SAN entry (e.g., dns:ocsp.example.com). Repeatable.")
    ocsp_cert_parser.add_argument("--out-dir", default="./pki/certs", help="Output directory (default: ./pki/certs)")
    ocsp_cert_parser.add_argument("--validity-days", type=int, default=365, help="Validity period in days (default: 365)")
    ocsp_cert_parser.add_argument("--log-file", default=None, help="Log file path")

    # --- ocsp commands (Sprint 5) ---
    ocsp_parser = subparsers.add_parser("ocsp", help="OCSP responder operations")
    ocsp_sub = ocsp_parser.add_subparsers(dest="ocsp_action", help="OCSP actions")

    ocsp_serve_parser = ocsp_sub.add_parser("serve", help="Start the OCSP responder")
    ocsp_serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    ocsp_serve_parser.add_argument("--port", type=int, default=8081, help="TCP port (default: 8081)")
    ocsp_serve_parser.add_argument("--db-path", default="./pki/micropki.db", help="SQLite database path (default: ./pki/micropki.db)")
    ocsp_serve_parser.add_argument("--responder-cert", required=True, help="OCSP signing certificate (PEM)")
    ocsp_serve_parser.add_argument("--responder-key", required=True, help="OCSP signing private key (PEM, unencrypted)")
    ocsp_serve_parser.add_argument("--ca-cert", required=True, help="Issuer CA certificate (PEM)")
    ocsp_serve_parser.add_argument("--cache-ttl", type=int, default=60, help="Response cache TTL in seconds (default: 60)")
    ocsp_serve_parser.add_argument("--log-file", default=None, help="Log file path (default: stderr)")

    return parser


def validate_args(args: argparse.Namespace) -> list[str]:
    """Validate parsed arguments. Returns a list of error messages (empty = OK)."""
    errors: list[str] = []

    if not hasattr(args, "subject") or args.subject is None:
        return errors

    if not args.subject or not args.subject.strip():
        errors.append("--subject must be a non-empty string.")

    if hasattr(args, "key_size") and hasattr(args, "key_type"):
        if args.key_size is None:
            args.key_size = 4096 if args.key_type == "rsa" else 384

        if args.key_type == "rsa" and args.key_size != 4096:
            errors.append(f"RSA key size must be 4096, got {args.key_size}.")
        elif args.key_type == "ecc" and args.key_size != 384:
            errors.append(f"ECC key size must be 384 (NIST P-384), got {args.key_size}.")

    if hasattr(args, "passphrase_file") and args.passphrase_file:
        pf = args.passphrase_file
        if not os.path.isfile(pf):
            errors.append(f"Passphrase file does not exist: {pf}")
        elif not os.access(pf, os.R_OK):
            errors.append(f"Passphrase file is not readable: {pf}")

    if hasattr(args, "validity_days") and args.validity_days is not None:
        if args.validity_days <= 0:
            errors.append("--validity-days must be a positive integer.")

    return errors


def validate_intermediate_args(args: argparse.Namespace) -> list[str]:
    """Validate arguments for issue-intermediate."""
    errors = validate_args(args)

    for attr, label in [
        ("root_cert", "--root-cert"),
        ("root_key", "--root-key"),
        ("root_pass_file", "--root-pass-file"),
    ]:
        path = getattr(args, attr, None)
        if path and not os.path.isfile(path):
            errors.append(f"{label} file does not exist: {path}")

    if hasattr(args, "pathlen") and args.pathlen < 0:
        errors.append("--pathlen must be non-negative.")

    return errors


def validate_issue_cert_args(args: argparse.Namespace) -> list[str]:
    """Validate arguments for issue-cert."""
    errors: list[str] = []

    if not args.subject or not args.subject.strip():
        errors.append("--subject must be a non-empty string.")

    for attr, label in [
        ("ca_cert", "--ca-cert"),
        ("ca_key", "--ca-key"),
        ("ca_pass_file", "--ca-pass-file"),
    ]:
        path = getattr(args, attr, None)
        if path and not os.path.isfile(path):
            errors.append(f"{label} file does not exist: {path}")

    if hasattr(args, "validity_days") and args.validity_days <= 0:
        errors.append("--validity-days must be a positive integer.")

    csr_path = getattr(args, "csr", None)
    if csr_path and not os.path.isfile(csr_path):
        errors.append(f"--csr file does not exist: {csr_path}")

    return errors


def read_passphrase(path: str) -> bytes:
    """Read passphrase from file, stripping trailing newline."""
    with open(path, "rb") as f:
        data = f.read()
    return data.rstrip(b"\n").rstrip(b"\r\n")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``micropki`` CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "ca":
        if not hasattr(args, "ca_action") or args.ca_action is None:
            parser.parse_args(["ca", "--help"])
            return 1

        if args.ca_action == "init":
            return _handle_ca_init(args)
        elif args.ca_action == "issue-intermediate":
            return _handle_issue_intermediate(args)
        elif args.ca_action == "issue-cert":
            return _handle_issue_cert(args)
        elif args.ca_action == "validate-chain":
            return _handle_validate_chain(args)
        elif args.ca_action == "list-certs":
            return _handle_list_certs(args)
        elif args.ca_action == "show-cert":
            return _handle_show_cert(args)
        elif args.ca_action == "revoke":
            return _handle_ca_revoke(args)
        elif args.ca_action == "gen-crl":
            return _handle_ca_gen_crl(args)
        elif args.ca_action == "check-revoked":
            return _handle_ca_check_revoked(args)
        elif args.ca_action == "issue-ocsp-cert":
            return _handle_issue_ocsp_cert(args)

    elif args.command == "db":
        if not hasattr(args, "db_action") or args.db_action is None:
            parser.parse_args(["db", "--help"])
            return 1

        if args.db_action == "init":
            return _handle_db_init(args)

    elif args.command == "repo":
        if not hasattr(args, "repo_action") or args.repo_action is None:
            parser.parse_args(["repo", "--help"])
            return 1

        if args.repo_action == "serve":
            return _handle_repo_serve(args)
        elif args.repo_action == "status":
            return _handle_repo_status(args)

    elif args.command == "ocsp":
        if not hasattr(args, "ocsp_action") or args.ocsp_action is None:
            parser.parse_args(["ocsp", "--help"])
            return 1

        if args.ocsp_action == "serve":
            return _handle_ocsp_serve(args)

    return 0


def _handle_ca_init(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import init_root_ca
    from .serial import SerialNumberGenerator

    logger = setup_logging(args.log_file)

    errors = validate_args(args)
    if errors:
        for err in errors:
            logger.error(err)
            print(f"Error: {err}", file=sys.stderr)
        return 1

    out_dir = args.out_dir
    key_path = os.path.join(out_dir, "private", "ca.key.pem")
    cert_path = os.path.join(out_dir, "certs", "ca.cert.pem")

    if not args.force:
        for path in (key_path, cert_path):
            if os.path.exists(path):
                print(
                    f"Error: {path} already exists. Use --force to overwrite.",
                    file=sys.stderr,
                )
                logger.error("File already exists: %s. Use --force to overwrite.", path)
                return 1

    passphrase = read_passphrase(args.passphrase_file)

    # Create a serial number generator (Sprint 3)
    # Use a persistent counter stored in the DB to guarantee uniqueness across runs.
    db_path = os.path.join(out_dir, "micropki.db")
    serial_gen = SerialNumberGenerator(db_path=db_path)

    try:
        init_root_ca(
            subject_str=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=out_dir,
            validity_days=args.validity_days,
            logger=logger,
            serial_generator=serial_gen
        )
    except Exception as exc:
        logger.error("CA initialisation failed: %s", exc)
        print(f"Error: CA initialisation failed.", file=sys.stderr)
        return 1

    return 0


def _handle_issue_intermediate(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import issue_intermediate_ca
    from .serial import SerialNumberGenerator

    logger = setup_logging(getattr(args, "log_file", None))

    errors = validate_intermediate_args(args)
    if errors:
        for err in errors:
            logger.error(err)
            print(f"Error: {err}", file=sys.stderr)
        return 1

    root_passphrase = read_passphrase(args.root_pass_file)
    inter_passphrase = read_passphrase(args.passphrase_file)

    # Persistent serial generator (Sprint 3)
    db_path = os.path.join(args.out_dir, "micropki.db")
    serial_gen = SerialNumberGenerator(db_path=db_path)

    try:
        issue_intermediate_ca(
            root_cert_path=args.root_cert,
            root_key_path=args.root_key,
            root_passphrase=root_passphrase,
            subject_str=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=inter_passphrase,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            path_length=args.pathlen,
            logger=logger,
            serial_generator=serial_gen
        )
    except Exception as exc:
        logger.error("Intermediate CA issuance failed: %s", exc)
        print(f"Error: Intermediate CA issuance failed: {exc}", file=sys.stderr)
        return 1

    return 0


def _handle_issue_cert(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import issue_certificate
    from .serial import SerialNumberGenerator

    logger = setup_logging(getattr(args, "log_file", None))

    errors = validate_issue_cert_args(args)
    if errors:
        for err in errors:
            logger.error(err)
            print(f"Error: {err}", file=sys.stderr)
        return 1

    ca_passphrase = read_passphrase(args.ca_pass_file)

    # Persistent serial generator (Sprint 3)
    # Leaf certificates are written to .../certs, while DB is in the parent folder.
    db_root = os.path.dirname(args.out_dir) if args.out_dir else "./pki"
    db_path = os.path.join(db_root, "micropki.db")
    serial_gen = SerialNumberGenerator(db_path=db_path)

    try:
        issue_certificate(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_passphrase,
            template_name=args.template,
            subject_str=args.subject,
            san_strings=args.san,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            logger=logger,
            csr_path=getattr(args, "csr", None),
            serial_generator=serial_gen
        )
    except Exception as exc:
        logger.error("Certificate issuance failed: %s", exc)
        print(f"Error: Certificate issuance failed: {exc}", file=sys.stderr)
        return 1

    return 0


def _handle_validate_chain(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .certificates import load_certificate
    from .chain import validate_chain, ChainValidationError

    logger = setup_logging(getattr(args, "log_file", None))

    try:
        leaf = load_certificate(args.cert)
        intermediate = load_certificate(args.intermediate)
        root = load_certificate(args.root)
    except Exception as exc:
        logger.error("Failed to load certificates: %s", exc)
        print(f"Error: Failed to load certificates: {exc}", file=sys.stderr)
        return 1

    try:
        validate_chain([leaf, intermediate], root)
    except ChainValidationError as exc:
        logger.error("Chain validation FAILED: %s", exc)
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    msg = "Chain validation PASSED: leaf → intermediate → root"
    logger.info(msg)
    print(msg)
    return 0


def _get_default_db_path() -> str:
    """Default DB path for Sprint 3 certificate repository commands."""
    cfg = Config()
    return cfg.get("database.path", "./pki/micropki.db")


def _handle_db_init(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .database import CertificateDatabase

    logger = setup_logging(args.log_file)

    try:
        db = CertificateDatabase(args.db_path)
        db.connect()
        db.init_schema()
        db.close()
        logger.info("Database initialized: %s", args.db_path)
        return 0
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc)
        print(f"Error: Database initialization failed.", file=sys.stderr)
        return 1


def _handle_list_certs(args: argparse.Namespace) -> int:
    from .database import CertificateDatabase

    db_path = _get_default_db_path()
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()

    try:
        records = db.list_certificates(status=args.status)
        if args.format == "json":
            import json

            print(json.dumps(records, ensure_ascii=False, indent=2))
        elif args.format == "csv":
            import csv
            import sys as _sys

            writer = csv.writer(_sys.stdout)
            writer.writerow(
                ["serial_hex", "subject", "issuer", "not_before", "not_after", "status"]
            )
            for r in records:
                writer.writerow(
                    [
                        r.get("serial_hex"),
                        r.get("subject"),
                        r.get("issuer"),
                        r.get("not_before"),
                        r.get("not_after"),
                        r.get("status"),
                    ]
                )
        else:
            # table (default)
            headers = ["serial_hex", "subject", "not_after", "status"]
            print(" | ".join(headers))
            print("-" * 90)
            for r in records:
                row = [
                    str(r.get("serial_hex", "")),
                    str(r.get("subject", "")),
                    str(r.get("not_after", "")),
                    str(r.get("status", "")),
                ]
                print(" | ".join(row))
        return 0
    finally:
        db.close()


def _handle_show_cert(args: argparse.Namespace) -> int:
    from .database import CertificateDatabase

    db_path = _get_default_db_path()
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()

    try:
        serial_hex = args.serial
        if not isinstance(serial_hex, str) or not serial_hex.strip():
            print("Error: serial must be provided.", file=sys.stderr)
            return 1

        if not all(c in "0123456789abcdefABCDEF" for c in serial_hex):
            print("Error: serial must be a hex string.", file=sys.stderr)
            return 1

        record = db.get_certificate_by_serial(serial_hex)
        if not record:
            print("Error: certificate not found.", file=sys.stderr)
            return 1

        # Sprint 3: print PEM content to stdout.
        print(record["cert_pem"])
        return 0
    finally:
        db.close()


def _handle_repo_serve(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .repository import RepositoryServer

    logger = setup_logging(args.log_file)
    try:
        audit_log_path = f"{args.log_file}.jsonl" if getattr(args, "log_file", None) else None
        server = RepositoryServer(
            host=args.host,
            port=args.port,
            db_path=args.db_path,
            cert_dir=args.cert_dir,
            audit_log_path=audit_log_path,
        )
        server.start()
        return 0
    except KeyboardInterrupt:
        logger.info("Repository server stopped (KeyboardInterrupt).")
        return 0


def _handle_repo_status(args: argparse.Namespace) -> int:
    import socket

    try:
        with socket.create_connection((args.host, args.port), timeout=1):
            print(f"Repository is running at {args.host}:{args.port}")
            return 0
    except OSError:
        print(f"Repository is NOT running at {args.host}:{args.port}")
        return 1


def _handle_ca_revoke(args: argparse.Namespace) -> int:
    from .database import CertificateDatabase
    from .revocation import revoke_certificate

    db_path = _get_default_db_path()
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()

    try:
        if not args.force:
            ans = input(f"Are you sure you want to revoke certificate {args.serial}? [y/N]: ")
            if ans.lower() != 'y':
                print("Operation cancelled.")
                return 0
                
        revoked = revoke_certificate(db, args.serial, args.reason)
        if revoked:
            print(f"Successfully revoked {args.serial} with reason '{args.reason}'.")
        else:
            print(f"Warning: {args.serial} is already revoked. No changes made.")
            
        # Technically we should also auto-update CRL if --crl is set, but out of scope for basic Sprint 4 requirements.
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error connecting or revoking: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def _handle_ca_gen_crl(args: argparse.Namespace) -> int:
    from .database import CertificateDatabase
    from .crl import generate_crl

    db_path = _get_default_db_path()
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()

    try:
        out_dir = args.out_dir
        
        ca_name = args.ca.lower()
        if ca_name == "root":
            ca_cert_path = os.path.join(out_dir, "certs", "ca.cert.pem")
            ca_key_path = os.path.join(out_dir, "private", "ca.key.pem")
            ca_pass_file = args.ca_pass_file or os.path.join(out_dir, "secrets", "ca.pass")
        elif ca_name == "intermediate":
            ca_cert_path = os.path.join(out_dir, "certs", "intermediate.cert.pem")
            ca_key_path = os.path.join(out_dir, "private", "intermediate.key.pem")
            ca_pass_file = args.ca_pass_file or os.path.join(out_dir, "secrets", "intermediate.pass")
        else:
            # Assume passing exact path to CA cert, guessing the key
            ca_cert_path = args.ca
            ca_key_path = args.ca.replace(".cert.pem", ".key.pem").replace("certs", "private")
            ca_pass_file = args.ca_pass_file
            ca_name = "custom"

        if not os.path.isfile(ca_cert_path) or not os.path.isfile(ca_key_path):
            print(f"Error: Could not locate CA cert/key for '{args.ca}'", file=sys.stderr)
            return 1

        if not ca_pass_file or not os.path.isfile(ca_pass_file):
            print(f"Error: Could not locate pass file for '{args.ca}'", file=sys.stderr)
            return 1
            
        passphrase = read_passphrase(ca_pass_file)
        
        crl_path = generate_crl(
            ca_name=args.ca,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            ca_passphrase=passphrase,
            out_dir=out_dir,
            next_update_days=args.next_update,
            db=db,
            out_file=args.out_file
        )
        print(f"CRL generated at {crl_path}")
        return 0
    except Exception as e:
        print(f"Error generating CRL: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def _handle_ca_check_revoked(args: argparse.Namespace) -> int:
    from .database import CertificateDatabase
    
    db_path = _get_default_db_path()
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()
    
    try:
        record = db.get_certificate_by_serial(args.serial)
        if not record:
            print(f"Certificate {args.serial} not found in database.", file=sys.stderr)
            return 1
            
        status = record.get("status")
        if status == "revoked":
            reason = record.get("revocation_reason", "unspecified")
            date = record.get("revocation_date", "unknown")
            print(f"Certificate {args.serial} is REVOKED since {date} (Reason: {reason})")
            return 2 # special exit code for revoked
        else:
            print(f"Certificate {args.serial} is {status.upper()}")
            return 0
    except Exception as e:
        print(f"Error checking status: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def _handle_issue_ocsp_cert(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import issue_ocsp_certificate
    from .serial import SerialNumberGenerator

    logger = setup_logging(getattr(args, "log_file", None))

    # Validate file paths
    for attr, label in [
        ("ca_cert", "--ca-cert"),
        ("ca_key", "--ca-key"),
        ("ca_pass_file", "--ca-pass-file"),
    ]:
        path = getattr(args, attr, None)
        if path and not os.path.isfile(path):
            logger.error("%s file does not exist: %s", label, path)
            print(f"Error: {label} file does not exist: {path}", file=sys.stderr)
            return 1

    ca_passphrase = read_passphrase(args.ca_pass_file)

    db_root = os.path.dirname(args.out_dir) if args.out_dir else "./pki"
    db_path = os.path.join(db_root, "micropki.db")
    serial_gen = SerialNumberGenerator(db_path=db_path)

    try:
        issue_ocsp_certificate(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_passphrase,
            subject_str=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            logger=logger,
            san_strings=args.san if args.san else None,
            serial_generator=serial_gen,
        )
    except Exception as exc:
        logger.error("OCSP certificate issuance failed: %s", exc)
        print(f"Error: OCSP certificate issuance failed: {exc}", file=sys.stderr)
        return 1

    return 0


def _handle_ocsp_serve(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ocsp_responder import OCSPServer

    logger = setup_logging(getattr(args, "log_file", None))

    # Validate file paths
    for attr, label in [
        ("responder_cert", "--responder-cert"),
        ("responder_key", "--responder-key"),
        ("ca_cert", "--ca-cert"),
    ]:
        path = getattr(args, attr, None)
        if path and not os.path.isfile(path):
            logger.error("%s file does not exist: %s", label, path)
            print(f"Error: {label} file does not exist: {path}", file=sys.stderr)
            return 1

    try:
        server = OCSPServer(
            host=args.host,
            port=args.port,
            db_path=args.db_path,
            responder_cert_path=args.responder_cert,
            responder_key_path=args.responder_key,
            ca_cert_path=args.ca_cert,
            cache_ttl=args.cache_ttl,
            log_file=getattr(args, "log_file", None),
        )
        server.start()
        return 0
    except KeyboardInterrupt:
        logger.info("OCSP responder stopped (KeyboardInterrupt).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
