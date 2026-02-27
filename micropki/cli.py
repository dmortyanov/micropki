"""CLI argument parser for MicroPKI.

Provides the ``micropki`` entry point with subcommands:
- ``ca init``              — create a self-signed Root CA
- ``ca issue-intermediate`` — create an Intermediate CA signed by Root
- ``ca issue-cert``         — issue an end-entity certificate
- ``ca validate-chain``     — validate a certificate chain
"""

from __future__ import annotations

import argparse
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI — a minimal Public Key Infrastructure tool.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    ca_parser = subparsers.add_parser("ca", help="Certificate Authority operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_action", help="CA actions")

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

    return 0


def _handle_ca_init(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import init_root_ca

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

    try:
        init_root_ca(
            subject_str=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=out_dir,
            validity_days=args.validity_days,
            logger=logger,
        )
    except Exception as exc:
        logger.error("CA initialisation failed: %s", exc)
        print(f"Error: CA initialisation failed.", file=sys.stderr)
        return 1

    return 0


def _handle_issue_intermediate(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import issue_intermediate_ca

    logger = setup_logging(getattr(args, "log_file", None))

    errors = validate_intermediate_args(args)
    if errors:
        for err in errors:
            logger.error(err)
            print(f"Error: {err}", file=sys.stderr)
        return 1

    root_passphrase = read_passphrase(args.root_pass_file)
    inter_passphrase = read_passphrase(args.passphrase_file)

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
        )
    except Exception as exc:
        logger.error("Intermediate CA issuance failed: %s", exc)
        print(f"Error: Intermediate CA issuance failed: {exc}", file=sys.stderr)
        return 1

    return 0


def _handle_issue_cert(args: argparse.Namespace) -> int:
    from .logger import setup_logging
    from .ca import issue_certificate

    logger = setup_logging(getattr(args, "log_file", None))

    errors = validate_issue_cert_args(args)
    if errors:
        for err in errors:
            logger.error(err)
            print(f"Error: {err}", file=sys.stderr)
        return 1

    ca_passphrase = read_passphrase(args.ca_pass_file)

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


if __name__ == "__main__":
    sys.exit(main())
