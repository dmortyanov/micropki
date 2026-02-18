"""CLI argument parser for MicroPKI.

Provides the ``micropki`` entry point with the ``ca init`` subcommand.
Extensible for future subcommands (ca issue, ca revoke, etc.).
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

    init_parser = ca_sub.add_parser("init", help="Initialise a self-signed Root CA")

    init_parser.add_argument(
        "--subject", required=True,
        help="Distinguished Name (e.g., '/CN=My Root CA' or 'CN=My Root CA,O=Demo,C=US')",
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

    return parser


def validate_args(args: argparse.Namespace) -> list[str]:
    """Validate parsed arguments. Returns a list of error messages (empty = OK)."""
    errors: list[str] = []

    if not hasattr(args, "subject") or args.subject is None:
        return errors

    if not args.subject or not args.subject.strip():
        errors.append("--subject must be a non-empty string.")

    if args.key_size is None:
        args.key_size = 4096 if args.key_type == "rsa" else 384

    if args.key_type == "rsa" and args.key_size != 4096:
        errors.append(f"RSA key size must be 4096, got {args.key_size}.")
    elif args.key_type == "ecc" and args.key_size != 384:
        errors.append(f"ECC key size must be 384 (NIST P-384), got {args.key_size}.")

    pf = args.passphrase_file
    if not os.path.isfile(pf):
        errors.append(f"Passphrase file does not exist: {pf}")
    elif not os.access(pf, os.R_OK):
        errors.append(f"Passphrase file is not readable: {pf}")

    if args.validity_days is not None and args.validity_days <= 0:
        errors.append("--validity-days must be a positive integer.")

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


if __name__ == "__main__":
    sys.exit(main())
