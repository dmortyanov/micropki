"""Tests for certificate chain validation (TEST-7)."""

import datetime
import os

import pytest
from cryptography import x509

from micropki.certificates import load_certificate
from micropki.chain import ChainValidationError, validate_chain


class TestChainValidation:
    """TEST-7: Validate leaf → intermediate → root chain."""

    def test_valid_chain(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        root = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        intermediate = load_certificate(
            os.path.join(out_dir, "certs", "intermediate.cert.pem")
        )
        validate_chain([intermediate], root)

    def test_valid_three_level_chain_with_leaf(self, rsa_intermediate):
        """Issue a server cert and validate the full 3-level chain."""
        import logging
        from micropki.ca import issue_certificate

        out_dir, _, inter_pass = rsa_intermediate
        logger = logging.getLogger("test")

        issue_certificate(
            ca_cert_path=os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            ca_key_path=os.path.join(out_dir, "private", "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            template_name="server",
            subject_str="CN=example.com,O=TestOrg",
            san_strings=["dns:example.com"],
            out_dir=os.path.join(out_dir, "certs"),
            validity_days=365,
            logger=logger,
        )

        root = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        intermediate = load_certificate(
            os.path.join(out_dir, "certs", "intermediate.cert.pem")
        )
        leaf = load_certificate(
            os.path.join(out_dir, "certs", "example.com.cert.pem")
        )

        validate_chain([leaf, intermediate], root)

    def test_wrong_root_fails(self, rsa_intermediate, tmp_path):
        """Using a different root should fail signature verification."""
        import logging
        from micropki.ca import init_root_ca

        out_dir, _, _ = rsa_intermediate
        other_dir = str(tmp_path / "other_pki")
        logger = logging.getLogger("test")
        init_root_ca(
            subject_str="CN=Other Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase=b"other",
            out_dir=other_dir,
            validity_days=365,
            logger=logger,
        )
        wrong_root = load_certificate(
            os.path.join(other_dir, "certs", "ca.cert.pem")
        )
        intermediate = load_certificate(
            os.path.join(out_dir, "certs", "intermediate.cert.pem")
        )
        with pytest.raises(ChainValidationError, match="Signature verification failed"):
            validate_chain([intermediate], wrong_root)

    def test_expired_cert_fails(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        root = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        intermediate = load_certificate(
            os.path.join(out_dir, "certs", "intermediate.cert.pem")
        )
        future = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        with pytest.raises(ChainValidationError, match="expired"):
            validate_chain([intermediate], root, at_time=future)
