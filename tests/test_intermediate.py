"""Integration tests for Intermediate CA and end-entity certificate issuance.

Covers PKI-6..PKI-11, KEY-5..KEY-7, TEST-7..TEST-12.
"""

import logging
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from micropki.ca import issue_certificate, issue_intermediate_ca
from micropki.certificates import load_certificate
from micropki.crypto_utils import load_private_key


class TestIntermediateCA:
    """PKI-6, PKI-7: Intermediate CSR generation and Root signing."""

    def test_intermediate_files_exist(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        assert os.path.isfile(os.path.join(out_dir, "certs", "intermediate.cert.pem"))
        assert os.path.isfile(os.path.join(out_dir, "private", "intermediate.key.pem"))
        assert os.path.isfile(os.path.join(out_dir, "csrs", "intermediate.csr.pem"))

    def test_intermediate_basic_constraints(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        cert = load_certificate(os.path.join(out_dir, "certs", "intermediate.cert.pem"))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length == 0

    def test_intermediate_key_usage(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        cert = load_certificate(os.path.join(out_dir, "certs", "intermediate.cert.pem"))
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_intermediate_issuer_is_root(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        root = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        inter = load_certificate(os.path.join(out_dir, "certs", "intermediate.cert.pem"))
        assert inter.issuer == root.subject

    def test_intermediate_ski_and_aki(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        root = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        inter = load_certificate(os.path.join(out_dir, "certs", "intermediate.cert.pem"))

        root_ski = root.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        inter_aki = inter.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )
        assert inter_aki.value.key_identifier == root_ski.value.digest

    def test_intermediate_key_encrypted(self, rsa_intermediate, inter_passphrase):
        out_dir, _, _ = rsa_intermediate
        key_pem = open(
            os.path.join(out_dir, "private", "intermediate.key.pem"), "rb"
        ).read()
        assert b"ENCRYPTED" in key_pem
        key = load_private_key(key_pem, inter_passphrase)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_wrong_passphrase_fails(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        key_pem = open(
            os.path.join(out_dir, "private", "intermediate.key.pem"), "rb"
        ).read()
        with pytest.raises(Exception):
            load_private_key(key_pem, b"wrong-passphrase")

    def test_policy_updated(self, rsa_intermediate):
        out_dir, _, _ = rsa_intermediate
        policy = open(os.path.join(out_dir, "policy.txt"), encoding="utf-8").read()
        assert "Intermediate CA" in policy
        assert "Test Intermediate CA" in policy
        assert "Path Length Constraint: 0" in policy


class TestEndEntityCertificates:
    """PKI-8..PKI-11: End-entity certificate issuance."""

    def _issue(self, rsa_intermediate, template, subject, san_strings):
        out_dir, _, inter_pass = rsa_intermediate
        logger = logging.getLogger("test")
        issue_certificate(
            ca_cert_path=os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            ca_key_path=os.path.join(out_dir, "private", "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            template_name=template,
            subject_str=subject,
            san_strings=san_strings,
            out_dir=os.path.join(out_dir, "certs"),
            validity_days=365,
            logger=logger,
        )
        return out_dir

    def test_server_cert(self, rsa_intermediate):
        out_dir = self._issue(
            rsa_intermediate, "server",
            "CN=example.com,O=TestOrg",
            ["dns:example.com", "dns:www.example.com", "ip:10.0.0.1"],
        )
        cert = load_certificate(
            os.path.join(out_dir, "certs", "example.com.cert.pem")
        )
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        assert bc.critical is True

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = [u.dotted_string for u in eku.value]
        assert "1.3.6.1.5.5.7.3.1" in oids  # serverAuth

        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names
        assert "www.example.com" in dns_names

    def test_client_cert(self, rsa_intermediate):
        out_dir = self._issue(
            rsa_intermediate, "client",
            "CN=Alice Smith",
            ["email:alice@example.com"],
        )
        cert = load_certificate(
            os.path.join(out_dir, "certs", "Alice_Smith.cert.pem")
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = [u.dotted_string for u in eku.value]
        assert "1.3.6.1.5.5.7.3.2" in oids  # clientAuth

        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        emails = san.value.get_values_for_type(x509.RFC822Name)
        assert "alice@example.com" in emails

    def test_code_signing_cert(self, rsa_intermediate):
        out_dir = self._issue(
            rsa_intermediate, "code_signing",
            "CN=MicroPKI Code Signer",
            [],
        )
        cert = load_certificate(
            os.path.join(out_dir, "certs", "MicroPKI_Code_Signer.cert.pem")
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = [u.dotted_string for u in eku.value]
        assert "1.3.6.1.5.5.7.3.3" in oids  # codeSigning

    def test_end_entity_key_is_unencrypted(self, rsa_intermediate):
        out_dir = self._issue(
            rsa_intermediate, "code_signing",
            "CN=Unencrypted Key Test",
            [],
        )
        key_path = os.path.join(out_dir, "certs", "Unencrypted_Key_Test.key.pem")
        assert os.path.isfile(key_path)
        key_pem = open(key_path, "rb").read()
        assert b"ENCRYPTED" not in key_pem
        assert b"BEGIN PRIVATE KEY" in key_pem


class TestNegativeScenarios:
    """TEST-10: Negative tests."""

    def test_server_without_san_fails(self, rsa_intermediate):
        """Issuing a server cert without SAN must fail."""
        out_dir, _, inter_pass = rsa_intermediate
        logger = logging.getLogger("test")
        with pytest.raises(ValueError, match="requires at least one SAN"):
            issue_certificate(
                ca_cert_path=os.path.join(out_dir, "certs", "intermediate.cert.pem"),
                ca_key_path=os.path.join(out_dir, "private", "intermediate.key.pem"),
                ca_passphrase=inter_pass,
                template_name="server",
                subject_str="CN=no-san.example.com",
                san_strings=[],
                out_dir=os.path.join(out_dir, "certs"),
                validity_days=365,
                logger=logger,
            )

    def test_server_with_email_san_fails(self, rsa_intermediate):
        """Server template must not accept email SAN."""
        out_dir, _, inter_pass = rsa_intermediate
        logger = logging.getLogger("test")
        with pytest.raises(ValueError, match="email"):
            issue_certificate(
                ca_cert_path=os.path.join(out_dir, "certs", "intermediate.cert.pem"),
                ca_key_path=os.path.join(out_dir, "private", "intermediate.key.pem"),
                ca_passphrase=inter_pass,
                template_name="server",
                subject_str="CN=bad-san.example.com",
                san_strings=["email:bad@example.com"],
                out_dir=os.path.join(out_dir, "certs"),
                validity_days=365,
                logger=logger,
            )

    def test_code_signing_with_ip_san_fails(self, rsa_intermediate):
        """Code signing template must not accept IP SAN."""
        out_dir, _, inter_pass = rsa_intermediate
        logger = logging.getLogger("test")
        with pytest.raises(ValueError, match="ip"):
            issue_certificate(
                ca_cert_path=os.path.join(out_dir, "certs", "intermediate.cert.pem"),
                ca_key_path=os.path.join(out_dir, "private", "intermediate.key.pem"),
                ca_passphrase=inter_pass,
                template_name="code_signing",
                subject_str="CN=BadSigner",
                san_strings=["ip:10.0.0.1"],
                out_dir=os.path.join(out_dir, "certs"),
                validity_days=365,
                logger=logger,
            )

    def test_wrong_ca_passphrase_fails(self, rsa_intermediate):
        """Using wrong passphrase for CA key must fail."""
        out_dir, _, _ = rsa_intermediate
        logger = logging.getLogger("test")
        with pytest.raises(Exception):
            issue_certificate(
                ca_cert_path=os.path.join(out_dir, "certs", "intermediate.cert.pem"),
                ca_key_path=os.path.join(out_dir, "private", "intermediate.key.pem"),
                ca_passphrase=b"wrong-passphrase",
                template_name="server",
                subject_str="CN=fail.example.com",
                san_strings=["dns:fail.example.com"],
                out_dir=os.path.join(out_dir, "certs"),
                validity_days=365,
                logger=logger,
            )
