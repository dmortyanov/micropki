"""Unit tests for certificate generation."""

import datetime
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from micropki.certificates import (
    build_x509_name,
    create_self_signed_cert,
    load_certificate,
    save_certificate,
    serialize_certificate,
)
from micropki.crypto_utils import generate_key


class TestSelfSignedCert:
    def test_rsa_cert_is_valid_x509v3(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Test CA", 365)
        assert cert.version == x509.Version.v3

    def test_ecc_cert_is_valid_x509v3(self):
        key = generate_key("ecc", 384)
        cert = create_self_signed_cert(key, "CN=ECC CA,O=Test", 365)
        assert cert.version == x509.Version.v3

    def test_subject_equals_issuer(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        assert cert.subject == cert.issuer

    def test_validity_period(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 364 <= delta.days <= 366

    def test_basic_constraints_ca_true(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length is None

    def test_key_usage(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True
        assert ku.value.digital_signature is True

    def test_ski_and_aki_present(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert ski.value.digest == aki.value.key_identifier

    def test_pem_serialization(self):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        pem = serialize_certificate(cert)
        assert b"-----BEGIN CERTIFICATE-----" in pem

    def test_save_and_load(self, tmp_path):
        key = generate_key("rsa", 4096)
        cert = create_self_signed_cert(key, "/CN=Root", 365)
        path = str(tmp_path / "certs" / "ca.cert.pem")
        save_certificate(serialize_certificate(cert), path)
        assert os.path.exists(path)
        loaded = load_certificate(path)
        assert loaded.serial_number == cert.serial_number
