"""Unit tests for CSR generation and verification (TEST-12 partial)."""

import pytest
from cryptography import x509

from micropki.crypto_utils import generate_key
from micropki.csr import generate_csr, serialize_csr, verify_csr


class TestCSRGeneration:
    def test_rsa_csr_subject(self):
        key = generate_key("rsa", 4096)
        csr = generate_csr(key, "CN=Test CSR,O=Org")
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "Test CSR"

    def test_ecc_csr_subject(self):
        key = generate_key("ecc", 384)
        csr = generate_csr(key, "CN=ECC CSR")
        assert csr.is_signature_valid

    def test_ca_csr_has_basic_constraints(self):
        key = generate_key("rsa", 4096)
        csr = generate_csr(key, "CN=CA CSR", is_ca=True, path_length=0)
        bc = csr.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.value.path_length == 0

    def test_non_ca_csr_has_no_basic_constraints(self):
        key = generate_key("rsa", 4096)
        csr = generate_csr(key, "CN=Leaf CSR")
        with pytest.raises(x509.ExtensionNotFound):
            csr.extensions.get_extension_for_class(x509.BasicConstraints)

    def test_csr_serialization(self):
        key = generate_key("rsa", 4096)
        csr = generate_csr(key, "CN=Serialize Test")
        pem = serialize_csr(csr)
        assert b"-----BEGIN CERTIFICATE REQUEST-----" in pem

    def test_verify_csr(self):
        key = generate_key("rsa", 4096)
        csr = generate_csr(key, "CN=Verify Test")
        assert verify_csr(csr) is True
