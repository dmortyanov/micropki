"""Integration tests for Root CA initialisation.

Covers TEST-1 (self-consistency), TEST-2 (key-cert matching),
TEST-3 (encrypted key loading).
"""

import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives import hashes

from micropki.crypto_utils import load_private_key
from micropki.certificates import load_certificate


class TestSelfConsistency:
    """TEST-1: The generated certificate must be verifiable using itself."""

    def test_rsa_cert_self_verifies(self, rsa_ca):
        out_dir, _ = rsa_ca
        cert = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

    def test_ecc_cert_self_verifies(self, ecc_ca):
        out_dir, _ = ecc_ca
        cert = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))
        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )


class TestKeyCertMatching:
    """TEST-2: Private key must correspond to the certificate's public key."""

    def test_rsa_sign_and_verify(self, rsa_ca):
        out_dir, passphrase = rsa_ca
        key_pem = open(os.path.join(out_dir, "private", "ca.key.pem"), "rb").read()
        private_key = load_private_key(key_pem, passphrase)
        cert = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))

        message = b"test message for signature verification"
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        cert.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())

    def test_ecc_sign_and_verify(self, ecc_ca):
        out_dir, passphrase = ecc_ca
        key_pem = open(os.path.join(out_dir, "private", "ca.key.pem"), "rb").read()
        private_key = load_private_key(key_pem, passphrase)
        cert = load_certificate(os.path.join(out_dir, "certs", "ca.cert.pem"))

        message = b"test message for signature verification"
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))
        cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA384()))


class TestEncryptedKeyLoading:
    """TEST-3: The encrypted private key can be decrypted with the correct passphrase."""

    def test_rsa_key_loads(self, rsa_ca):
        out_dir, passphrase = rsa_ca
        key_pem = open(os.path.join(out_dir, "private", "ca.key.pem"), "rb").read()
        assert b"ENCRYPTED" in key_pem
        key = load_private_key(key_pem, passphrase)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_ecc_key_loads(self, ecc_ca):
        out_dir, passphrase = ecc_ca
        key_pem = open(os.path.join(out_dir, "private", "ca.key.pem"), "rb").read()
        assert b"ENCRYPTED" in key_pem
        key = load_private_key(key_pem, passphrase)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_wrong_passphrase_fails(self, rsa_ca):
        out_dir, _ = rsa_ca
        key_pem = open(os.path.join(out_dir, "private", "ca.key.pem"), "rb").read()
        with pytest.raises(Exception):
            load_private_key(key_pem, b"wrong-passphrase")


class TestDirectoryStructure:
    """KEY-4: Directory layout must be correct."""

    def test_rsa_output_structure(self, rsa_ca):
        out_dir, _ = rsa_ca
        assert os.path.isfile(os.path.join(out_dir, "private", "ca.key.pem"))
        assert os.path.isfile(os.path.join(out_dir, "certs", "ca.cert.pem"))
        assert os.path.isfile(os.path.join(out_dir, "policy.txt"))

    def test_policy_content(self, rsa_ca):
        out_dir, _ = rsa_ca
        content = open(os.path.join(out_dir, "policy.txt"), encoding="utf-8").read()
        assert "Test Root CA" in content
        assert "RSA-4096" in content
        assert "Policy Version: 1.0" in content
