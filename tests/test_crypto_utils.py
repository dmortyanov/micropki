"""Unit tests for crypto_utils module."""

import pytest

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from micropki.crypto_utils import (
    generate_key,
    load_private_key,
    parse_subject_dn,
    serialize_private_key,
)


class TestKeyGeneration:
    def test_rsa_4096(self):
        key = generate_key("rsa", 4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_ecc_p384(self):
        key = generate_key("ecc", 384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP384R1)

    def test_unsupported_type(self):
        with pytest.raises(ValueError, match="Unsupported key type"):
            generate_key("dsa", 2048)


class TestPEMSerialization:
    def test_rsa_roundtrip(self):
        key = generate_key("rsa", 4096)
        passphrase = b"secret"
        pem = serialize_private_key(key, passphrase)
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in pem
        loaded = load_private_key(pem, passphrase)
        assert isinstance(loaded, rsa.RSAPrivateKey)

    def test_ecc_roundtrip(self):
        key = generate_key("ecc", 384)
        passphrase = b"secret"
        pem = serialize_private_key(key, passphrase)
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in pem
        loaded = load_private_key(pem, passphrase)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)


class TestDNParsing:
    def test_slash_notation(self):
        dn = parse_subject_dn("/CN=My CA/O=Org/C=US")
        assert dn == {"CN": "My CA", "O": "Org", "C": "US"}

    def test_comma_notation(self):
        dn = parse_subject_dn("CN=My CA, O=Org, C=US")
        assert dn == {"CN": "My CA", "O": "Org", "C": "US"}

    def test_cn_only(self):
        dn = parse_subject_dn("/CN=Root CA")
        assert dn == {"CN": "Root CA"}

    def test_missing_cn(self):
        with pytest.raises(ValueError, match="CN"):
            parse_subject_dn("O=Org,C=US")

    def test_invalid_component(self):
        with pytest.raises(ValueError, match="missing '='"):
            parse_subject_dn("CN=OK,BADPART")

    def test_empty_value(self):
        with pytest.raises(ValueError, match="Empty value"):
            parse_subject_dn("CN=")
