"""Tests for PKCS#12 container export/import functionality."""

import os
import tempfile
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from micropki.crypto_utils import (
    generate_key,
    serialize_private_key,
    save_private_key,
    load_private_key,
    serialize_pkcs12,
    load_pkcs12,
)
from micropki.certificates import (
    create_self_signed_cert,
    serialize_certificate,
    save_certificate,
    load_certificate,
)
from micropki.ca import export_ca_to_container, import_ca_from_container

import logging

logger = logging.getLogger("test_pkcs12")


@pytest.fixture
def tmp_pki(tmp_path):
    """Create a temporary PKI directory with a Root CA."""
    pki_dir = tmp_path / "pki"
    (pki_dir / "certs").mkdir(parents=True)
    (pki_dir / "private").mkdir(parents=True)

    # Generate Root CA
    key = generate_key("rsa", 4096)
    cert = create_self_signed_cert(key, "CN=Test Root CA", 3650)

    key_pass = b"test-key-passphrase"
    key_pem = serialize_private_key(key, key_pass)
    cert_pem = serialize_certificate(cert)

    key_path = str(pki_dir / "private" / "ca.key.pem")
    cert_path = str(pki_dir / "certs" / "ca.cert.pem")

    save_private_key(key_pem, key_path)
    save_certificate(cert_pem, cert_path)

    # Write passphrase files
    key_pass_file = str(tmp_path / "ca.pass")
    with open(key_pass_file, "wb") as f:
        f.write(key_pass)

    p12_pass_file = str(tmp_path / "p12.pass")
    with open(p12_pass_file, "wb") as f:
        f.write(b"container-password-123")

    return {
        "pki_dir": str(pki_dir),
        "key_path": key_path,
        "cert_path": cert_path,
        "key_pass": key_pass,
        "key_pass_file": key_pass_file,
        "p12_pass": b"container-password-123",
        "p12_pass_file": p12_pass_file,
        "key": key,
        "cert": cert,
        "tmp_path": str(tmp_path),
    }


class TestSerializePkcs12:
    """Unit tests for serialize_pkcs12 / load_pkcs12."""

    def test_roundtrip_rsa(self, tmp_pki):
        """Export and re-import an RSA key pair via PKCS#12."""
        key = tmp_pki["key"]
        cert = tmp_pki["cert"]
        passphrase = b"p12-roundtrip-test"

        p12_data = serialize_pkcs12(cert, key, passphrase, "Test CA")
        assert isinstance(p12_data, bytes)
        assert len(p12_data) > 0

        loaded_key, loaded_cert, chain = load_pkcs12(p12_data, passphrase)

        # Certificate must be identical
        assert loaded_cert.serial_number == cert.serial_number
        assert loaded_cert.subject == cert.subject

        # Key must produce the same public key
        orig_pub = key.public_key().public_numbers()
        loaded_pub = loaded_key.public_key().public_numbers()
        assert orig_pub == loaded_pub

    def test_roundtrip_ecc(self):
        """Export and re-import an ECC key pair via PKCS#12."""
        key = generate_key("ecc", 384)
        cert = create_self_signed_cert(key, "CN=ECC Test CA", 365)
        passphrase = b"ecc-p12-test"

        p12_data = serialize_pkcs12(cert, key, passphrase, "ECC CA")
        loaded_key, loaded_cert, chain = load_pkcs12(p12_data, passphrase)

        assert loaded_cert.serial_number == cert.serial_number
        orig_pub = key.public_key().public_numbers()
        loaded_pub = loaded_key.public_key().public_numbers()
        assert orig_pub == loaded_pub

    def test_wrong_password_fails(self, tmp_pki):
        """Loading a PKCS#12 with wrong password must raise an error."""
        key = tmp_pki["key"]
        cert = tmp_pki["cert"]

        p12_data = serialize_pkcs12(cert, key, b"correct-password")

        with pytest.raises(Exception):
            load_pkcs12(p12_data, b"wrong-password")

    def test_chain_is_empty_when_no_extras(self, tmp_pki):
        """When no extra certs are bundled, chain should be empty."""
        key = tmp_pki["key"]
        cert = tmp_pki["cert"]

        p12_data = serialize_pkcs12(cert, key, b"test")
        _, _, chain = load_pkcs12(p12_data, b"test")
        assert chain == []


class TestExportImportCA:
    """Integration tests for export_ca_to_container / import_ca_from_container."""

    def test_export_creates_p12_file(self, tmp_pki):
        """ca export should produce a .p12 file."""
        p12_path = os.path.join(tmp_pki["tmp_path"], "root_ca.p12")

        export_ca_to_container(
            cert_path=tmp_pki["cert_path"],
            key_path=tmp_pki["key_path"],
            key_passphrase=tmp_pki["key_pass"],
            container_passphrase=tmp_pki["p12_pass"],
            out_path=p12_path,
            logger=logger,
        )

        assert os.path.isfile(p12_path)
        assert os.path.getsize(p12_path) > 0

    def test_export_import_roundtrip(self, tmp_pki):
        """Export → delete originals → import must restore identical cert and key."""
        p12_path = os.path.join(tmp_pki["tmp_path"], "root_ca.p12")

        # Export
        export_ca_to_container(
            cert_path=tmp_pki["cert_path"],
            key_path=tmp_pki["key_path"],
            key_passphrase=tmp_pki["key_pass"],
            container_passphrase=tmp_pki["p12_pass"],
            out_path=p12_path,
            logger=logger,
        )

        # Remember original cert serial
        original_cert = load_certificate(tmp_pki["cert_path"])
        original_serial = original_cert.serial_number

        # Delete originals
        os.remove(tmp_pki["cert_path"])
        os.remove(tmp_pki["key_path"])
        assert not os.path.exists(tmp_pki["cert_path"])
        assert not os.path.exists(tmp_pki["key_path"])

        # Import
        new_key_pass = b"new-key-passphrase"
        import_ca_from_container(
            p12_path=p12_path,
            container_passphrase=tmp_pki["p12_pass"],
            new_key_passphrase=new_key_pass,
            out_dir=tmp_pki["pki_dir"],
            logger=logger,
        )

        # Verify restored files exist
        assert os.path.isfile(tmp_pki["cert_path"])
        assert os.path.isfile(tmp_pki["key_path"])

        # Verify certificate integrity
        restored_cert = load_certificate(tmp_pki["cert_path"])
        assert restored_cert.serial_number == original_serial

        # Verify key integrity (can be loaded with new passphrase)
        with open(tmp_pki["key_path"], "rb") as f:
            restored_key = load_private_key(f.read(), new_key_pass)
        assert restored_key is not None

    def test_import_with_wrong_password_fails(self, tmp_pki):
        """Importing a PKCS#12 with the wrong password must fail."""
        p12_path = os.path.join(tmp_pki["tmp_path"], "root_ca.p12")

        export_ca_to_container(
            cert_path=tmp_pki["cert_path"],
            key_path=tmp_pki["key_path"],
            key_passphrase=tmp_pki["key_pass"],
            container_passphrase=tmp_pki["p12_pass"],
            out_path=p12_path,
            logger=logger,
        )

        with pytest.raises(Exception):
            import_ca_from_container(
                p12_path=p12_path,
                container_passphrase=b"totally-wrong-password",
                new_key_passphrase=b"irrelevant",
                out_dir=tmp_pki["pki_dir"],
                logger=logger,
            )

    def test_import_with_prefix(self, tmp_pki):
        """Importing with prefix='intermediate' creates intermediate.cert.pem."""
        p12_path = os.path.join(tmp_pki["tmp_path"], "inter.p12")

        export_ca_to_container(
            cert_path=tmp_pki["cert_path"],
            key_path=tmp_pki["key_path"],
            key_passphrase=tmp_pki["key_pass"],
            container_passphrase=tmp_pki["p12_pass"],
            out_path=p12_path,
            logger=logger,
        )

        restore_dir = os.path.join(tmp_pki["tmp_path"], "restored_pki")
        os.makedirs(os.path.join(restore_dir, "certs"), exist_ok=True)
        os.makedirs(os.path.join(restore_dir, "private"), exist_ok=True)

        import_ca_from_container(
            p12_path=p12_path,
            container_passphrase=tmp_pki["p12_pass"],
            new_key_passphrase=b"inter-pass",
            out_dir=restore_dir,
            logger=logger,
            prefix="intermediate",
        )

        assert os.path.isfile(os.path.join(restore_dir, "certs", "intermediate.cert.pem"))
        assert os.path.isfile(os.path.join(restore_dir, "private", "intermediate.key.pem"))
