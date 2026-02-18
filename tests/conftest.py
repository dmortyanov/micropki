"""Shared test fixtures."""

import os
import pytest


@pytest.fixture()
def tmp_out_dir(tmp_path):
    """Return a temporary output directory for PKI files."""
    return str(tmp_path / "pki")


@pytest.fixture()
def passphrase_file(tmp_path):
    """Create a temporary passphrase file and return its path."""
    pf = tmp_path / "passphrase.txt"
    pf.write_bytes(b"TestPassphrase123!\n")
    return str(pf)


@pytest.fixture()
def passphrase():
    return b"TestPassphrase123!"


@pytest.fixture()
def rsa_ca(tmp_out_dir, passphrase_file):
    """Initialise an RSA Root CA and return (out_dir, passphrase)."""
    import logging
    from micropki.ca import init_root_ca

    logger = logging.getLogger("test")
    init_root_ca(
        subject_str="/CN=Test Root CA/O=TestOrg/C=US",
        key_type="rsa",
        key_size=4096,
        passphrase=b"TestPassphrase123!",
        out_dir=tmp_out_dir,
        validity_days=365,
        logger=logger,
    )
    return tmp_out_dir, b"TestPassphrase123!"


@pytest.fixture()
def ecc_ca(tmp_out_dir, passphrase_file):
    """Initialise an ECC Root CA and return (out_dir, passphrase)."""
    import logging
    from micropki.ca import init_root_ca

    logger = logging.getLogger("test")
    init_root_ca(
        subject_str="CN=ECC Test CA,O=TestOrg",
        key_type="ecc",
        key_size=384,
        passphrase=b"TestPassphrase123!",
        out_dir=tmp_out_dir,
        validity_days=365,
        logger=logger,
    )
    return tmp_out_dir, b"TestPassphrase123!"
