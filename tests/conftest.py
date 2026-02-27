"""Shared test fixtures."""

import logging
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
def inter_passphrase_file(tmp_path):
    """Create a separate passphrase file for the Intermediate CA."""
    pf = tmp_path / "inter_passphrase.txt"
    pf.write_bytes(b"InterPassphrase456!\n")
    return str(pf)


@pytest.fixture()
def inter_passphrase():
    return b"InterPassphrase456!"


@pytest.fixture()
def rsa_ca(tmp_out_dir, passphrase_file):
    """Initialise an RSA Root CA and return (out_dir, passphrase)."""
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


@pytest.fixture()
def rsa_intermediate(rsa_ca, inter_passphrase):
    """Create an RSA Intermediate CA under the RSA Root CA.

    Returns (out_dir, root_passphrase, inter_passphrase).
    """
    from micropki.ca import issue_intermediate_ca

    out_dir, root_pass = rsa_ca
    logger = logging.getLogger("test")
    issue_intermediate_ca(
        root_cert_path=os.path.join(out_dir, "certs", "ca.cert.pem"),
        root_key_path=os.path.join(out_dir, "private", "ca.key.pem"),
        root_passphrase=root_pass,
        subject_str="CN=Test Intermediate CA,O=TestOrg",
        key_type="rsa",
        key_size=4096,
        passphrase=inter_passphrase,
        out_dir=out_dir,
        validity_days=365,
        path_length=0,
        logger=logger,
    )
    return out_dir, root_pass, inter_passphrase
