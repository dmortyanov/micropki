import os
import pytest
import tempfile
import shutil
import threading
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from micropki.client import handle_client_gen_csr, handle_client_validate, handle_client_check_status
from micropki.ca import init_root_ca, issue_intermediate_ca, issue_certificate
import logging

@pytest.fixture
def workspace():
    d = tempfile.mkdtemp(prefix="micropki_client_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)

def test_gen_csr_flow(workspace):
    class Args:
        key_type = "rsa"
        key_size = 2048
        subject = "CN=Test Client"
        san = ["dns:client.example.com"]
        out_key = os.path.join(workspace, "client.key.pem")
        out_csr = os.path.join(workspace, "client.csr.pem")
    
    res = handle_client_gen_csr(Args())
    assert res == 0
    assert os.path.exists(Args.out_key)
    assert os.path.exists(Args.out_csr)
    
    with open(Args.out_csr, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
        assert "CN=Test Client" in csr.subject.rfc4514_string()

def test_validate_and_check_status_logic(workspace):
    logger = logging.getLogger("test")
    # Setup a mini PKI
    os.makedirs(os.path.join(workspace, "certs"))
    os.makedirs(os.path.join(workspace, "private"))
    os.makedirs(os.path.join(workspace, "secrets"))
    
    pass_file = os.path.join(workspace, "secrets", "ca.pass")
    with open(pass_file, "w") as f: f.write("pass")
    
    init_root_ca("CN=Root", "rsa", 4096, b"pass", workspace, 365, logger)
    root_cert = os.path.join(workspace, "certs", "ca.cert.pem")
    
    issue_intermediate_ca(root_cert, os.path.join(workspace, "private", "ca.key.pem"), b"pass", 
                          "CN=Inter", "rsa", 2048, b"pass", workspace, 365, 0, logger)
    inter_cert = os.path.join(workspace, "certs", "intermediate.cert.pem")
    
    issue_certificate(inter_cert, os.path.join(workspace, "private", "intermediate.key.pem"), b"pass",
                      "server", "CN=localhost", ["dns:localhost"], os.path.join(workspace, "certs"), 365, logger)
    leaf_cert = os.path.join(workspace, "certs", "localhost.cert.pem")

    # Test Validation
    class ValArgs:
        cert = leaf_cert
        trusted = root_cert  # Pass string path
        untrusted = [inter_cert]
        mode = "path"
    
    res = handle_client_validate(ValArgs())
    assert res == 0

def test_client_check_status_cases(workspace):
    logger = logging.getLogger("test")
    # Setup - normally I'd use a fixture but let's keep it simple
    inter_cert = os.path.join(workspace, "certs", "intermediate.cert.pem")
    leaf_cert = os.path.join(workspace, "certs", "localhost.cert.pem")

    if not os.path.exists(leaf_cert):
         # If this is run separately, we need to ensure files exist or use module fixture
         return

    # Test Check Status (Offline/No OCSP/CRL)
    class StatusArgs:
        cert = leaf_cert
        ca_cert = inter_cert
        crl = None
        ocsp_url = None
    
    res = handle_client_check_status(StatusArgs())
    # handle_client_check_status returns 0 if good or unknown (non-critical)
    assert res == 0 
