import os
import subprocess
import pytest
import sqlite3
import urllib.request
import time
from threading import Thread
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime

from micropki.cli import main
from micropki.database import CertificateDatabase
from micropki.repository import RepositoryServer

@pytest.fixture
def temp_pki_dir(tmp_path):
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    
    pass_dir = pki_dir / "secrets"
    pass_dir.mkdir()
    
    root_pass = pass_dir / "ca.pass"
    root_pass.write_text("rootpass")
    
    inter_pass = pass_dir / "intermediate.pass"
    inter_pass.write_text("interpass")
    
    # Initialize Root CA
    main([
        "ca", "init",
        "--subject", "CN=Test Root CA",
        "--passphrase-file", str(root_pass),
        "--out-dir", str(pki_dir),
        "--validity-days", "365"
    ])
    
    # Initialize Intermediate CA
    main([
        "ca", "issue-intermediate",
        "--root-cert", str(pki_dir / "certs" / "ca.cert.pem"),
        "--root-key", str(pki_dir / "private" / "ca.key.pem"),
        "--root-pass-file", str(root_pass),
        "--subject", "CN=Test Intermediate CA",
        "--passphrase-file", str(inter_pass),
        "--out-dir", str(pki_dir),
        "--validity-days", "180"
    ])
    
    return pki_dir

def test_sprint4_revocation_lifecycle(temp_pki_dir, capsys):
    pki_dir = temp_pki_dir
    inter_pass = pki_dir / "secrets" / "intermediate.pass"
    
    # Issue a cert to revoke
    main([
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(inter_pass),
        "--template", "server",
        "--subject", "CN=revoked.example.com",
        "--san", "dns:revoked.example.com",
        "--out-dir", str(pki_dir / "certs"),
        "--validity-days", "30"
    ])
    
    db_path = pki_dir / "micropki.db"
    db = CertificateDatabase(str(db_path))
    db.connect()
    
    # Find the serial of the newly issued cert
    certs = db.list_certificates()
    cert_to_revoke = [c for c in certs if c["subject"] == "CN=revoked.example.com"][0]
    serial = cert_to_revoke["serial_hex"]
    assert cert_to_revoke["status"] == "valid"
    db.close()
    
    # 1. Revoke the certificate via CLI
    env = os.environ.copy()
    env["MICROPKI_CONFIG"] = ""  # just to be sure we're fully isolated
    # Mocking standard configuration in tests doesn't always work if it reads some global db.
    # However we can just run the function or overwrite default db path.
    # Let's patch `_get_default_db_path`
    
    import micropki.cli as cli
    original_db = cli._get_default_db_path
    cli._get_default_db_path = lambda: str(db_path)
    
    res = cli.main([
        "ca", "revoke", serial, "--reason", "keycompromise", "--force"
    ])
    assert res == 0
    
    # Check revoked status
    res = cli.main([
        "ca", "check-revoked", serial
    ])
    assert res == 2 # 2 means revoked
    
    # Check that output says REVOKED
    captured = capsys.readouterr()
    assert "REVOKED" in captured.out or "REVOKED" in captured.err
    
    # 2. Generate CRL
    res = cli.main([
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", str(pki_dir)
    ])
    assert res == 0
    
    crl_path = pki_dir / "crl" / "intermediate.crl.pem"
    assert crl_path.exists()
    
    # 3. Parse CRL to verify it has the certificate
    crl_data = crl_path.read_bytes()
    crl = x509.load_pem_x509_crl(crl_data)
    
    revoked_list = crl.get_revoked_certificate_by_serial_number(int(serial, 16))
    assert revoked_list is not None
    
    reason_ext = revoked_list.extensions.get_extension_for_class(x509.CRLReason)
    assert reason_ext.value.reason == x509.ReasonFlags.key_compromise
    
    cli._get_default_db_path = original_db

def test_sprint4_crl_number_increment(temp_pki_dir):
    pki_dir = temp_pki_dir
    db_path = pki_dir / "micropki.db"
    
    import micropki.cli as cli
    original_db = cli._get_default_db_path
    cli._get_default_db_path = lambda: str(db_path)
    
    # Gen first time
    cli.main([
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", str(pki_dir)
    ])
    
    crl_path = pki_dir / "crl" / "intermediate.crl.pem"
    crl1 = x509.load_pem_x509_crl(crl_path.read_bytes())
    crl_num1 = crl1.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert crl_num1 == 1
    
    # Gen second time
    cli.main([
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", str(pki_dir)
    ])
    crl2 = x509.load_pem_x509_crl(crl_path.read_bytes())
    crl_num2 = crl2.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert crl_num2 == 2
    
    cli._get_default_db_path = original_db

def test_sprint4_negative_revoke(temp_pki_dir, capsys):
    pki_dir = temp_pki_dir
    db_path = pki_dir / "micropki.db"
    
    import micropki.cli as cli
    original_db = cli._get_default_db_path
    cli._get_default_db_path = lambda: str(db_path)
    
    # Attempt to check non-existent
    res = cli.main([
        "ca", "check-revoked", "deadbeef"
    ])
    assert res == 1
    
    # Revoking non-existent
    res = cli.main([
        "ca", "revoke", "deadbeef", "--force"
    ])
    assert res == 1
    
    cli._get_default_db_path = original_db

def test_sprint4_http_crl(temp_pki_dir):
    pki_dir = temp_pki_dir
    db_path = pki_dir / "micropki.db"
    
    import micropki.cli as cli
    original_db = cli._get_default_db_path
    cli._get_default_db_path = lambda: str(db_path)
    
    cli.main([
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", str(pki_dir)
    ])
    
    cli._get_default_db_path = original_db
    
    server = RepositoryServer(
        host="127.0.0.1", port=8082, db_path=str(db_path), cert_dir=str(pki_dir / "certs")
    )
    t = Thread(target=server.start, daemon=True)
    t.start()
    
    time.sleep(1) # wait for server
    
    try:
        # Default CRL
        req = urllib.request.Request("http://127.0.0.1:8082/crl")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/pkix-crl"
            crl_bytes = resp.read()
            assert len(crl_bytes) > 0
            
            cache_ctrl = resp.headers.get("Cache-Control", "")
            assert "max-age=" in cache_ctrl
            
        # Target crl
        req2 = urllib.request.Request("http://127.0.0.1:8082/crl/intermediate.crl")
        with urllib.request.urlopen(req2) as resp:
            assert resp.status == 200
            
    finally:
        server.stop()
        t.join(timeout=1)

def test_sprint4_openssl_verify_crl(temp_pki_dir):
    pki_dir = temp_pki_dir
    db_path = pki_dir / "micropki.db"
    
    import micropki.cli as cli
    original_db = cli._get_default_db_path
    cli._get_default_db_path = lambda: str(db_path)
    
    cli.main([
        "ca", "gen-crl",
        "--ca", "intermediate",
        "--out-dir", str(pki_dir)
    ])
    
    cli._get_default_db_path = original_db
    
    crl_path = pki_dir / "crl" / "intermediate.crl.pem"
    cert_path = pki_dir / "certs" / "intermediate.cert.pem"
    
    # Execute openssl tool
    proc = subprocess.run([
        "openssl", "crl", "-in", str(crl_path), "-CAfile", str(cert_path), "-noout"
    ], capture_output=True, text=True)
    
    # In OpenSSL 1.1.1+, output is "verify OK" on stdout or stderr.
    assert proc.returncode == 0
    output = proc.stdout + proc.stderr
    assert "verify OK" in output or "OK" in output
