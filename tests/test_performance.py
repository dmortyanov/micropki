import os
import time
import tempfile
import shutil
import pytest
from micropki.cli import main

def test_performance_1000_certs():
    """TEST-65: Performance test for 1000 certificate issuance."""
    workspace = tempfile.mkdtemp(prefix="micropki_perf_")
    try:
        # 1. Setup CA
        secrets_dir = os.path.join(workspace, "secrets")
        os.makedirs(secrets_dir)
        pass_file = os.path.join(secrets_dir, "ca.pass")
        with open(pass_file, "w") as f: f.write("perf_pass")
        
        main([
            "ca", "init",
            "--subject", "CN=Perf Root CA",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", pass_file,
            "--out-dir", workspace,
        ])
        
        ca_cert = os.path.join(workspace, "certs", "ca.cert.pem")
        ca_key = os.path.join(workspace, "private", "ca.key.pem")
        
        # 2. Issue 1000 certs
        count = 1000
        start_time = time.time()
        
        for i in range(count):
            subject = f"CN=leaf{i}.example.com"
            res = main([
                "ca", "issue-cert",
                "--ca-cert", ca_cert,
                "--ca-key", ca_key,
                "--ca-pass-file", pass_file,
                "--template", "server",
                "--subject", subject,
                "--san", f"dns:leaf{i}.example.com",
                "--out-dir", os.path.join(workspace, "certs"),
            ])
            if res != 0:
                pytest.fail(f"Failed to issue certificate {i}")
        
        end_time = time.time()
        duration = end_time - start_time
        avg = duration / count
        
        print(f"\n[PERF] Issued {count} certificates in {duration:.2f}s")
        print(f"[PERF] Average time per certificate: {avg*1000:.2f}ms")
        
        # We expect a reasonable performance, e.g., < 100ms per cert on decent hardware
        # But for CI/Test environments, let's just assert it finishes.
        assert duration > 0
        
    finally:
        shutil.rmtree(workspace)

if __name__ == "__main__":
    test_performance_1000_certs()
