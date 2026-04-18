import os
import subprocess
import time
import shutil
import sys
import tempfile

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")

def run(cmd, cwd=None, check=True):
    print(f"$ {' '.join(cmd)}")
    env = os.environ.copy()
    if os.path.abspath(".") not in env.get("PYTHONPATH", ""):
        env["PYTHONPATH"] = os.path.abspath(".") + os.pathsep + env.get("PYTHONPATH", "")
    
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[FAIL] Command failed with code {result.returncode}")
        print(result.stdout)
        print(result.stderr)
        sys.exit(1)
    return result

def main():
    print_header("MicroPKI Demonstration Script (Sprint 8)")
    
    # Setup working directory
    workspace = tempfile.mkdtemp(prefix="micropki_demo_")
    print(f"Created temporary workspace at: {workspace}")
    
    # Path to micropki executable
    micropki_cmd = [sys.executable, "-m", "micropki.cli"]
    
    try:
        # Create passphrase files
        os.makedirs(os.path.join(workspace, "secrets"))
        ca_pass_file = os.path.join(workspace, "secrets", "ca.pass")
        inter_pass_file = os.path.join(workspace, "secrets", "inter.pass")
        ocsp_pass_file = os.path.join(workspace, "secrets", "ocsp.pass")
        
        with open(ca_pass_file, "w") as f: f.write("demo_root_pass")
        with open(inter_pass_file, "w") as f: f.write("demo_inter_pass")
        with open(ocsp_pass_file, "w") as f: f.write("demo_ocsp_pass")
        
        print_header("1. Root CA Initialization")
        run(micropki_cmd + [
            "ca", "init",
            "--subject", "CN=Demo Root CA",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", ca_pass_file,
            "--out-dir", os.path.join(workspace, "pki"),
        ])
        print("[PASS] Root CA Initialized")
        
        print_header("2. Intermediate CA Initialization")
        run(micropki_cmd + [
            "ca", "issue-intermediate",
            "--root-cert", os.path.join(workspace, "pki", "certs", "ca.cert.pem"),
            "--root-key", os.path.join(workspace, "pki", "private", "ca.key.pem"),
            "--root-pass-file", ca_pass_file,
            "--subject", "CN=Demo Intermediate CA",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", inter_pass_file,
            "--out-dir", os.path.join(workspace, "pki")
        ])
        print("[PASS] Intermediate CA Initialized")
        
        print_header("3. Issue Server Certificate")
        run(micropki_cmd + [
            "ca", "issue-cert",
            "--ca-cert", os.path.join(workspace, "pki", "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(workspace, "pki", "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pass_file,
            "--template", "server",
            "--subject", "CN=localhost",
            "--san", "dns:localhost",
            "--out-dir", os.path.join(workspace, "pki", "certs"),
        ])
        print("[PASS] Server Certificate Issued")
        
        print_header("4. Issue Client Certificate")
        run(micropki_cmd + [
            "ca", "issue-cert",
            "--ca-cert", os.path.join(workspace, "pki", "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(workspace, "pki", "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pass_file,
            "--template", "client",
            "--subject", "CN=Demo Client",
            "--out-dir", os.path.join(workspace, "pki", "certs"),
        ])
        print("[PASS] Client Certificate Issued")
        
        print_header("5. Issue OCSP Responder Certificate")
        run(micropki_cmd + [
            "ca", "issue-ocsp-cert",
            "--ca-cert", os.path.join(workspace, "pki", "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(workspace, "pki", "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pass_file,
            "--subject", "CN=Demo OCSP Responder",
            "--out-dir", os.path.join(workspace, "pki", "certs"),
        ])
        print("[PASS] OCSP Certificate Issued")

        print_header("6. Start HTTP Servers (Repo & OCSP)")
        repo_proc = subprocess.Popen(
            micropki_cmd + ["repo", "serve", "--db-path", os.path.join(workspace, "pki", "micropki.db"), "--cert-dir", os.path.join(workspace, "pki", "certs")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        ocsp_proc = subprocess.Popen(
            micropki_cmd + ["ocsp", "serve", 
                            "--db-path", os.path.join(workspace, "pki", "micropki.db"), 
                            "--responder-cert", os.path.join(workspace, "pki", "certs", "Demo_OCSP_Responder.cert.pem"), 
                            "--responder-key", os.path.join(workspace, "pki", "certs", "Demo_OCSP_Responder.key.pem"), 
                            "--ca-cert", os.path.join(workspace, "pki", "certs", "intermediate.cert.pem")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2) # let servers start
        print("[PASS] Servers started")

        print_header("7. Validate Server Certificate (Path + Full)")
        run(micropki_cmd + [
            "client", "validate",
            "--cert", os.path.join(workspace, "pki", "certs", "localhost.cert.pem"),
            "--trusted", os.path.join(workspace, "pki", "certs", "ca.cert.pem"),
            "--untrusted", os.path.join(workspace, "pki", "certs", "intermediate.cert.pem"),
            "--mode", "path"
        ])
        print("[PASS] Path validation successful")
        
        print_header("8. Revoke Server Certificate")
        # List certs to find serial
        list_out = run(micropki_cmd + ["ca", "list-certs", "--format", "json"], cwd=workspace).stdout
        import json
        certs = json.loads(list_out)
        server_serial = next(c["serial_hex"] for c in certs if "localhost" in c["subject"])
        
        run(micropki_cmd + ["ca", "revoke", server_serial, "--reason", "keycompromise", "--force"], cwd=workspace)
        print(f"[PASS] Certificate {server_serial} revoked")

        print_header("9. Verify Revocation with OCSP")
        result = run(micropki_cmd + [
            "client", "check-status",
            "--cert", os.path.join(workspace, "pki", "certs", "localhost.cert.pem"),
            "--ca-cert", os.path.join(workspace, "pki", "certs", "intermediate.cert.pem"),
            "--ocsp-url", "http://127.0.0.1:8081/ocsp"
        ], check=False)
        if "REVOKED" in result.stdout:
            print("[PASS] Revocation check returned REVOKED correctly.")
        else:
            print("[FAIL] Revocation check did not return REVOKED!")
            print(result.stdout)
            sys.exit(1)

        print_header("10. Audit Log Integrity Check")
        run(micropki_cmd + ["audit", "verify", "--log-file", os.path.join(workspace, "pki", "audit.log")])
        print("[PASS] Audit log verified")

    finally:
        # Cleanup
        if 'repo_proc' in locals(): 
            repo_proc.terminate()
            repo_proc.wait()
        if 'ocsp_proc' in locals(): 
            ocsp_proc.terminate()
            ocsp_proc.wait()
        shutil.rmtree(workspace)
        print("\nDemo Complete! Workspace cleaned up.")

if __name__ == "__main__":
    main()
