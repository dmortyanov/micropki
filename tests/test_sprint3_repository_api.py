import os
import socket
import threading
import time
import urllib.error
import urllib.request

from micropki.cli import main
from micropki.database import CertificateDatabase
from micropki.repository import RepositoryServer


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _setup_pki(tmp_path) -> str:
    pki_dir = tmp_path / "pki"
    secrets_dir = pki_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    root_pass = secrets_dir / "root.pass"
    inter_pass = secrets_dir / "intermediate.pass"
    root_pass.write_bytes(b"RootPass123!\n")
    inter_pass.write_bytes(b"InterPass456!\n")

    # Root CA
    assert (
        main(
            [
                "ca",
                "init",
                "--subject",
                "CN=Repo Root CA,O=TestOrg,C=US",
                "--key-type",
                "rsa",
                "--key-size",
                "4096",
                "--passphrase-file",
                str(root_pass),
                "--out-dir",
                str(pki_dir),
                "--validity-days",
                "365",
            ]
        )
        == 0
    )

    # DB init
    assert (
        main(
            [
                "db",
                "init",
                "--db-path",
                str(pki_dir / "micropki.db"),
            ]
        )
        == 0
    )

    # Intermediate CA
    assert (
        main(
            [
                "ca",
                "issue-intermediate",
                "--root-cert",
                str(pki_dir / "certs" / "ca.cert.pem"),
                "--root-key",
                str(pki_dir / "private" / "ca.key.pem"),
                "--root-pass-file",
                str(root_pass),
                "--subject",
                "CN=Repo Intermediate CA,O=TestOrg",
                "--key-type",
                "rsa",
                "--key-size",
                "4096",
                "--passphrase-file",
                str(inter_pass),
                "--out-dir",
                str(pki_dir),
                "--validity-days",
                "365",
                "--pathlen",
                "0",
            ]
        )
        == 0
    )

    cert_dir = str(pki_dir / "certs")

    # Leaf certs (keep it small for API tests)
    assert (
        main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                str(pki_dir / "certs" / "intermediate.cert.pem"),
                "--ca-key",
                str(pki_dir / "private" / "intermediate.key.pem"),
                "--ca-pass-file",
                str(inter_pass),
                "--template",
                "server",
                "--subject",
                "CN=server1.example.com,O=TestOrg",
                "--san",
                "dns:server1.example.com",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "30",
            ]
        )
        == 0
    )

    assert (
        main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                str(pki_dir / "certs" / "intermediate.cert.pem"),
                "--ca-key",
                str(pki_dir / "private" / "intermediate.key.pem"),
                "--ca-pass-file",
                str(inter_pass),
                "--template",
                "client",
                "--subject",
                "CN=client1,O=TestOrg",
                "--san",
                "email:client1@example.com",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "30",
            ]
        )
        == 0
    )

    assert (
        main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                str(pki_dir / "certs" / "intermediate.cert.pem"),
                "--ca-key",
                str(pki_dir / "private" / "intermediate.key.pem"),
                "--ca-pass-file",
                str(inter_pass),
                "--template",
                "code_signing",
                "--subject",
                "CN=signer1,O=TestOrg",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "30",
            ]
        )
        == 0
    )

    return str(pki_dir)


def test_sprint3_repository_api_certificate_and_ca(tmp_path):
    pki_dir = _setup_pki(tmp_path)
    db_path = os.path.join(pki_dir, "micropki.db")
    cert_dir = os.path.join(pki_dir, "certs")

    # Pick one issued leaf cert serial from DB.
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()
    records = db.list_certificates(status="valid")
    db.close()

    leaf = next(r for r in records if "CN=server1.example.com" in r["subject"])
    serial_hex = leaf["serial_hex"]
    expected_leaf_pem = leaf["cert_pem"].encode("utf-8")

    root_pem = open(os.path.join(cert_dir, "ca.cert.pem"), "rb").read()
    intermediate_pem = open(os.path.join(cert_dir, "intermediate.cert.pem"), "rb").read()

    host = "127.0.0.1"
    port = _get_free_port()

    server = RepositoryServer(host=host, port=port, db_path=db_path, cert_dir=cert_dir)
    t = threading.Thread(target=server.start, daemon=True)
    t.start()

    # Wait until the port is reachable.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)

    base = f"http://{host}:{port}"

    # CA root
    with urllib.request.urlopen(base + "/ca/root") as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"
        body = resp.read()
        assert body == root_pem

    # CA intermediate
    with urllib.request.urlopen(base + "/ca/intermediate") as resp:
        assert resp.status == 200
        body = resp.read()
        assert body == intermediate_pem

    # Leaf cert
    with urllib.request.urlopen(base + f"/certificate/{serial_hex}") as resp:
        assert resp.status == 200
        body = resp.read()
        assert body == expected_leaf_pem

    # /crl placeholder
    try:
        urllib.request.urlopen(base + "/crl")
        assert False, "Expected HTTPError for /crl"
    except urllib.error.HTTPError as e:
        assert e.code == 501
        body = e.read().decode("utf-8").strip()
        assert body == "CRL generation not yet implemented"

    # Negative: invalid serial format
    try:
        urllib.request.urlopen(base + "/certificate/XYZ")
        assert False, "Expected HTTPError for invalid serial"
    except urllib.error.HTTPError as e:
        assert e.code == 400
        body = e.read().decode("utf-8")
        assert "hexadecimal" in body.lower()

    server.stop()
    t.join(timeout=5)

