import os

import pytest

from micropki.cli import main
from micropki.database import CertificateDatabase


def _issue_leaf_certs(pki_dir: str) -> None:
    cert_dir = os.path.join(pki_dir, "certs")

    # server (requires SAN)
    assert (
        main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
                "--ca-key",
                os.path.join(pki_dir, "private", "intermediate.key.pem"),
                "--ca-pass-file",
                os.path.join(pki_dir, "secrets", "intermediate.pass"),
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
                os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
                "--ca-key",
                os.path.join(pki_dir, "private", "intermediate.key.pem"),
                "--ca-pass-file",
                os.path.join(pki_dir, "secrets", "intermediate.pass"),
                "--template",
                "server",
                "--subject",
                "CN=server2.example.com,O=TestOrg",
                "--san",
                "dns:server2.example.com",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "30",
            ]
        )
        == 0
    )

    # client (doesn't require SAN, but allowed types include email)
    assert (
        main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
                "--ca-key",
                os.path.join(pki_dir, "private", "intermediate.key.pem"),
                "--ca-pass-file",
                os.path.join(pki_dir, "secrets", "intermediate.pass"),
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
                os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
                "--ca-key",
                os.path.join(pki_dir, "private", "intermediate.key.pem"),
                "--ca-pass-file",
                os.path.join(pki_dir, "secrets", "intermediate.pass"),
                "--template",
                "client",
                "--subject",
                "CN=client2,O=TestOrg",
                "--san",
                "email:client2@example.com",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "30",
            ]
        )
        == 0
    )

    # code_signing
    assert (
        main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
                "--ca-key",
                os.path.join(pki_dir, "private", "intermediate.key.pem"),
                "--ca-pass-file",
                os.path.join(pki_dir, "secrets", "intermediate.pass"),
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


def _setup_pki(tmp_path) -> str:
    # We use relative `./pki/...` paths for Sprint 3 default DB lookup in CLI.
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
                "CN=CLI Root CA,O=TestOrg,C=US",
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
                "CN=CLI Intermediate CA,O=TestOrg",
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

    _issue_leaf_certs(str(pki_dir))

    return str(pki_dir)


def test_sprint3_db_insertion_and_serial_uniqueness(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pki_dir = _setup_pki(tmp_path)

    db = CertificateDatabase(os.path.join(pki_dir, "micropki.db"))
    db.connect()
    db.init_schema()
    try:
        records = db.list_certificates(status="valid")
        assert len(records) >= 6  # intermediate + 5 leaf certs

        serials = [r["serial_hex"] for r in records]
        assert len(serials) == len(set(serials)), "serial_hex values must be unique"

        for r in records:
            assert r["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
            assert r["not_before"] is not None
            assert r["not_after"] is not None
    finally:
        db.close()


def test_sprint3_cli_list_and_show_cert(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pki_dir = _setup_pki(tmp_path)

    db = CertificateDatabase(os.path.join(pki_dir, "micropki.db"))
    db.connect()
    db.init_schema()
    try:
        records = db.list_certificates(status="valid")
        server1 = next(r for r in records if "CN=server1.example.com" in r["subject"])
        server1_serial = server1["serial_hex"]
    finally:
        db.close()

    rc = main(["ca", "list-certs", "--status", "valid", "--format", "table"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CN=server1.example.com" in out

    rc = main(["ca", "show-cert", server1_serial])
    assert rc == 0
    pem_out = capsys.readouterr().out
    assert pem_out.strip() == server1["cert_pem"].strip()

