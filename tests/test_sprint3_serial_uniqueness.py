import os

import pytest

from micropki.cli import main
from micropki.database import CertificateDatabase


def _setup_ecc_pki(tmp_path):
    pki_dir = tmp_path / "pki"
    secrets_dir = pki_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    root_pass = secrets_dir / "root.pass"
    inter_pass = secrets_dir / "intermediate.pass"
    root_pass.write_bytes(b"RootPass123!\n")
    inter_pass.write_bytes(b"InterPass456!\n")

    # Root CA (ECC)
    assert (
        main(
            [
                "ca",
                "init",
                "--subject",
                "CN=Stress Root CA,O=TestOrg",
                "--key-type",
                "ecc",
                "--key-size",
                "384",
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

    # Intermediate CA (ECC)
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
                "CN=Stress Intermediate CA,O=TestOrg",
                "--key-type",
                "ecc",
                "--key-size",
                "384",
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

    return str(pki_dir), str(inter_pass)


def test_sprint3_serial_uniqueness_stress(tmp_path):
    pki_dir, inter_pass = _setup_ecc_pki(tmp_path)
    cert_dir = os.path.join(pki_dir, "certs")

    # Issue many leaf certificates quickly (client template doesn't require SAN).
    for i in range(100):
        rc = main(
            [
                "ca",
                "issue-cert",
                "--ca-cert",
                os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
                "--ca-key",
                os.path.join(pki_dir, "private", "intermediate.key.pem"),
                "--ca-pass-file",
                inter_pass,
                "--template",
                "client",
                "--subject",
                f"CN=stress-client-{i},O=TestOrg",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "10",
            ]
        )
        assert rc == 0

    db = CertificateDatabase(os.path.join(pki_dir, "micropki.db"))
    db.connect()
    db.init_schema()
    try:
        records = db.list_certificates(status="valid")
        serials = [r["serial_hex"] for r in records]
        assert len(serials) == len(set(serials))
        assert len(records) >= 101  # intermediate + 100 leaf certs
    finally:
        db.close()


def test_sprint3_duplicate_serial_insertion_rejected(tmp_path):
    pki_dir, inter_pass = _setup_ecc_pki(tmp_path)
    cert_dir = os.path.join(pki_dir, "certs")

    # Issue a single leaf certificate.
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
                inter_pass,
                "--template",
                "client",
                "--subject",
                "CN=dup-client,O=TestOrg",
                "--out-dir",
                cert_dir,
                "--validity-days",
                "10",
            ]
        )
        == 0
    )

    db_path = os.path.join(pki_dir, "micropki.db")
    db = CertificateDatabase(db_path)
    db.connect()
    db.init_schema()

    try:
        records = db.list_certificates(status="valid")
        rec = next(r for r in records if "CN=dup-client" in r["subject"])
        with pytest.raises(ValueError):
            db.insert_certificate(
                serial_hex=rec["serial_hex"],
                subject="CN=dup-client-2,O=TestOrg",
                issuer=rec["issuer"],
                not_before=rec["not_before"],
                not_after=rec["not_after"],
                cert_pem=rec["cert_pem"],
                status="valid",
            )
    finally:
        db.close()

