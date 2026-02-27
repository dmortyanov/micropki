"""CLI tests for Sprint 2 subcommands (issue-intermediate, issue-cert, validate-chain, --csr)."""

import os

import pytest

from micropki.cli import main
from micropki.crypto_utils import generate_key
from micropki.csr import generate_csr, serialize_csr


@pytest.fixture()
def pki_with_root(tmp_path):
    """Set up a Root CA via CLI and return (out_dir, passphrase_file)."""
    out_dir = str(tmp_path / "pki")
    pf = tmp_path / "root.pass"
    pf.write_bytes(b"RootPass123!\n")

    rc = main([
        "ca", "init",
        "--subject", "CN=CLI Root CA,O=TestOrg",
        "--key-type", "rsa",
        "--key-size", "4096",
        "--passphrase-file", str(pf),
        "--out-dir", out_dir,
    ])
    assert rc == 0
    return out_dir, str(pf)


@pytest.fixture()
def pki_with_intermediate(pki_with_root, tmp_path):
    """Set up Root + Intermediate CA via CLI."""
    out_dir, root_pf = pki_with_root
    inter_pf = tmp_path / "inter.pass"
    inter_pf.write_bytes(b"InterPass456!\n")

    rc = main([
        "ca", "issue-intermediate",
        "--root-cert", os.path.join(out_dir, "certs", "ca.cert.pem"),
        "--root-key", os.path.join(out_dir, "private", "ca.key.pem"),
        "--root-pass-file", root_pf,
        "--subject", "CN=CLI Intermediate CA,O=TestOrg",
        "--key-type", "rsa",
        "--key-size", "4096",
        "--passphrase-file", str(inter_pf),
        "--out-dir", out_dir,
        "--validity-days", "1825",
        "--pathlen", "0",
    ])
    assert rc == 0
    return out_dir, root_pf, str(inter_pf)


class TestIssueIntermediateCLI:
    def test_success(self, pki_with_intermediate):
        out_dir, _, _ = pki_with_intermediate
        assert os.path.isfile(os.path.join(out_dir, "certs", "intermediate.cert.pem"))
        assert os.path.isfile(os.path.join(out_dir, "private", "intermediate.key.pem"))

    def test_nonexistent_root_cert(self, tmp_path):
        pf = tmp_path / "pass.txt"
        pf.write_bytes(b"pass\n")
        rc = main([
            "ca", "issue-intermediate",
            "--root-cert", str(tmp_path / "no.pem"),
            "--root-key", str(tmp_path / "no.key.pem"),
            "--root-pass-file", str(pf),
            "--subject", "CN=Test",
            "--passphrase-file", str(pf),
        ])
        assert rc != 0


class TestIssueCertCLI:
    def test_server_cert_success(self, pki_with_intermediate):
        out_dir, _, inter_pf = pki_with_intermediate
        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=test.example.com",
            "--san", "dns:test.example.com",
            "--san", "ip:192.168.1.10",
            "--out-dir", os.path.join(out_dir, "certs"),
            "--validity-days", "365",
        ])
        assert rc == 0
        assert os.path.isfile(
            os.path.join(out_dir, "certs", "test.example.com.cert.pem")
        )
        assert os.path.isfile(
            os.path.join(out_dir, "certs", "test.example.com.key.pem")
        )

    def test_client_cert_success(self, pki_with_intermediate):
        out_dir, _, inter_pf = pki_with_intermediate
        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "client",
            "--subject", "CN=Bob Jones",
            "--san", "email:bob@example.com",
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc == 0

    def test_code_signing_cert_success(self, pki_with_intermediate):
        out_dir, _, inter_pf = pki_with_intermediate
        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "code_signing",
            "--subject", "CN=Signer Tool",
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc == 0

    def test_server_without_san_fails(self, pki_with_intermediate):
        out_dir, _, inter_pf = pki_with_intermediate
        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=no-san.example.com",
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc != 0

    def test_nonexistent_ca_cert_fails(self, tmp_path):
        pf = tmp_path / "pass.txt"
        pf.write_bytes(b"pass\n")
        rc = main([
            "ca", "issue-cert",
            "--ca-cert", str(tmp_path / "no.pem"),
            "--ca-key", str(tmp_path / "no.key.pem"),
            "--ca-pass-file", str(pf),
            "--template", "server",
            "--subject", "CN=fail",
            "--san", "dns:fail.com",
        ])
        assert rc != 0


class TestValidateChainCLI:
    def test_valid_chain(self, pki_with_intermediate):
        out_dir, _, inter_pf = pki_with_intermediate

        main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=valid.example.com",
            "--san", "dns:valid.example.com",
            "--out-dir", os.path.join(out_dir, "certs"),
        ])

        rc = main([
            "ca", "validate-chain",
            "--cert", os.path.join(out_dir, "certs", "valid.example.com.cert.pem"),
            "--intermediate", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--root", os.path.join(out_dir, "certs", "ca.cert.pem"),
        ])
        assert rc == 0

    def test_invalid_chain_wrong_root(self, pki_with_intermediate, tmp_path):
        out_dir, _, inter_pf = pki_with_intermediate

        main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=chain-test.example.com",
            "--san", "dns:chain-test.example.com",
            "--out-dir", os.path.join(out_dir, "certs"),
        ])

        other_dir = str(tmp_path / "other_pki")
        pf2 = tmp_path / "other.pass"
        pf2.write_bytes(b"other\n")
        main([
            "ca", "init",
            "--subject", "CN=Other Root",
            "--passphrase-file", str(pf2),
            "--out-dir", other_dir,
        ])

        rc = main([
            "ca", "validate-chain",
            "--cert", os.path.join(out_dir, "certs", "chain-test.example.com.cert.pem"),
            "--intermediate", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--root", os.path.join(other_dir, "certs", "ca.cert.pem"),
        ])
        assert rc != 0


class TestIssueCertFromCSR:
    """CLI-11 / PKI-12: Sign an externally generated CSR."""

    def _write_csr(self, tmp_path, subject: str, is_ca: bool = False) -> str:
        key = generate_key("rsa", 2048)
        csr = generate_csr(key, subject, is_ca=is_ca)
        csr_path = str(tmp_path / "external.csr.pem")
        with open(csr_path, "wb") as f:
            f.write(serialize_csr(csr))
        return csr_path

    def test_server_cert_from_csr(self, pki_with_intermediate, tmp_path):
        out_dir, _, inter_pf = pki_with_intermediate
        csr_path = self._write_csr(tmp_path, "/CN=csr.example.com")

        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=csr.example.com",
            "--san", "dns:csr.example.com",
            "--csr", csr_path,
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc == 0
        assert os.path.isfile(
            os.path.join(out_dir, "certs", "csr.example.com.cert.pem")
        )
        assert not os.path.isfile(
            os.path.join(out_dir, "certs", "csr.example.com.key.pem")
        )

    def test_client_cert_from_csr(self, pki_with_intermediate, tmp_path):
        out_dir, _, inter_pf = pki_with_intermediate
        csr_path = self._write_csr(tmp_path, "/CN=Alice")

        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "client",
            "--subject", "CN=Alice",
            "--san", "email:alice@example.com",
            "--csr", csr_path,
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc == 0

    def test_csr_with_ca_true_rejected(self, pki_with_intermediate, tmp_path):
        """CSR requesting CA=TRUE must be rejected for end-entity certs."""
        out_dir, _, inter_pf = pki_with_intermediate
        csr_path = self._write_csr(tmp_path, "/CN=Evil CA", is_ca=True)

        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=evil.example.com",
            "--san", "dns:evil.example.com",
            "--csr", csr_path,
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc != 0

    def test_nonexistent_csr_fails(self, pki_with_intermediate):
        out_dir, _, inter_pf = pki_with_intermediate
        rc = main([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(out_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", inter_pf,
            "--template", "server",
            "--subject", "CN=fail.com",
            "--san", "dns:fail.com",
            "--csr", "/nonexistent/path.csr.pem",
            "--out-dir", os.path.join(out_dir, "certs"),
        ])
        assert rc != 0
