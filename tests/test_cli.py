"""Tests for the CLI parser and edge cases (TEST-4, TEST-5)."""

import os

import pytest

from micropki.cli import build_parser, main, validate_args


class TestCLIValidation:
    """TEST-4: Negative / edge-case scenarios."""

    def test_missing_subject(self, passphrase_file, tmp_out_dir):
        with pytest.raises(SystemExit) as exc_info:
            main(["ca", "init", "--passphrase-file", passphrase_file, "--out-dir", tmp_out_dir])
        assert exc_info.value.code != 0

    def test_ecc_with_wrong_key_size(self, passphrase_file, tmp_out_dir):
        exit_code = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "ecc",
            "--key-size", "256",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
        ])
        assert exit_code != 0

    def test_rsa_with_wrong_key_size(self, passphrase_file, tmp_out_dir):
        exit_code = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "rsa",
            "--key-size", "2048",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
        ])
        assert exit_code != 0

    def test_nonexistent_passphrase_file(self, tmp_out_dir):
        exit_code = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--passphrase-file", "/nonexistent/path/pass.txt",
            "--out-dir", tmp_out_dir,
        ])
        assert exit_code != 0

    def test_negative_validity(self, passphrase_file, tmp_out_dir):
        exit_code = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
            "--validity-days", "-10",
        ])
        assert exit_code != 0

    def test_no_command_shows_help(self, capsys):
        exit_code = main([])
        assert exit_code != 0


class TestCLISuccess:
    def test_rsa_init_success(self, passphrase_file, tmp_out_dir):
        exit_code = main([
            "ca", "init",
            "--subject", "/CN=CLI Test CA",
            "--key-type", "rsa",
            "--key-size", "4096",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
        ])
        assert exit_code == 0
        assert os.path.isfile(os.path.join(tmp_out_dir, "private", "ca.key.pem"))
        assert os.path.isfile(os.path.join(tmp_out_dir, "certs", "ca.cert.pem"))
        assert os.path.isfile(os.path.join(tmp_out_dir, "policy.txt"))

    def test_ecc_init_success(self, passphrase_file, tmp_out_dir):
        exit_code = main([
            "ca", "init",
            "--subject", "CN=ECC CLI CA,O=Test",
            "--key-type", "ecc",
            "--key-size", "384",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
        ])
        assert exit_code == 0

    def test_force_overwrite(self, passphrase_file, tmp_out_dir):
        args = [
            "ca", "init",
            "--subject", "/CN=Force CA",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
        ]
        assert main(args) == 0
        assert main(args + ["--force"]) == 0

    def test_no_force_refuses_overwrite(self, passphrase_file, tmp_out_dir):
        args = [
            "ca", "init",
            "--subject", "/CN=No Force CA",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
        ]
        assert main(args) == 0
        assert main(args) != 0

    def test_log_file_created(self, passphrase_file, tmp_out_dir, tmp_path):
        log_file = str(tmp_path / "test.log")
        exit_code = main([
            "ca", "init",
            "--subject", "/CN=Log CA",
            "--passphrase-file", passphrase_file,
            "--out-dir", tmp_out_dir,
            "--log-file", log_file,
        ])
        assert exit_code == 0
        assert os.path.isfile(log_file)
        content = open(log_file, encoding="utf-8").read()
        assert "Key generation completed" in content
        assert "Certificate signing completed" in content
        assert "TestPassphrase" not in content
