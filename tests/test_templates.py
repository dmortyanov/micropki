"""Unit tests for certificate templates and SAN parsing (TEST-12 partial)."""

import ipaddress

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from micropki.templates import (
    SERVER_TEMPLATE,
    CLIENT_TEMPLATE,
    CODE_SIGNING_TEMPLATE,
    ParsedSAN,
    build_key_usage,
    build_san_extension,
    get_template,
    parse_san_strings,
    validate_san_for_template,
)


class TestGetTemplate:
    def test_server(self):
        t = get_template("server")
        assert t.name == "server"

    def test_client(self):
        t = get_template("client")
        assert t.name == "client"

    def test_code_signing(self):
        t = get_template("code_signing")
        assert t.name == "code_signing"

    def test_unknown(self):
        with pytest.raises(ValueError, match="Unknown template"):
            get_template("vpn")


class TestParseSAN:
    def test_dns(self):
        san = parse_san_strings(["dns:example.com", "dns:www.example.com"])
        assert san.dns_names == ["example.com", "www.example.com"]

    def test_ip(self):
        san = parse_san_strings(["ip:192.168.1.1", "ip:::1"])
        assert san.ip_addresses == [
            ipaddress.ip_address("192.168.1.1"),
            ipaddress.ip_address("::1"),
        ]

    def test_email(self):
        san = parse_san_strings(["email:alice@example.com"])
        assert san.emails == ["alice@example.com"]

    def test_uri(self):
        san = parse_san_strings(["uri:https://example.com"])
        assert san.uris == ["https://example.com"]

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid SAN format"):
            parse_san_strings(["no-colon-here"])

    def test_empty_value(self):
        with pytest.raises(ValueError, match="Empty value"):
            parse_san_strings(["dns:"])

    def test_unsupported_type(self):
        with pytest.raises(ValueError, match="Unsupported SAN type"):
            parse_san_strings(["x500:foo"])

    def test_invalid_ip(self):
        with pytest.raises(ValueError, match="Invalid IP"):
            parse_san_strings(["ip:not-an-ip"])


class TestValidateSANForTemplate:
    def test_server_requires_san(self):
        errors = validate_san_for_template(SERVER_TEMPLATE, ParsedSAN())
        assert any("requires at least one SAN" in e for e in errors)

    def test_server_accepts_dns_and_ip(self):
        san = parse_san_strings(["dns:example.com", "ip:10.0.0.1"])
        errors = validate_san_for_template(SERVER_TEMPLATE, san)
        assert errors == []

    def test_server_rejects_email(self):
        san = parse_san_strings(["email:a@example.com"])
        errors = validate_san_for_template(SERVER_TEMPLATE, san)
        assert any("email" in e for e in errors)

    def test_code_signing_rejects_ip(self):
        san = parse_san_strings(["ip:10.0.0.1"])
        errors = validate_san_for_template(CODE_SIGNING_TEMPLATE, san)
        assert any("ip" in e for e in errors)

    def test_client_allows_email(self):
        san = parse_san_strings(["email:a@example.com"])
        errors = validate_san_for_template(CLIENT_TEMPLATE, san)
        assert errors == []

    def test_client_does_not_require_san(self):
        errors = validate_san_for_template(CLIENT_TEMPLATE, ParsedSAN())
        assert errors == []


class TestBuildSANExtension:
    def test_dns_names(self):
        san = parse_san_strings(["dns:example.com", "dns:www.example.com"])
        ext = build_san_extension(san)
        assert ext is not None
        names = ext.get_values_for_type(x509.DNSName)
        assert names == ["example.com", "www.example.com"]

    def test_ip_addresses(self):
        san = parse_san_strings(["ip:10.0.0.1"])
        ext = build_san_extension(san)
        ips = ext.get_values_for_type(x509.IPAddress)
        assert ips == [ipaddress.ip_address("10.0.0.1")]

    def test_empty_san(self):
        ext = build_san_extension(ParsedSAN())
        assert ext is None


class TestBuildKeyUsage:
    def test_server_rsa(self):
        ku = build_key_usage(SERVER_TEMPLATE, is_rsa=True)
        assert ku.digital_signature is True
        assert ku.key_encipherment is True

    def test_server_ecc(self):
        ku = build_key_usage(SERVER_TEMPLATE, is_rsa=False)
        assert ku.digital_signature is True
        assert ku.key_encipherment is False

    def test_code_signing(self):
        ku = build_key_usage(CODE_SIGNING_TEMPLATE, is_rsa=True)
        assert ku.digital_signature is True
        assert ku.key_cert_sign is False
