"""Certificate templates and SAN parsing for end-entity certificates.

Three templates are supported: ``server``, ``client``, ``code_signing``.
Each template defines the correct Key Usage, Extended Key Usage, and
allowed SAN types per RFC 5280.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Sequence

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


@dataclass(frozen=True)
class _KeyUsageSpec:
    digital_signature: bool = False
    key_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False


@dataclass(frozen=True)
class CertificateTemplate:
    name: str
    key_usage: _KeyUsageSpec
    extended_key_usage: list[x509.ObjectIdentifier]
    allowed_san_types: frozenset[str]
    san_required: bool = False

    # For RSA keys, allow key_encipherment override
    key_usage_rsa_override: _KeyUsageSpec | None = None


SERVER_TEMPLATE = CertificateTemplate(
    name="server",
    key_usage=_KeyUsageSpec(digital_signature=True),
    key_usage_rsa_override=_KeyUsageSpec(
        digital_signature=True,
        key_encipherment=True,
    ),
    extended_key_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
    allowed_san_types=frozenset({"dns", "ip"}),
    san_required=True,
)

CLIENT_TEMPLATE = CertificateTemplate(
    name="client",
    key_usage=_KeyUsageSpec(digital_signature=True),
    extended_key_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
    allowed_san_types=frozenset({"dns", "email", "ip", "uri"}),
    san_required=False,
)

CODE_SIGNING_TEMPLATE = CertificateTemplate(
    name="code_signing",
    key_usage=_KeyUsageSpec(digital_signature=True),
    extended_key_usage=[ExtendedKeyUsageOID.CODE_SIGNING],
    allowed_san_types=frozenset({"dns", "uri"}),
    san_required=False,
)

TEMPLATES: dict[str, CertificateTemplate] = {
    "server": SERVER_TEMPLATE,
    "client": CLIENT_TEMPLATE,
    "code_signing": CODE_SIGNING_TEMPLATE,
}


def get_template(name: str) -> CertificateTemplate:
    """Return a template by name, raising ValueError if unknown."""
    tpl = TEMPLATES.get(name)
    if tpl is None:
        raise ValueError(
            f"Unknown template '{name}'. Available: {', '.join(TEMPLATES)}"
        )
    return tpl


@dataclass
class ParsedSAN:
    dns_names: list[str] = field(default_factory=list)
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(
        default_factory=list
    )
    emails: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)


def parse_san_strings(san_strings: Sequence[str]) -> ParsedSAN:
    """Parse SAN entries of the form ``type:value``.

    Supported types: ``dns``, ``ip``, ``email``, ``uri``.
    """
    result = ParsedSAN()
    for entry in san_strings:
        if ":" not in entry:
            raise ValueError(f"Invalid SAN format (expected type:value): '{entry}'")
        san_type, value = entry.split(":", 1)
        san_type = san_type.strip().lower()
        value = value.strip()
        if not value:
            raise ValueError(f"Empty value for SAN type '{san_type}'")

        if san_type == "dns":
            result.dns_names.append(value)
        elif san_type == "ip":
            try:
                result.ip_addresses.append(ipaddress.ip_address(value))
            except ValueError:
                raise ValueError(f"Invalid IP address in SAN: '{value}'")
        elif san_type == "email":
            result.emails.append(value)
        elif san_type == "uri":
            result.uris.append(value)
        else:
            raise ValueError(
                f"Unsupported SAN type '{san_type}'. Supported: dns, ip, email, uri"
            )

    return result


def validate_san_for_template(
    template: CertificateTemplate,
    parsed_san: ParsedSAN,
) -> list[str]:
    """Validate that the parsed SAN entries are compatible with the template.

    Returns a list of error messages (empty means valid).
    """
    errors: list[str] = []
    present_types: set[str] = set()

    if parsed_san.dns_names:
        present_types.add("dns")
    if parsed_san.ip_addresses:
        present_types.add("ip")
    if parsed_san.emails:
        present_types.add("email")
    if parsed_san.uris:
        present_types.add("uri")

    disallowed = present_types - template.allowed_san_types
    if disallowed:
        errors.append(
            f"Template '{template.name}' does not allow SAN types: "
            f"{', '.join(sorted(disallowed))}. "
            f"Allowed: {', '.join(sorted(template.allowed_san_types))}"
        )

    if template.san_required and not present_types:
        errors.append(
            f"Template '{template.name}' requires at least one SAN entry "
            f"(allowed types: {', '.join(sorted(template.allowed_san_types))})"
        )

    return errors


def build_san_extension(parsed_san: ParsedSAN) -> x509.SubjectAlternativeName | None:
    """Build an x509.SubjectAlternativeName extension from parsed SANs.

    Returns None if no SAN entries are present.
    """
    names: list[x509.GeneralName] = []

    for dns in parsed_san.dns_names:
        names.append(x509.DNSName(dns))
    for ip_addr in parsed_san.ip_addresses:
        names.append(x509.IPAddress(ip_addr))
    for email in parsed_san.emails:
        names.append(x509.RFC822Name(email))
    for uri in parsed_san.uris:
        names.append(x509.UniformResourceIdentifier(uri))

    if not names:
        return None
    return x509.SubjectAlternativeName(names)


def build_key_usage(template: CertificateTemplate, is_rsa: bool) -> x509.KeyUsage:
    """Build a KeyUsage extension based on template and key type."""
    spec = template.key_usage
    if is_rsa and template.key_usage_rsa_override is not None:
        spec = template.key_usage_rsa_override

    return x509.KeyUsage(
        digital_signature=spec.digital_signature,
        key_encipherment=spec.key_encipherment,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=spec.key_agreement,
        key_cert_sign=spec.key_cert_sign,
        crl_sign=spec.crl_sign,
        encipher_only=False,
        decipher_only=False,
    )
