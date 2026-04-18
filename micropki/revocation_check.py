import logging
import datetime
import requests
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as x509_ocsp

logger = logging.getLogger(__name__)


def extract_ocsp_url(cert: x509.Certificate) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for desc in aia:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def extract_crl_urls(cert: x509.Certificate) -> list[str]:
    urls = []
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dp in cdp:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return urls


def _check_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    ocsp_url: str,
) -> tuple[str | None, str | None, datetime.datetime | None]:
    """Check OCSP status.
    Returns (status, reason, datetime) where status is 'good', 'revoked', 'unknown', or None on failure.
    """
    logger.info("Checking OCSP via %s", ocsp_url)
    try:
        # Build OCSP Request
        builder = x509_ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp = requests.post(
            ocsp_url,
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=5,
        )
        resp.raise_for_status()
        
        # Parse OCSP Response
        ocsp_resp = x509_ocsp.load_der_ocsp_response(resp.content)
        if ocsp_resp.response_status != x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
            logger.warning("OCSP Response was not successful: %s", ocsp_resp.response_status)
            return None, None, None

        if ocsp_resp.certificate_status == x509_ocsp.OCSPCertStatus.GOOD:
            return "good", None, None
        elif ocsp_resp.certificate_status == x509_ocsp.OCSPCertStatus.REVOKED:
            reason = ocsp_resp.revocation_reason.name if ocsp_resp.revocation_reason else "unspecified"
            return "revoked", reason, ocsp_resp.revocation_time_utc
        elif ocsp_resp.certificate_status == x509_ocsp.OCSPCertStatus.UNKNOWN:
            return "unknown", None, None

    except Exception as exc:
        logger.warning("OCSP check failed: %s", exc)
        
    return None, None, None


def _check_crl(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    crl_source: str,
) -> tuple[str | None, str | None, datetime.datetime | None]:
    """Check CRL status.
    Returns (status, reason, datetime).
    """
    logger.info("Checking CRL via %s", crl_source)
    try:
        crl_bytes = None
        parsed_url = urlparse(crl_source)
        if parsed_url.scheme in ("http", "https"):
            resp = requests.get(crl_source, timeout=5)
            resp.raise_for_status()
            crl_bytes = resp.content
        else:
            with open(crl_source, "rb") as f:
                crl_bytes = f.read()

        try:
            crl = x509.load_der_x509_crl(crl_bytes)
        except ValueError:
            crl = x509.load_pem_x509_crl(crl_bytes)

        if not crl.is_signature_valid(issuer.public_key()):
            logger.warning("CRL signature validation failed")
            return None, None, None

        now = datetime.datetime.now(datetime.timezone.utc)
        if crl.next_update_utc and crl.next_update_utc < now:
            logger.warning("CRL is expired (next_update: %s)", crl.next_update_utc)
            # Proceed anyway as per requirement: "may still be used"

        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked_cert:
            reason = "unspecified"
            try:
                crl_reason = revoked_cert.extensions.get_extension_for_class(x509.CRLReason)
                reason = crl_reason.value.reason.name
            except x509.ExtensionNotFound:
                pass
            return "revoked", reason, revoked_cert.revocation_date_utc
        else:
            return "good", None, None

    except Exception as exc:
        logger.warning("CRL check failed: %s", exc)
        return None, None, None


def check_status(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    crl_path_or_url: str | None = None,
    ocsp_url: str | None = None,
) -> tuple[str, str | None, datetime.datetime | None]:
    """Check revocation status using OCSP with fallback to CRL.
    Returns (status, reason, datetime) where status is 'good', 'revoked', or 'unknown'.
    """
    check_ocsp_url = ocsp_url or extract_ocsp_url(cert)
    
    if check_ocsp_url:
        status, reason, dt = _check_ocsp(cert, issuer, check_ocsp_url)
        if status in ("good", "revoked"):
            logger.info("OCSP check successful: %s", status)
            return status, reason, dt
        else:
            logger.info("OCSP check returned '%s' or failed. Falling back to CRL.", status)

    check_crl_urls = []
    if crl_path_or_url:
        check_crl_urls.append(crl_path_or_url)
    else:
        check_crl_urls.extend(extract_crl_urls(cert))

    for crl_url in check_crl_urls:
        status, reason, dt = _check_crl(cert, issuer, crl_url)
        if status in ("good", "revoked"):
            logger.info("CRL check successful: %s", status)
            return status, reason, dt

    logger.warning("Both OCSP and CRL checks failed or no distribution points found.")
    return "unknown", None, None
