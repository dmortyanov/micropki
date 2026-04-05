"""
Sprint 5 tests — OCSP Responder.

Covers TEST-28 through TEST-37 from Sprint 5 requirements:
- OCSP Signer Certificate profile validation
- OCSP good/revoked/unknown responses
- Nonce handling
- Malformed request handling
- Full PKI workflow with OCSP
"""

import os
import time
import threading
import urllib.request
import tempfile
import shutil
import logging

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp as x509_ocsp

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki_dir():
    """Create a temporary PKI directory tree for the Sprint 5 tests."""
    d = tempfile.mkdtemp(prefix="micropki_s5_")
    os.makedirs(os.path.join(d, "certs"), exist_ok=True)
    os.makedirs(os.path.join(d, "private"), exist_ok=True)
    os.makedirs(os.path.join(d, "secrets"), exist_ok=True)
    os.makedirs(os.path.join(d, "crl"), exist_ok=True)
    os.makedirs(os.path.join(d, "ocsp"), exist_ok=True)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def root_ca(pki_dir):
    """Initialize a Root CA."""
    from micropki.ca import init_root_ca

    logger = logging.getLogger("test_sprint5")
    pass_path = os.path.join(pki_dir, "secrets", "ca.pass")
    with open(pass_path, "w") as f:
        f.write("RootPass123")

    init_root_ca(
        subject_str="CN=Test Root CA,O=MicroPKI Test,C=US",
        key_type="rsa",
        key_size=4096,
        passphrase=b"RootPass123",
        out_dir=pki_dir,
        validity_days=3650,
        logger=logger,
    )

    return {
        "cert_path": os.path.join(pki_dir, "certs", "ca.cert.pem"),
        "key_path": os.path.join(pki_dir, "private", "ca.key.pem"),
        "pass_path": pass_path,
    }


@pytest.fixture(scope="module")
def intermediate_ca(pki_dir, root_ca):
    """Issue an Intermediate CA."""
    from micropki.ca import issue_intermediate_ca

    logger = logging.getLogger("test_sprint5")
    pass_path = os.path.join(pki_dir, "secrets", "intermediate.pass")
    with open(pass_path, "w") as f:
        f.write("IntermPass123")

    issue_intermediate_ca(
        root_cert_path=root_ca["cert_path"],
        root_key_path=root_ca["key_path"],
        root_passphrase=b"RootPass123",
        subject_str="CN=Test Intermediate CA,O=MicroPKI Test",
        key_type="rsa",
        key_size=4096,
        passphrase=b"IntermPass123",
        out_dir=pki_dir,
        validity_days=1825,
        path_length=0,
        logger=logger,
    )

    return {
        "cert_path": os.path.join(pki_dir, "certs", "intermediate.cert.pem"),
        "key_path": os.path.join(pki_dir, "private", "intermediate.key.pem"),
        "pass_path": pass_path,
    }


@pytest.fixture(scope="module")
def server_cert(pki_dir, intermediate_ca):
    """Issue a server certificate for OCSP testing."""
    from micropki.ca import issue_certificate

    logger = logging.getLogger("test_sprint5")

    issue_certificate(
        ca_cert_path=intermediate_ca["cert_path"],
        ca_key_path=intermediate_ca["key_path"],
        ca_passphrase=b"IntermPass123",
        template_name="server",
        subject_str="CN=test.example.com,O=MicroPKI Test",
        san_strings=["dns:test.example.com"],
        out_dir=os.path.join(pki_dir, "certs"),
        validity_days=365,
        logger=logger,
    )

    cert_path = os.path.join(pki_dir, "certs", "test.example.com.cert.pem")
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())

    return {
        "cert_path": cert_path,
        "serial_hex": format(cert.serial_number, "X"),
        "cert": cert,
    }


@pytest.fixture(scope="module")
def ocsp_cert(pki_dir, intermediate_ca):
    """Issue an OCSP responder certificate."""
    from micropki.ca import issue_ocsp_certificate

    logger = logging.getLogger("test_sprint5")
    out_dir = os.path.join(pki_dir, "certs")

    issue_ocsp_certificate(
        ca_cert_path=intermediate_ca["cert_path"],
        ca_key_path=intermediate_ca["key_path"],
        ca_passphrase=b"IntermPass123",
        subject_str="CN=OCSP Responder,O=MicroPKI Test",
        key_type="rsa",
        key_size=2048,
        out_dir=out_dir,
        validity_days=365,
        logger=logger,
    )

    cert_path = os.path.join(out_dir, "OCSP_Responder.cert.pem")
    key_path = os.path.join(out_dir, "OCSP_Responder.key.pem")

    return {
        "cert_path": cert_path,
        "key_path": key_path,
    }


@pytest.fixture(scope="module")
def db(pki_dir):
    """Initialize and return the certificate database."""
    from micropki.database import CertificateDatabase

    db_path = os.path.join(pki_dir, "micropki.db")
    database = CertificateDatabase(db_path)
    database.connect()
    database.init_schema()
    yield database
    database.close()


@pytest.fixture(scope="module")
def ocsp_server_port(pki_dir, intermediate_ca, ocsp_cert, db):
    """Start an OCSP responder in a background thread and return the port."""
    import socketserver
    from micropki.ocsp_responder import OCSPHandler
    from micropki.database import CertificateDatabase

    ca_cert = x509.load_pem_x509_certificate(
        open(intermediate_ca["cert_path"], "rb").read()
    )
    responder_cert = x509.load_pem_x509_certificate(
        open(ocsp_cert["cert_path"], "rb").read()
    )
    responder_key = serialization.load_pem_private_key(
        open(ocsp_cert["key_path"], "rb").read(), password=None
    )

    # Use a fresh DB connection for the server thread
    db_path = os.path.join(pki_dir, "micropki.db")
    server_db = CertificateDatabase(db_path)
    server_db.connect()
    server_db.init_schema()

    handler = lambda *args, **kwargs: OCSPHandler(
        *args,
        db=server_db,
        ca_cert=ca_cert,
        responder_cert=responder_cert,
        responder_key=responder_key,
        cache_ttl=60,
        ocsp_log_path=None,
        **kwargs,
    )

    # Find a free port
    server = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)  # Let the server start

    yield port

    server.shutdown()
    server.server_close()
    server_db.close()


def _build_ocsp_request(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    add_nonce: bool = True,
) -> bytes:
    """Build a DER-encoded OCSP request."""
    builder = x509_ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
    if add_nonce:
        builder = builder.add_extension(x509.OCSPNonce(os.urandom(16)), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def _send_ocsp_request(port: int, der_data: bytes) -> bytes:
    """Send an OCSP request to the responder and return the response bytes."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/ocsp",
        data=der_data,
        headers={"Content-Type": "application/ocsp-request"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# TEST-28: OCSP Signer Certificate Profile
# ---------------------------------------------------------------------------


class TestOCSPSignerCertificate:
    """TEST-28: Verify OCSP signer certificate has correct extensions."""

    def test_ocsp_cert_is_not_ca(self, ocsp_cert):
        cert = x509.load_pem_x509_certificate(
            open(ocsp_cert["cert_path"], "rb").read()
        )
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is False

    def test_ocsp_cert_key_usage(self, ocsp_cert):
        cert = x509.load_pem_x509_certificate(
            open(ocsp_cert["cert_path"], "rb").read()
        )
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.digital_signature is True
        assert ku.value.key_cert_sign is False
        assert ku.value.crl_sign is False

    def test_ocsp_cert_extended_key_usage(self, ocsp_cert):
        cert = x509.load_pem_x509_certificate(
            open(ocsp_cert["cert_path"], "rb").read()
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oid_strings = [oid.dotted_string for oid in eku.value]
        assert "1.3.6.1.5.5.7.3.9" in oid_strings  # id-kp-OCSPSigning

    def test_ocsp_key_is_unencrypted(self, ocsp_cert):
        """OSC-3: Private key must be stored unencrypted."""
        key_data = open(ocsp_cert["key_path"], "rb").read()
        # Should load without a password
        key = serialization.load_pem_private_key(key_data, password=None)
        assert key is not None


# ---------------------------------------------------------------------------
# TEST-29: OCSP Good Certificate Response
# ---------------------------------------------------------------------------


class TestOCSPGoodResponse:
    """TEST-29: Query OCSP for a valid certificate — expect 'good'."""

    def test_good_response(self, ocsp_server_port, server_cert, intermediate_ca):
        issuer_cert = x509.load_pem_x509_certificate(
            open(intermediate_ca["cert_path"], "rb").read()
        )
        der_req = _build_ocsp_request(server_cert["cert"], issuer_cert, add_nonce=True)
        der_resp = _send_ocsp_request(ocsp_server_port, der_req)

        resp = x509_ocsp.load_der_ocsp_response(der_resp)
        assert resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == x509_ocsp.OCSPCertStatus.GOOD


# ---------------------------------------------------------------------------
# TEST-30: OCSP Revoked Certificate Response
# ---------------------------------------------------------------------------


class TestOCSPRevokedResponse:
    """TEST-30: Revoke a certificate, then query OCSP — expect 'revoked'."""

    def test_revoked_response(self, ocsp_server_port, server_cert, intermediate_ca, db):
        serial = server_cert["serial_hex"]

        # Revoke the certificate
        from micropki.revocation import revoke_certificate
        revoke_certificate(db, serial, "keycompromise")

        # Give DB a moment
        time.sleep(0.2)

        issuer_cert = x509.load_pem_x509_certificate(
            open(intermediate_ca["cert_path"], "rb").read()
        )
        der_req = _build_ocsp_request(server_cert["cert"], issuer_cert, add_nonce=True)
        der_resp = _send_ocsp_request(ocsp_server_port, der_req)

        resp = x509_ocsp.load_der_ocsp_response(der_resp)
        assert resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == x509_ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time is not None
        assert resp.revocation_reason is not None


# ---------------------------------------------------------------------------
# TEST-31: OCSP Unknown Certificate Response
# ---------------------------------------------------------------------------


class TestOCSPUnknownResponse:
    """TEST-31: Query for a non-existent serial — expect 'unknown'."""

    def test_unknown_response(self, ocsp_server_port, intermediate_ca):
        issuer_cert = x509.load_pem_x509_certificate(
            open(intermediate_ca["cert_path"], "rb").read()
        )

        # Create a dummy certificate with a random serial for the request
        import datetime as _dt
        from cryptography.x509.ocsp import OCSPRequestBuilder

        fake_key = rsa.generate_private_key(65537, 2048)
        fake_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Fake")]))
            .issuer_name(issuer_cert.subject)
            .public_key(fake_key.public_key())
            .serial_number(999999999999999)
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(
                _dt.datetime.now(_dt.timezone.utc)
                + _dt.timedelta(days=1)
            )
            .sign(fake_key, hashes.SHA256())
        )

        der_req = _build_ocsp_request(fake_cert, issuer_cert, add_nonce=False)
        der_resp = _send_ocsp_request(ocsp_server_port, der_req)

        resp = x509_ocsp.load_der_ocsp_response(der_resp)
        # The serial doesn't exist in DB, but the issuer matches,
        # so we expect SUCCESSFUL response with UNKNOWN status
        assert resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == x509_ocsp.OCSPCertStatus.UNKNOWN


# ---------------------------------------------------------------------------
# TEST-32: OCSP Nonce Handling
# ---------------------------------------------------------------------------


class TestOCSPNonce:
    """TEST-32: Nonce must be echoed when present, absent when not sent."""

    def test_nonce_echoed(self, ocsp_server_port, server_cert, intermediate_ca, ocsp_cert):
        issuer_cert = x509.load_pem_x509_certificate(
            open(intermediate_ca["cert_path"], "rb").read()
        )

        # Build request WITH nonce
        nonce_value = os.urandom(16)
        builder = x509_ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(server_cert["cert"], issuer_cert, hashes.SHA1())
        builder = builder.add_extension(x509.OCSPNonce(nonce_value), critical=False)
        der_req = builder.build().public_bytes(serialization.Encoding.DER)

        der_resp = _send_ocsp_request(ocsp_server_port, der_req)
        resp = x509_ocsp.load_der_ocsp_response(der_resp)

        assert resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL

        # Check nonce is echoed
        try:
            resp_nonce = resp.extensions.get_extension_for_class(x509.OCSPNonce)
            assert resp_nonce.value.nonce == nonce_value
        except x509.ExtensionNotFound:
            pytest.fail("Response should contain echoed nonce")

    def test_no_nonce_when_not_sent(self, ocsp_server_port, server_cert, intermediate_ca):
        issuer_cert = x509.load_pem_x509_certificate(
            open(intermediate_ca["cert_path"], "rb").read()
        )

        # Build request WITHOUT nonce
        der_req = _build_ocsp_request(server_cert["cert"], issuer_cert, add_nonce=False)
        der_resp = _send_ocsp_request(ocsp_server_port, der_req)
        resp = x509_ocsp.load_der_ocsp_response(der_resp)

        assert resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL

        # Response should NOT contain nonce
        with pytest.raises(x509.ExtensionNotFound):
            resp.extensions.get_extension_for_class(x509.OCSPNonce)


# ---------------------------------------------------------------------------
# TEST-34: Negative Test — Malformed Request
# ---------------------------------------------------------------------------


class TestOCSPMalformedRequest:
    """TEST-34: Sending garbage data should return malformedRequest or HTTP 400."""

    def test_garbage_data(self, ocsp_server_port):
        garbage = b"\x00\x01\x02\x03\x04GARBAGE"
        req = urllib.request.Request(
            f"http://127.0.0.1:{ocsp_server_port}/ocsp",
            data=garbage,
            headers={"Content-Type": "application/ocsp-request"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            der_resp = resp.read()

        parsed = x509_ocsp.load_der_ocsp_response(der_resp)
        assert parsed.response_status == x509_ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_wrong_content_type(self, ocsp_server_port):
        req = urllib.request.Request(
            f"http://127.0.0.1:{ocsp_server_port}/ocsp",
            data=b"hello",
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                der_resp = resp.read()
            parsed = x509_ocsp.load_der_ocsp_response(der_resp)
            assert parsed.response_status == x509_ocsp.OCSPResponseStatus.MALFORMED_REQUEST
        except urllib.error.HTTPError as e:
            # HTTP 400 is also acceptable
            assert e.code == 400


# ---------------------------------------------------------------------------
# TEST-37: Full PKI Workflow with OCSP (Integration)
# ---------------------------------------------------------------------------


class TestFullPKIWorkflowWithOCSP:
    """TEST-37: Complete scenario: Root → Intermediate → issue cert →
    issue OCSP cert → start responder → query good → revoke → query revoked.
    """

    def test_full_workflow(self):
        """End-to-end integration test in a fresh temporary PKI."""
        tmp = tempfile.mkdtemp(prefix="micropki_s5_full_")
        try:
            from micropki.ca import init_root_ca, issue_intermediate_ca, issue_certificate, issue_ocsp_certificate
            from micropki.database import CertificateDatabase
            from micropki.revocation import revoke_certificate
            from micropki.ocsp_responder import OCSPHandler
            import socketserver

            lgr = logging.getLogger("test_full_workflow")

            os.makedirs(os.path.join(tmp, "secrets"), exist_ok=True)
            with open(os.path.join(tmp, "secrets", "ca.pass"), "w") as f:
                f.write("RootPassFull")
            with open(os.path.join(tmp, "secrets", "intermediate.pass"), "w") as f:
                f.write("InterPassFull")

            # Step 1: Root CA
            init_root_ca(
                subject_str="CN=Full Root CA,O=Test",
                key_type="rsa", key_size=4096,
                passphrase=b"RootPassFull",
                out_dir=tmp, validity_days=3650, logger=lgr,
            )

            # Step 2: Intermediate CA
            issue_intermediate_ca(
                root_cert_path=os.path.join(tmp, "certs", "ca.cert.pem"),
                root_key_path=os.path.join(tmp, "private", "ca.key.pem"),
                root_passphrase=b"RootPassFull",
                subject_str="CN=Full Intermediate CA,O=Test",
                key_type="rsa", key_size=4096,
                passphrase=b"InterPassFull",
                out_dir=tmp, validity_days=1825, path_length=0, logger=lgr,
            )

            # Step 3: Issue server cert
            issue_certificate(
                ca_cert_path=os.path.join(tmp, "certs", "intermediate.cert.pem"),
                ca_key_path=os.path.join(tmp, "private", "intermediate.key.pem"),
                ca_passphrase=b"InterPassFull",
                template_name="server",
                subject_str="CN=web.example.com,O=Test",
                san_strings=["dns:web.example.com"],
                out_dir=os.path.join(tmp, "certs"),
                validity_days=365, logger=lgr,
            )

            # Step 4: Issue OCSP responder cert
            issue_ocsp_certificate(
                ca_cert_path=os.path.join(tmp, "certs", "intermediate.cert.pem"),
                ca_key_path=os.path.join(tmp, "private", "intermediate.key.pem"),
                ca_passphrase=b"InterPassFull",
                subject_str="CN=OCSP Signer,O=Test",
                key_type="rsa", key_size=2048,
                out_dir=os.path.join(tmp, "certs"),
                validity_days=365, logger=lgr,
            )

            # Load certs + key
            ca_cert = x509.load_pem_x509_certificate(
                open(os.path.join(tmp, "certs", "intermediate.cert.pem"), "rb").read()
            )
            server_cert = x509.load_pem_x509_certificate(
                open(os.path.join(tmp, "certs", "web.example.com.cert.pem"), "rb").read()
            )
            ocsp_cert = x509.load_pem_x509_certificate(
                open(os.path.join(tmp, "certs", "OCSP_Signer.cert.pem"), "rb").read()
            )
            ocsp_key = serialization.load_pem_private_key(
                open(os.path.join(tmp, "certs", "OCSP_Signer.key.pem"), "rb").read(),
                password=None,
            )

            # Step 5: Start OCSP server
            db = CertificateDatabase(os.path.join(tmp, "micropki.db"))
            db.connect()
            db.init_schema()

            handler = lambda *args, **kwargs: OCSPHandler(
                *args, db=db, ca_cert=ca_cert,
                responder_cert=ocsp_cert, responder_key=ocsp_key,
                cache_ttl=60, ocsp_log_path=None, **kwargs,
            )
            srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            time.sleep(0.3)

            # Step 6: Query — should be GOOD
            der_req = _build_ocsp_request(server_cert, ca_cert, add_nonce=True)
            der_resp = _send_ocsp_request(port, der_req)
            resp = x509_ocsp.load_der_ocsp_response(der_resp)
            assert resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp.certificate_status == x509_ocsp.OCSPCertStatus.GOOD

            # Step 7: Revoke
            serial = format(server_cert.serial_number, "X")
            revoke_certificate(db, serial, "keycompromise")
            time.sleep(0.2)

            # Step 8: Query — should be REVOKED
            der_req2 = _build_ocsp_request(server_cert, ca_cert, add_nonce=True)
            der_resp2 = _send_ocsp_request(port, der_req2)
            resp2 = x509_ocsp.load_der_ocsp_response(der_resp2)
            assert resp2.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp2.certificate_status == x509_ocsp.OCSPCertStatus.REVOKED

            srv.shutdown()
            srv.server_close()
            db.close()

        finally:
            shutil.rmtree(tmp, ignore_errors=True)
