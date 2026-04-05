"""
OCSP Responder HTTP server for MicroPKI.

Provides a standalone HTTP server that handles OCSP requests
via POST method. Can be run independently on its own port.

Logging follows OCSP-8: timestamp, client IP, serial(s), response status, processing time.
"""

import http.server
import socketserver
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp as x509_ocsp

from .database import CertificateDatabase
from .ocsp import process_ocsp_request, build_error_response, OCSP_RESPONSE_STATUS_MALFORMED_REQUEST

logger = logging.getLogger(__name__)


class OCSPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for OCSP responder.

    Accepts POST requests with Content-Type application/ocsp-request
    and returns application/ocsp-response.
    """

    def __init__(self, *args, **kwargs):
        self.db: Optional[CertificateDatabase] = kwargs.pop("db", None)
        self.ca_cert: Optional[x509.Certificate] = kwargs.pop("ca_cert", None)
        self.responder_cert: Optional[x509.Certificate] = kwargs.pop("responder_cert", None)
        self.responder_key = kwargs.pop("responder_key", None)
        self.cache_ttl: int = kwargs.pop("cache_ttl", 60)
        self.ocsp_log_path: Optional[str] = kwargs.pop("ocsp_log_path", None)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        """Override to use our logger instead of stderr."""
        message = format % args
        logger.info("[OCSP-HTTP] %s - %s", self.client_address[0], message)

    def _send_ocsp_response(self, response_der: bytes, http_status: int = 200) -> None:
        """Send an OCSP response with proper headers."""
        self.send_response(http_status)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(response_der)))
        self.send_header("Cache-Control", f"max-age={self.cache_ttl}, public, no-transform")
        self.end_headers()
        self.wfile.write(response_der)

    def _log_ocsp_request(
        self,
        serial_hex: str,
        response_status: str,
        processing_time_ms: float,
        error: Optional[str] = None,
    ) -> None:
        """Log OCSP request details in JSON format (LOG-12, OCSP-8)."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z",
            "client_ip": self.client_address[0] if self.client_address else None,
            "serial": serial_hex,
            "response_status": response_status,
            "processing_time_ms": round(processing_time_ms, 2),
        }
        if error:
            record["error"] = error

        log_line = json.dumps(record, ensure_ascii=False)

        if response_status in ("error", "malformed", "internalError", "unauthorized"):
            logger.error("OCSP request: %s", log_line)
        else:
            logger.info("OCSP request: %s", log_line)

        if self.ocsp_log_path:
            try:
                with open(self.ocsp_log_path, "a", encoding="utf-8") as f:
                    f.write(log_line + "\n")
            except Exception:
                pass  # logging must never break the server

    def do_POST(self) -> None:
        """Handle POST request for OCSP."""
        start_time = time.monotonic()

        # Check path — accept / and /ocsp
        path = self.path.rstrip("/")
        if path not in ("", "/ocsp"):
            self._send_ocsp_response(
                build_error_response(OCSP_RESPONSE_STATUS_MALFORMED_REQUEST), 404
            )
            self._log_ocsp_request("N/A", "not_found", (time.monotonic() - start_time) * 1000)
            return

        # Check Content-Type
        content_type = self.headers.get("Content-Type", "")
        if "application/ocsp-request" not in content_type:
            self._send_ocsp_response(
                build_error_response(OCSP_RESPONSE_STATUS_MALFORMED_REQUEST), 400
            )
            self._log_ocsp_request(
                "N/A", "malformed",
                (time.monotonic() - start_time) * 1000,
                error="Invalid Content-Type",
            )
            return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0 or content_length > 65536:
            self._send_ocsp_response(
                build_error_response(OCSP_RESPONSE_STATUS_MALFORMED_REQUEST), 400
            )
            self._log_ocsp_request(
                "N/A", "malformed",
                (time.monotonic() - start_time) * 1000,
                error="Invalid Content-Length",
            )
            return

        der_data = self.rfile.read(content_length)

        # Extract serial for logging before full processing
        serial_hex = "N/A"
        try:
            from .ocsp import parse_ocsp_request
            ocsp_req = parse_ocsp_request(der_data)
            serial_hex = format(ocsp_req.serial_number, "X")
        except Exception:
            pass

        # Process the OCSP request
        try:
            response_der = process_ocsp_request(
                der_data=der_data,
                db=self.db,
                ca_cert=self.ca_cert,
                responder_cert=self.responder_cert,
                responder_key=self.responder_key,
                cache_ttl=self.cache_ttl,
            )
        except Exception as exc:
            logger.exception("Unhandled exception in OCSP processing: %s", exc)
            from .ocsp import OCSP_RESPONSE_STATUS_INTERNAL_ERROR
            response_der = build_error_response(OCSP_RESPONSE_STATUS_INTERNAL_ERROR)
            self._send_ocsp_response(response_der, 200)
            self._log_ocsp_request(
                serial_hex, "internalError",
                (time.monotonic() - start_time) * 1000,
                error=str(exc),
            )
            return

        # Determine response status for logging
        response_status = "unknown"
        try:
            parsed_resp = x509_ocsp.load_der_ocsp_response(response_der)
            if parsed_resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
                cert_status = parsed_resp.certificate_status
                if cert_status == x509_ocsp.OCSPCertStatus.GOOD:
                    response_status = "good"
                elif cert_status == x509_ocsp.OCSPCertStatus.REVOKED:
                    response_status = "revoked"
                else:
                    response_status = "unknown"
            else:
                response_status = parsed_resp.response_status.name
        except Exception:
            response_status = "error"

        processing_time_ms = (time.monotonic() - start_time) * 1000

        self._send_ocsp_response(response_der, 200)
        self._log_ocsp_request(serial_hex, response_status, processing_time_ms)

    def do_GET(self) -> None:
        """GET is not used for OCSP; return 405."""
        self.send_response(405)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Allow", "POST")
        self.end_headers()
        self.wfile.write(b"Method Not Allowed. Use POST for OCSP requests.")


class OCSPServer:
    """Standalone OCSP HTTP responder server."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
        db_path: str = "./pki/micropki.db",
        responder_cert_path: str = "",
        responder_key_path: str = "",
        ca_cert_path: str = "",
        cache_ttl: int = 60,
        log_file: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.db_path = db_path
        self.responder_cert_path = responder_cert_path
        self.responder_key_path = responder_key_path
        self.ca_cert_path = ca_cert_path
        self.cache_ttl = cache_ttl
        self.log_file = log_file
        self.db: Optional[CertificateDatabase] = None
        self.httpd: Optional[socketserver.TCPServer] = None

    def start(self) -> None:
        """Start the OCSP responder server."""
        # Load certificates and key
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(self.responder_cert_path, "rb") as f:
            responder_cert = x509.load_pem_x509_certificate(f.read())

        with open(self.responder_key_path, "rb") as f:
            responder_key = serialization.load_pem_private_key(f.read(), password=None)

        # Connect to database
        self.db = CertificateDatabase(self.db_path)
        self.db.connect()
        self.db.init_schema()

        ocsp_log_path = f"{self.log_file}.ocsp.jsonl" if self.log_file else None

        # Create handler with OCSP context
        db = self.db
        handler = lambda *args, **kwargs: OCSPHandler(
            *args,
            db=db,
            ca_cert=ca_cert,
            responder_cert=responder_cert,
            responder_key=responder_key,
            cache_ttl=self.cache_ttl,
            ocsp_log_path=ocsp_log_path,
            **kwargs,
        )

        try:
            self.httpd = socketserver.TCPServer((self.host, self.port), handler)
            logger.info(
                "OCSP responder started at http://%s:%d/ocsp",
                self.host, self.port,
            )
            logger.info("Press Ctrl+C to stop.")
            self.httpd.serve_forever()
        except Exception as e:
            logger.error("Failed to start OCSP server: %s", e)
            raise
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the OCSP server and clean up."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("OCSP server stopped.")
        if self.db:
            self.db.close()
            self.db = None
