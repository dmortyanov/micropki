"""
HTTP Repository module for MicroPKI.

Implements a REST-like server to serve certificates and CRLs
from the filesystem and database.
"""

import http.server
import socketserver
import os
import re
import urllib.parse
import logging
import json
import datetime as _dt
from typing import Optional, Dict, Any
from .database import CertificateDatabase

# Initialize module logger
logger = logging.getLogger(__name__)


class RepositoryHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for the certificate repository."""

    def __init__(self, *args, **kwargs):
        # Extract custom arguments
        self.db: Optional[CertificateDatabase] = kwargs.pop('db', None)
        self.cert_dir: str = kwargs.pop('cert_dir', '.')
        self.audit_log_path: Optional[str] = kwargs.pop("audit_log_path", None)
        super().__init__(*args, **kwargs)

    def _send_response_no_cache(self, code: int, content_type: str = 'text/plain', content: bytes = b''):
        """Send HTTP response with no caching."""
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()

        # Sprint 3 LOG-8 (Could): structured JSON request log (one JSON per line).
        if self.audit_log_path:
            try:
                record = {
                    "ts": _dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                    "method": self.command,
                    "path": self.path,
                    "client_ip": self.client_address[0] if self.client_address else None,
                    "status": code,
                }
                with open(self.audit_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception:
                # Logging must never break the server.
                pass

        if content:
            self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to use our logger."""
        message = format % args
        logger.info("[HTTP] %s - %s", self.client_address[0], message)

    def do_GET(self):
        """Handle GET requests."""
        # Parse the URL
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        try:
            if path.startswith('/certificate/'):
                # Extract serial number from path
                serial_hex = path[len('/certificate/'):].strip('/')
                if not serial_hex:
                    self._send_response_no_cache(400, 'text/plain', b'Bad Request: Serial number is required.')
                    return

                # Validate hex format
                if not re.fullmatch(r'[0-9A-Fa-f]+', serial_hex):
                    self._send_response_no_cache(400, 'text/plain', b'Bad Request: Serial number must be hexadecimal.')
                    return

                if not self.db:
                    self._send_response_no_cache(500, 'text/plain', b'Internal Server Error: Database not initialized.')
                    return

                # Lookup certificate in database
                cert_data = self.db.get_certificate_by_serial(serial_hex)
                if not cert_data:
                    self._send_response_no_cache(404, 'text/plain', b'Certificate not found.')
                    return

                # Send the PEM certificate
                cert_pem = cert_data['cert_pem'].encode('utf-8')
                self._send_response_no_cache(200, 'application/x-pem-file', cert_pem)
                return

            elif path.startswith('/ca/'):
                # Extract level
                level = path[len('/ca/'):].strip('/')
                if level not in ['root', 'intermediate']:
                    self._send_response_no_cache(404, 'text/plain', b'CA level not found.')
                    return

                # Map CA level to certificate filename on disk.
                # Root CA is stored as `ca.cert.pem` (project convention).
                filename = "ca.cert.pem" if level == "root" else "intermediate.cert.pem"
                cert_path = os.path.join(self.cert_dir, filename)

                if not os.path.isfile(cert_path):
                    self._send_response_no_cache(404, 'text/plain', b'CA certificate not found on disk.')
                    return

                # Read and send the file
                with open(cert_path, 'rb') as f:
                    cert_pem = f.read()

                self._send_response_no_cache(200, 'application/x-pem-file', cert_pem)
                return

            elif path == '/crl' or path.startswith('/crl/'):
                ca_hint = "intermediate"
                qs = urllib.parse.parse_qs(parsed_path.query)
                if "ca" in qs:
                    ca_hint = qs["ca"][0]
                elif path.startswith('/crl/') and path.endswith('.crl'):
                    ca_hint = path[len('/crl/'):-len('.crl')]

                if ca_hint not in ["root", "intermediate"]:
                    self._send_response_no_cache(404, 'text/plain', b'CA level not found.')
                    return

                # Assuming crl directory is alongside certs
                out_dir = os.path.dirname(os.path.abspath(self.cert_dir))
                crl_path = os.path.join(out_dir, "crl", f"{ca_hint}.crl.pem")

                if not os.path.isfile(crl_path):
                    self._send_response_no_cache(404, 'text/plain', b'CRL not found on disk.')
                    return

                with open(crl_path, "rb") as f:
                    crl_pem = f.read()

                max_age = 0
                try:
                    from cryptography import x509
                    crl_obj = x509.load_pem_x509_crl(crl_pem)
                    
                    if hasattr(crl_obj, 'next_update_utc'):
                        next_upd = crl_obj.next_update_utc
                    else:
                        next_upd = crl_obj.next_update
                        if next_upd and next_upd.tzinfo is None:
                            next_upd = next_upd.replace(tzinfo=_dt.timezone.utc)
                            
                    if next_upd:
                        now = _dt.datetime.now(_dt.timezone.utc)
                        delta = next_upd - now
                        max_age = max(0, int(delta.total_seconds()))
                except Exception as e:
                    logger.warning("Failed to parse CRL for caching headers: %s", e)

                stat = os.stat(crl_path)
                last_mod_header = self.date_time_string(int(stat.st_mtime))

                self.send_response(200)
                self.send_header('Content-Type', 'application/pkix-crl')
                self.send_header('Content-Length', str(len(crl_pem)))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', f'max-age={max_age}')
                self.send_header('Last-Modified', last_mod_header)
                self.send_header('ETag', f'"{stat.st_size}-{stat.st_mtime}"')
                self.end_headers()

                if self.audit_log_path:
                    try:
                        record = {
                            "ts": _dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                            "method": self.command,
                            "path": self.path,
                            "client_ip": self.client_address[0] if self.client_address else None,
                            "status": 200,
                        }
                        with open(self.audit_log_path, "a", encoding="utf-8") as rf:
                            rf.write(json.dumps(record, ensure_ascii=False) + "\n")
                    except Exception:
                        pass

                self.wfile.write(crl_pem)
                return

            else:
                # For any other path, try to serve static files from cert_dir as fallback
                # This is optional (REPO-5)
                if path == '/' or path == '':
                    # List available files or redirect
                    self._send_response_no_cache(404, 'text/plain', b'Not Found. Available endpoints: /certificate/<serial>, /ca/root, /ca/intermediate, /crl')
                    return

                # Attempt to serve static file
                static_path = path.lstrip('/')
                full_path = os.path.join(self.cert_dir, static_path)
                if os.path.isfile(full_path):
                    # Serve the file directly
                    try:
                        with open(full_path, 'rb') as f:
                            content = f.read()
                        self._send_response_no_cache(200, 'application/x-pem-file', content)
                        return
                    except Exception as e:
                        logger.error("Failed to serve static file %s: %s", full_path, e)
                        self._send_response_no_cache(500, 'text/plain', b'Internal Server Error')
                        return

                # Not found
                self._send_response_no_cache(404, 'text/plain', b'Not Found')
                return

        except Exception as e:
            logger.exception("Unhandled exception in do_GET: %s", e)
            self._send_response_no_cache(500, 'text/plain', b'Internal Server Error')

    def _method_not_allowed(self) -> None:
        self._send_response_no_cache(
            405,
            'text/plain',
            b'Method Not Allowed',
        )

    # Sprint 3: reject non-GET methods with 405.
    def do_POST(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_HEAD(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._method_not_allowed()


class RepositoryServer:
    """A simple HTTP server for serving certificates."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        db_path: str = "./pki/micropki.db",
        cert_dir: str = "./pki/certs",
        audit_log_path: Optional[str] = None,
    ):
        """
        Initialize the repository server.

        Args:
            host: Host address to bind to.
            port: TCP port to listen on.
            db_path: Path to the SQLite database.
            cert_dir: Directory containing CA certificates.
        """
        self.host = host
        self.port = port
        self.db_path = db_path
        self.cert_dir = cert_dir
        self.audit_log_path = audit_log_path
        self.db: Optional[CertificateDatabase] = None
        self.httpd: Optional[socketserver.TCPServer] = None
        logger.info(
            "Repository server initialized: host=%s, port=%d, db=%s, cert_dir=%s",
            host, port, db_path, cert_dir
        )

    def start(self):
        """Start the HTTP server."""
        # Initialize and connect to the database
        self.db = CertificateDatabase(self.db_path)
        try:
            self.db.connect()
            # Ensure schema is in place
            self.db.init_schema()
            logger.info("Database connected and schema ensured.")
        except Exception as e:
            logger.error("Failed to initialize database: %s", e)
            if self.db:
                self.db.close()
            raise

        # Check if cert_dir exists
        if not os.path.isdir(self.cert_dir):
            logger.error("Certificate directory does not exist: %s", self.cert_dir)
            self.db.close()
            raise FileNotFoundError(f"Certificate directory not found: {self.cert_dir}")

        # Create the handler with custom arguments
        handler = lambda *args, **kwargs: RepositoryHandler(
            *args,
            db=self.db,
            cert_dir=self.cert_dir,
            audit_log_path=self.audit_log_path,
            **kwargs,
        )

        # Create server
        try:
            self.httpd = socketserver.TCPServer((self.host, self.port), handler)
            logger.info("Repository server started at http://%s:%d", self.host, self.port)
            logger.info("Press Ctrl+C to stop.")
            # Serve forever
            self.httpd.serve_forever()
        except Exception as e:
            logger.error("Failed to start HTTP server: %s", e)
            raise
        finally:
            self.stop()

    def stop(self):
        """Stop the HTTP server and clean up."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("HTTP server stopped.")

        if self.db:
            self.db.close()
            logger.info("Database connection closed.")
            self.db = None