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

                # Construct filename
                filename = f"{level}.cert.pem"
                cert_path = os.path.join(self.cert_dir, filename)

                if not os.path.isfile(cert_path):
                    self._send_response_no_cache(404, 'text/plain', b'CA certificate not found on disk.')
                    return

                # Read and send the file
                with open(cert_path, 'rb') as f:
                    cert_pem = f.read()

                self._send_response_no_cache(200, 'application/x-pem-file', cert_pem)
                return

            elif path == '/crl':
                # Placeholder for Sprint 4
                message = b'CRL generation not yet implemented.'
                self._send_response_no_cache(501, 'text/plain', message)
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


class RepositoryServer:
    """A simple HTTP server for serving certificates."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        db_path: str = "./pki/micropki.db",
        cert_dir: str = "./pki/certs"
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
        handler = lambda *args, **kwargs: RepositoryHandler(*args, db=self.db, cert_dir=self.cert_dir, **kwargs)

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