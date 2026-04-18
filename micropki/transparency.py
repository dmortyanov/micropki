import os
import json
import logging
from datetime import datetime, timezone
from cryptography import x509

logger = logging.getLogger(__name__)

class TransparencyLog:
    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        
    def append_cert(self, cert: x509.Certificate):
        """Append certificate to the simulated CT log."""
        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "serial_number": format(cert.serial_number, "X"),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string()
            }
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error("Failed to append to CT log: %s", e)
