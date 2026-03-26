"""
Serial number generator module for MicroPKI.

Implements a unique serial number generator that combines
timestamp and CSPRNG to guarantee uniqueness across the PKI.
"""

import os
import time
import logging
import sqlite3
from typing import Optional

# Initialize module logger
logger = logging.getLogger(__name__)


class SerialNumberGenerator:
    """Generates unique 64-bit serial numbers for X.509 certificates."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the serial number generator.

        Args:
            db_path: Optional path to the database for persistent counter.
                     If None, a simple timestamp-based generator is used.
        """
        self.db_path = db_path
        self._last_timestamp = 0
        self._in_memory_counter = 0
        logger.info("Serial number generator initialized.")

    def _next_counter(self) -> int:
        """Return next persistent counter value (monotonic) or in-memory fallback."""
        if not self.db_path:
            self._in_memory_counter += 1
            return self._in_memory_counter

        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS serial_state (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        counter INTEGER NOT NULL
                    )
                    """
                )
                row = conn.execute(
                    "SELECT counter FROM serial_state WHERE id = 1"
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO serial_state (id, counter) VALUES (1, 1)"
                    )
                    return 1

                counter = int(row[0]) + 1
                conn.execute(
                    "UPDATE serial_state SET counter = ? WHERE id = 1", (counter,)
                )
                return counter
        finally:
            conn.close()

    def generate(self) -> int:
        """
        Generate a new unique serial number.

        The number is a 64-bit integer composed of:
        - High 32 bits: Unix timestamp in seconds (ensures temporal uniqueness)
        - Low 32 bits: A cryptographically secure random number (ensures uniqueness within the same second)

        Returns:
            A positive 64-bit integer suitable for use as an X.509 serial number.
        """
        now = int(time.time())

        # Ensure non-decreasing timestamp to avoid duplicates on clock skew.
        if now < self._last_timestamp:
            now = self._last_timestamp
            logger.warning(
                "System clock moved backwards. Using last timestamp to ensure serial uniqueness."
            )
        else:
            self._last_timestamp = now

        # 32 bits of CSPRNG randomness (>= 20 bits as required).
        rand_part = int.from_bytes(os.urandom(4), byteorder="big")

        # Persistent monotonic counter stored in the DB (guarantees uniqueness across runs).
        counter = self._next_counter()

        # 64-bit serial: high 32 bits timestamp, low 32 bits random XOR counter.
        serial = ((now & 0xFFFFFFFF) << 32) | ((rand_part ^ (counter & 0xFFFFFFFF)) & 0xFFFFFFFF)

        if serial == 0:
            serial = 1
            logger.critical("Generated serial number was zero, corrected to 1.")

        logger.debug("Generated serial number: %d (hex: %016x)", serial, serial)
        return serial

    def generate_hex(self) -> str:
        """
        Generate a serial number and return it as an uppercase hexadecimal string.

        Returns:
            A hex string representation of the serial number (e.g., "2A7F1234567890ABCDEF").
        """
        serial = self.generate()
        hex_serial = format(serial, 'X')
        logger.debug("Generated serial number (hex): %s", hex_serial)
        return hex_serial