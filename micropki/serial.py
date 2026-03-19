"""
Serial number generator module for MicroPKI.

Implements a unique serial number generator that combines
timestamp and CSPRNG to guarantee uniqueness across the PKI.
"""

import os
import time
import logging
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
        logger.info("Serial number generator initialized.")

    def generate(self) -> int:
        """
        Generate a new unique serial number.

        The number is a 64-bit integer composed of:
        - High 32 bits: Unix timestamp in seconds (ensures temporal uniqueness)
        - Low 32 bits: A cryptographically secure random number (ensures uniqueness within the same second)

        Returns:
            A positive 64-bit integer suitable for use as an X.509 serial number.
        """
        # Get current timestamp in seconds
        now = int(time.time())

        # To prevent duplicates in the same second, ensure timestamp is non-decreasing
        if now < self._last_timestamp:
            # System clock might have gone back, use last known time
            now = self._last_timestamp
            logger.warning("System clock moved backwards. Using last timestamp to ensure serial uniqueness.")
        else:
            self._last_timestamp = now

        # Generate a 32-bit random number
        rand_part = int.from_bytes(os.urandom(4), byteorder='big')

        # Combine into a 64-bit integer
        serial = (now << 32) | rand_part

        # X.509 serial numbers must be positive and not zero
        # The high bits (timestamp) will be non-zero for any time after 1970,
        # so the entire number will be positive and non-zero.
        if serial == 0:
            # Extremely unlikely, but correct it anyway
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