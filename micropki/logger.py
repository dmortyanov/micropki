"""Logging infrastructure for MicroPKI.

Respects --log-file: writes to a file if provided, otherwise to stderr.
Format: ISO 8601 timestamp (with milliseconds), level, message.
"""

import logging
import os
import sys


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


class _MillisecondFormatter(logging.Formatter):
    """Formatter that outputs ISO 8601 timestamps with milliseconds."""

    default_msec_format = "%s.%03d"


def setup_logging(log_file: str | None = None, level: int = logging.INFO) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        log_file: Path to a log file.  If *None*, logs go to stderr.
        level: Logging level.

    Returns:
        Configured :class:`logging.Logger`.
    """
    logger = logging.getLogger("micropki")
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = _MillisecondFormatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
