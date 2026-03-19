"""
Configuration module for MicroPKI.

Loads settings from a YAML configuration file.
"""

import os
import yaml
from typing import Dict, Any


class Config:
    """Loads and holds configuration for MicroPKI."""

    def __init__(self, config_path: str = "micropki.conf"):
        """
        Initialize the configuration.

        Args:
            config_path: Path to the YAML configuration file.
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load the configuration from file."""
        if not os.path.isfile(self.config_path):
            # Config file is optional, use defaults if not present
            self.config = {
                "database": {
                    "path": "./pki/micropki.db"
                },
                "server": {
                    "host": "127.0.0.1",
                    "port": 8080,
                    "cert_dir": "./pki/certs"
                }
            }
            return

        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by dot-separated key.

        Args:
            key: Dot-separated key (e.g., "server.host").
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default