"""
Database module for MicroPKI.

Implements SQLite integration for certificate storage,
retrieval, and lifecycle management.
"""

import sqlite3
import json
import os
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

# Initialize module logger
logger = logging.getLogger(__name__)


class CertificateDatabase:
    """A wrapper around SQLite database for certificate storage."""

    def __init__(self, db_path: str):
        """
        Initialize the database connection.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure the directory for the database file exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info("Created database directory: %s", db_dir)

    def connect(self) -> None:
        """Establish a connection to the database."""
        try:
            # Repository server is started in a background thread in tests.
            # Allow the same connection to be safely closed from a different thread.
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row  # Enable dict-like access
            logger.info("Connected to database: %s", self.db_path)
        except sqlite3.Error as e:
            logger.error("Failed to connect to database %s: %s", self.db_path, e)
            raise

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("Database connection closed.")

    def init_schema(self) -> None:
        """Create the certificates table if it does not exist."""
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")

        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            );
        '''

        create_crl_metadata_sql = '''
            CREATE TABLE IF NOT EXISTS crl_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ca_subject TEXT NOT NULL UNIQUE,
                crl_number INTEGER NOT NULL,
                last_generated TEXT NOT NULL,
                next_update TEXT NOT NULL,
                crl_path TEXT NOT NULL
            );
        '''

        index_serial_sql = 'CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);'
        index_status_sql = 'CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);'
        index_ca_subject_sql = 'CREATE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject);'

        try:
            with self._conn:
                self._conn.execute(create_table_sql)
                self._conn.execute(create_crl_metadata_sql)

                # PKI-16 & DB-7: minimal schema migration support.
                # If columns or tables were missing in an older schema, add them automatically.
                user_version_row = self._conn.execute("PRAGMA user_version").fetchone()
                user_version = int(user_version_row[0]) if user_version_row else 0
                target_version = 2

                if user_version < 1:
                    existing_cols = {
                        r["name"]
                        for r in self._conn.execute("PRAGMA table_info(certificates)").fetchall()
                    }

                    if "revocation_reason" not in existing_cols:
                        self._conn.execute(
                            "ALTER TABLE certificates ADD COLUMN revocation_reason TEXT"
                        )
                    if "revocation_date" not in existing_cols:
                        self._conn.execute(
                            "ALTER TABLE certificates ADD COLUMN revocation_date TEXT"
                        )
                    if "created_at" not in existing_cols:
                        self._conn.execute(
                            "ALTER TABLE certificates ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
                        )

                if user_version < 2:
                    # Target version 2 adds the crl_metadata table, which is created by CREATE TABLE IF NOT EXISTS above.
                    pass

                if user_version != target_version:
                    self._conn.execute(f"PRAGMA user_version = {target_version}")

                self._conn.execute(index_serial_sql)
                self._conn.execute(index_status_sql)
                self._conn.execute(index_ca_subject_sql)

                logger.info("Database schema initialized successfully.")
        except sqlite3.Error as e:
            logger.error("Failed to initialize database schema: %s", e)
            raise

    def insert_certificate(
        self,
        serial_hex: str,
        subject: str,
        issuer: str,
        not_before: str,
        not_after: str,
        cert_pem: str,
        status: str = "valid"
    ) -> None:
        """
        Insert a new certificate record into the database.

        Args:
            serial_hex: Serial number in hexadecimal string.
            subject: Subject DN string.
            issuer: Issuer DN string.

            not_before: ISO 8601 formatted string.
            not_after: ISO 8601 formatted string.
            cert_pem: Full PEM certificate string.
            status: Status of the certificate (valid, revoked, expired).
        """
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")

        insert_sql = '''
        INSERT INTO certificates (
            serial_hex, subject, issuer, not_before, not_after,
            cert_pem, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''

        created_at = datetime.now().isoformat()

        try:
            with self._conn:
                self._conn.execute(
                    insert_sql,
                    (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                )
                logger.info("Certificate inserted into database: serial=%s, subject=%s", serial_hex, subject)
        except sqlite3.IntegrityError as e:
            logger.error("Failed to insert certificate (IntegrityError): %s", e)
            raise ValueError(f"Certificate with serial {serial_hex} already exists.")
        except sqlite3.Error as e:
            logger.error("Failed to insert certificate: %s", e)
            raise

    def get_certificate_by_serial(self, serial_hex: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a certificate record by its serial number.

        Args:
            serial_hex: Serial number in hexadecimal string (case-insensitive).

        Returns:
            A dictionary with certificate data or None if not found.
        """
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")

        select_sql = 'SELECT * FROM certificates WHERE UPPER(serial_hex) = UPPER(?)'

        try:
            cursor = self._conn.execute(select_sql, (serial_hex,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            logger.info("Certificate not found in database: serial=%s", serial_hex)
            return None
        except sqlite3.Error as e:
            logger.error("Failed to retrieve certificate by serial %s: %s", serial_hex, e)
            raise

    def list_certificates(
        self,
        status: Optional[str] = None,
        issuer: Optional[str] = None,
        not_before: Optional[str] = None,
        not_after: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query certificates with optional filters.

        Args:
            status: Filter by status (valid, revoked, expired).
            issuer: Filter by issuer DN.
            not_before: Filter by not_before >= this date.
            not_after: Filter by not_after <= this date.

        Returns:
            A list of dictionaries with certificate data.
        """
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")

        base_sql = 'SELECT * FROM certificates WHERE 1=1'
        params = []

        if status:
            base_sql += ' AND status = ?'
            params.append(status)
        if issuer:
            base_sql += ' AND issuer = ?'
            params.append(issuer)
        if not_before:
            base_sql += ' AND not_before >= ?'
            params.append(not_before)
        if not_after:
            base_sql += ' AND not_after <= ?'
            params.append(not_after)

        try:
            cursor = self._conn.execute(base_sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Failed to list certificates: %s", e)
            raise

    def update_certificate_status(
        self,
        serial_hex: str,
        status: str,
        revocation_reason: Optional[str] = None
    ) -> bool:
        """
        Update the status of a certificate (e.g., revoke it).

        Args:
            serial_hex: Serial number in hexadecimal string.
            status: New status (e.g., 'revoked').
            revocation_reason: Reason for revocation (optional).
            
        Returns:
            True if the status was successfully updated, False if the certificate was already in the requested status.
        """
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")

        select_sql = 'SELECT status FROM certificates WHERE UPPER(serial_hex) = UPPER(?)'
        
        update_sql = '''
        UPDATE certificates SET status = ?, revocation_date = ?, revocation_reason = ?
        WHERE UPPER(serial_hex) = UPPER(?)
        '''
        now = datetime.now().isoformat()

        try:
            with self._conn:
                cursor = self._conn.execute(select_sql, (serial_hex,))
                row = cursor.fetchone()
                if not row:
                    logger.warning("No certificate found for revocation with serial: %s", serial_hex)
                    raise ValueError(f"No certificate found with serial {serial_hex}")
                
                if row["status"] == status:
                    return False
                    
                cursor = self._conn.execute(update_sql, (status, now, revocation_reason, serial_hex))
                logger.info("Certificate status updated: serial=%s, status=%s", serial_hex, status)
                return True
        except sqlite3.Error as e:
            logger.error("Failed to update certificate status for serial %s: %s", serial_hex, e)
            raise
            
    def get_crl_metadata(self, ca_subject: str) -> Optional[Dict[str, Any]]:
        """Retrieve CRL metadata for a specific CA."""
        if not self._conn:
            raise RuntimeError("Database not connected")
            
        sql = 'SELECT * FROM crl_metadata WHERE ca_subject = ?'
        try:
            cursor = self._conn.execute(sql, (ca_subject,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error("Failed to get crl metadata for %s: %s", ca_subject, e)
            raise
            
    def upsert_crl_metadata(
        self,
        ca_subject: str,
        crl_number: int,
        last_generated: str,
        next_update: str,
        crl_path: str
    ) -> None:
        """Insert or update CRL metadata for a specific CA."""
        if not self._conn:
            raise RuntimeError("Database not connected")
            
        sql = '''
            INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ca_subject) DO UPDATE SET
                crl_number=excluded.crl_number,
                last_generated=excluded.last_generated,
                next_update=excluded.next_update,
                crl_path=excluded.crl_path
        '''
        try:
            with self._conn:
                self._conn.execute(sql, (ca_subject, crl_number, last_generated, next_update, crl_path))
                logger.info("Upserted crl_metadata for %s (CRL #%d)", ca_subject, crl_number)
        except sqlite3.Error as e:
            logger.error("Failed to upsert crl metadata for %s: %s", ca_subject, e)
            raise

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        """
        Retrieve all revoked certificates (for future CRL generation).

        Returns:
            A list of dictionaries with revoked certificate data.
        """
        return self.list_certificates(status="revoked")
