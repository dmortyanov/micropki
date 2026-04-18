import json
import logging
import hashlib
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class AuditLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.dir_path = os.path.dirname(os.path.abspath(log_file))
        if not self.dir_path:
            self.dir_path = "."
        self.chain_file = os.path.join(self.dir_path, "chain.dat")
        os.makedirs(self.dir_path, exist_ok=True)
        
        # Initialize chain file if missing
        if not os.path.exists(self.chain_file):
            with open(self.chain_file, "wb") as f:
                # Initial seed
                f.write(hashlib.sha256(b"MicroPKI_START").digest())

    def get_current_hash(self) -> bytes:
        with open(self.chain_file, "rb") as f:
            return f.read()
            
    def _update_hash(self, data_bytes: bytes) -> str:
        prev_hash = self.get_current_hash()
        hm = hashlib.sha256()
        hm.update(prev_hash)
        hm.update(data_bytes)
        new_hash = hm.digest()
        with open(self.chain_file, "wb") as f:
            f.write(new_hash)
        return new_hash.hex()

    def log(self, action: str, details: dict):
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z",
            "action": action,
            "details": details
        }
        
        # Serialize to bytes
        record_bytes = json.dumps(record, separators=(',', ':'), sort_keys=True).encode('utf-8')
        record_hash_hex = self._update_hash(record_bytes)
        record["hash"] = record_hash_hex
        
        # Write to log
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
            
def verify_audit_log(log_file: str) -> bool:
    dir_path = os.path.dirname(os.path.abspath(log_file))
    if not dir_path:
        dir_path = "."
    chain_file = os.path.join(dir_path, "chain.dat")
    
    if not os.path.exists(log_file) or not os.path.exists(chain_file):
        print(f"Error: files not found (log or chain): {log_file}")
        return False
        
    current_hash = hashlib.sha256(b"MicroPKI_START").digest()
    
    with open(log_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            try:
                record = json.loads(line.strip())
                recorded_hash = record.pop("hash")
                
                # Reconstruct bytes to match what was hashed
                record_bytes = json.dumps(record, separators=(',', ':'), sort_keys=True).encode('utf-8')
                hm = hashlib.sha256()
                hm.update(current_hash)
                hm.update(record_bytes)
                current_hash = hm.digest()
                computed_hash_hex = current_hash.hex()
                
                if computed_hash_hex != recorded_hash:
                    logger.error("Audit log tampered at line %d! Expected: %s, Found: %s", idx+1, computed_hash_hex, recorded_hash)
                    return False
            except Exception as e:
                logger.error("Failed to parse or verify line %d: %s", idx+1, e)
                return False
                
    # Check final hash
    with open(chain_file, "rb") as f:
        stored_hash = f.read()
    if stored_hash != current_hash:
         logger.error("Final hash does not match chain.dat! Expected %s, Found in chain %s", current_hash.hex(), stored_hash.hex())
         return False
         
    return True
