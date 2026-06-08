# Modulo de persistencia de auditorias y utilidades de almacenamiento cifrado.

"""
Audit results storage with AES-256-GCM encryption at rest.

The encryption key is derived from a machine-local secret stored at:
  storage/.db_key  (created automatically on first run, chmod 600)

This file MUST NOT be committed to VCS (.gitignore already excludes it).
Without the key file the database is unreadable, protecting confidential
audit findings, credentials-under-test, and session tokens at rest.
"""

import sqlite3
import json
import os
import secrets
from datetime import datetime
from pathlib import Path





_KEY_FILE = Path(__file__).parent / ".db_key"
_KEY_LEN = 32


def _load_or_create_key() -> bytes:
    """Load the AES key from disk, creating it securely on first run."""
    if _KEY_FILE.exists():
        raw = _KEY_FILE.read_bytes()
        if len(raw) >= _KEY_LEN:
            return raw[:_KEY_LEN]

    key = secrets.token_bytes(_KEY_LEN)
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_bytes(key)
    try:
        _KEY_FILE.chmod(0o600)
    except Exception:
        pass
    return key






def _encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM.
    Returns base64-encoded  nonce(12) + tag(16) + ciphertext.
    Falls back to base64-only obfuscation when cryptography module absent
    (warns the user, still better than completely plaintext).
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return "gcm:" + base64.b64encode(nonce + ct).decode("ascii")
    except ImportError:

        import base64
        import warnings
        warnings.warn(
            "[webaudit-toolkit] 'cryptography' package not installed. "
            "Audit DB is stored as base64-obfuscated, NOT encrypted. "
            "Run: pip install cryptography",
            RuntimeWarning,
            stacklevel=4,
        )
        return "b64:" + base64.b64encode(plaintext.encode("utf-8")).decode("ascii")


def _decrypt(blob: str, key: bytes) -> str:
    """Decrypt a value produced by _encrypt()."""
    if blob.startswith("gcm:"):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import base64
            raw = base64.b64decode(blob[4:])
            nonce, ct = raw[:12], raw[12:]
            return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"AES-GCM decryption failed: {exc}") from exc
    if blob.startswith("b64:"):
        import base64
        return base64.b64decode(blob[4:]).decode("utf-8")

    return blob






DB_PATH = str(Path(__file__).parent / "audit_results.db")

_KEY: bytes = _load_or_create_key()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            results_json TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_audit(audit_name: str, target_url: str, results: list):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    plaintext = json.dumps(results, ensure_ascii=False)
    encrypted_blob = _encrypt(plaintext, _KEY)

    cursor.execute("""
        INSERT INTO audits (audit_name, target_url, created_at, results_json)
        VALUES (?, ?, ?, ?)
    """, (
        audit_name,
        target_url,
        datetime.now().isoformat(),
        encrypted_blob,
    ))

    conn.commit()
    conn.close()


def load_audits() -> list[dict]:
    """Load and decrypt all stored audits. Returns list of dicts."""
    if not Path(DB_PATH).exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, audit_name, target_url, created_at, results_json "
            "FROM audits ORDER BY id DESC"
        )
        rows = cursor.fetchall()
    except Exception:
        return []
    finally:
        conn.close()

    audits = []
    for row in rows:
        audit_id, name, target, created_at, blob = row
        try:
            results = json.loads(_decrypt(blob, _KEY))
        except Exception:
            results = []
        audits.append({
            "id": audit_id,
            "audit_name": name,
            "target_url": target,
            "created_at": created_at,
            "results": results,
        })
    return audits
