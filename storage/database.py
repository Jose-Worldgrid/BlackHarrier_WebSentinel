import sqlite3
import json
from datetime import datetime


DB_PATH = "audit_results.db"


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

    cursor.execute("""
        INSERT INTO audits (audit_name, target_url, created_at, results_json)
        VALUES (?, ?, ?, ?)
    """, (
        audit_name,
        target_url,
        datetime.now().isoformat(),
        json.dumps(results, ensure_ascii=False)
    ))

    conn.commit()
    conn.close()