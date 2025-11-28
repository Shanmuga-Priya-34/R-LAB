"""
Unified logging: CSV, JSON, SQLite.
Lightweight, works without external DB servers.
"""

import csv
import json
import sqlite3
import os
import datetime
from config import EVENTS_CSV, EVENTS_JSON, EVENTS_DB, LOGS_DIR

# Ensure logs dir exists
os.makedirs(LOGS_DIR, exist_ok=True)

CSV_HEADERS = ["timestamp", "event_type", "details"]

def _now_iso():
    return datetime.datetime.utcnow().isoformat()

def log_event(event_type: str, details: str):
    """Write event to CSV, JSON and SQLite, and print to console."""
    ts = _now_iso()
    event = {"timestamp": ts, "event_type": event_type, "details": details}

    # CSV
    try:
        write_header = not os.path.exists(EVENTS_CSV) or os.path.getsize(EVENTS_CSV) == 0
        with open(EVENTS_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            if write_header:
                writer.writeheader()
            writer.writerow(event)
    except Exception as e:
        print(f"[LOGGER] CSV write error: {e}")

    # JSON (newline array style)
    try:
        if not os.path.exists(EVENTS_JSON) or os.path.getsize(EVENTS_JSON) == 0:
            data = []
        else:
            with open(EVENTS_JSON, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except Exception:
                    data = []
        data.append(event)
        with open(EVENTS_JSON, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[LOGGER] JSON write error: {e}")

    # SQLite
    try:
        conn = sqlite3.connect(EVENTS_DB, timeout=10)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                details TEXT
            )
        """)
        cur.execute("INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)",
                    (ts, event_type, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[LOGGER] SQLite error: {e}")

    # console
    print(f"[{ts}] {event_type} - {details}")
