"""
Generate simple daily summary from SQLite logs.
"""

import sqlite3
from datetime import datetime, timedelta
from config import EVENTS_DB, DAILY_REPORT
from logger import log_event

def generate_daily_report(output_file: str = DAILY_REPORT):
    try:
        today = datetime.utcnow().date()
        yesterday = today - timedelta(days=1)
        date_str = yesterday.strftime("%Y-%m-%d")

        conn = sqlite3.connect(EVENTS_DB)
        cur = conn.cursor()

        # counts per event_type for the date
        cur.execute("SELECT event_type, COUNT(*) FROM events WHERE DATE(timestamp)=? GROUP BY event_type", (date_str,))
        summary = cur.fetchall()

        # details for the date
        cur.execute("SELECT timestamp, event_type, details FROM events WHERE DATE(timestamp)=? ORDER BY timestamp", (date_str,))
        details = cur.fetchall()
        conn.close()

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Daily Report for {date_str}\n")
            f.write("="*60 + "\n\n")
            f.write("Summary:\n")
            for et, cnt in summary:
                f.write(f"{et}: {cnt}\n")
            f.write("\nDetails:\n")
            for row in details:
                f.write(f"{row[0]} - {row[1]} - {row[2]}\n")
        print(f"[REPORT] Generated {output_file}")
    except Exception as e:
        print(f"[REPORT] Error generating report: {e}")
        log_event("REPORT_ERROR", str(e))

if __name__ == "__main__":
    generate_daily_report()
