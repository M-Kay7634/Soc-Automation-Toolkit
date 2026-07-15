"""
db.py
-----
Central database layer for the SOC Automation Toolkit. Uses SQLite -
a real relational database that lives in a single file, no server
setup required. This is standard practice for tools at this scale.

Every module (IOC triage, log enricher, phishing analyzer) writes
its results here, which is what powers the dashboard and historical
trend analysis.
"""

import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "soc_toolkit.db")


def get_connection():
    """
    Returns a database connection. row_factory lets us access
    columns by name (row['verdict']) instead of by index (row[2]),
    which makes the rest of the code far more readable.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Creates all tables if they don't already exist. Safe to call
    every time the app starts - CREATE TABLE IF NOT EXISTS won't
    wipe existing data.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            verdict TEXT NOT NULL,
            reason TEXT,
            scanned_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT NOT NULL,
            source_file TEXT NOT NULL,
            attacker_ip TEXT NOT NULL,
            verdict TEXT NOT NULL,
            severity TEXT,
            details TEXT,
            analyzed_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phishing_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT NOT NULL,
            subject TEXT,
            verdict TEXT NOT NULL,
            risk_score INTEGER,
            reasons TEXT,
            scanned_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def _now() -> str:
    """ISO format timestamp - sortable as plain text, works well in SQLite."""
    return datetime.now(timezone.utc).isoformat()


def save_ioc_scan(indicator: str, ioc_type: str, verdict: str, reason: str) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO ioc_scans (indicator, ioc_type, verdict, reason, scanned_at) VALUES (?, ?, ?, ?, ?)",
        (indicator, ioc_type, verdict, reason, _now()),
    )
    conn.commit()
    conn.close()


def save_log_analysis(log_type: str, source_file: str, attacker_ip: str, verdict: str, severity: str, details: str) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO log_analyses
           (log_type, source_file, attacker_ip, verdict, severity, details, analyzed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (log_type, source_file, attacker_ip, verdict, severity, details, _now()),
    )
    conn.commit()
    conn.close()


def save_phishing_scan(sender_email: str, subject: str, verdict: str, risk_score: int, reasons: str) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO phishing_scans
           (sender_email, subject, verdict, risk_score, reasons, scanned_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sender_email, subject, verdict, risk_score, reasons, _now()),
    )
    conn.commit()
    conn.close()


def get_recent_ioc_scans(limit: int = 20) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM ioc_scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_log_analyses(limit: int = 20) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM log_analyses ORDER BY analyzed_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_phishing_scans(limit: int = 20) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM phishing_scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_verdict_counts() -> dict:
    """
    Returns counts of each verdict type across all three tables -
    this powers the dashboard's summary charts (e.g. a pie chart
    of MALICIOUS vs SUSPICIOUS vs CLEAN across everything scanned).
    """
    conn = get_connection()
    counts = {}

    for table, verdict_values in [
        ("ioc_scans", ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"]),
        ("log_analyses", ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"]),
        ("phishing_scans", ["PHISHING", "SUSPICIOUS", "LIKELY LEGITIMATE"]),
    ]:
        for verdict in verdict_values:
            row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM {table} WHERE verdict = ?", (verdict,)
            ).fetchone()
            counts[f"{table}:{verdict}"] = row["cnt"]

    conn.close()
    return counts


# Quick manual test
if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")

    # Insert some test data
    save_ioc_scan("8.8.8.8", "ip", "CLEAN", "No vendors flagged this indicator")
    save_ioc_scan("45.155.205.233", "ip", "MALICIOUS", "17 vendors flagged malicious")

    print("\n=== Recent IOC Scans ===")
    for scan in get_recent_ioc_scans():
        print(f"  {scan['indicator']:20} {scan['verdict']:12} {scan['scanned_at']}")

    print("\n=== Verdict Counts ===")
    for key, count in get_verdict_counts().items():
        if count > 0:
            print(f"  {key}: {count}")