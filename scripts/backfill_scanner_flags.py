#!/usr/bin/env python3
"""Re-runs scanner_detect.classify() over existing clicks/opens/submissions
rows and updates is_scanner/scanner_vendor/scanner_reason for any that are
newly detectable (e.g. after adding a new signal to scanner_detect.py).

Only rows currently marked is_scanner = FALSE are re-checked — detection
signals are additive, so a row already flagged never needs to be unflagged.
Historical rows have no stored User-Agent, so only the IP-based signals
(published CIDR ranges, reverse DNS, ASN) can apply retroactively; the
User-Agent signal only helps on new, live hits.

Usage: python scripts/backfill_scanner_flags.py
Reads DATABASE_URL from the environment the same way app.py does.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
import psycopg2.extras

import scanner_detect

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/rabbithole")


def backfill_table(cur, table):
    cur.execute(f"SELECT id, ip FROM {table} WHERE is_scanner = FALSE")
    rows = cur.fetchall()

    cache = {}
    updates = []
    for row in rows:
        ip = row["ip"]
        if ip not in cache:
            cache[ip] = scanner_detect.classify(ip, "")
        result = cache[ip]
        if result["is_scanner"]:
            updates.append((result["vendor"] or "", result["reason"], row["id"]))

    for vendor, reason, row_id in updates:
        cur.execute(
            f"UPDATE {table} SET is_scanner = TRUE, scanner_vendor = %s, scanner_reason = %s WHERE id = %s",
            (vendor, reason, row_id),
        )

    print(f"{table}: checked {len(rows)} unflagged rows, newly flagged {len(updates)}")


def main():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn.cursor() as cur:
            for table in ("clicks", "opens", "submissions"):
                backfill_table(cur, table)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
