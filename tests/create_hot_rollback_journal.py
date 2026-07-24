#!/usr/bin/env python3
"""Crash a SQLite writer after spilling uncommitted pages to the main file."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: create_hot_rollback_journal.py DB DELETE|PERSIST")
    database = Path(sys.argv[1])
    journal_mode = sys.argv[2].upper()
    if journal_mode not in {"DELETE", "PERSIST"}:
        raise SystemExit(f"unsupported journal mode: {journal_mode}")

    connection = sqlite3.connect(database)
    selected = connection.execute(
        f"PRAGMA journal_mode = {journal_mode}"
    ).fetchone()
    if selected is None or str(selected[0]).upper() != journal_mode:
        raise SystemExit(f"failed to select {journal_mode} journal mode")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA cache_size = 5")
    connection.execute("PRAGMA cache_spill = ON")
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        UPDATE evidence
        SET state = 'uncommitted',
            payload = printf('uncommitted-%06d-', id)
                || substr(payload, 1, 850)
        """
    )
    journal = database.with_name(f"{database.name}-journal")
    if not journal.is_file() or journal.stat().st_size == 0:
        raise SystemExit("rollback journal was not created")
    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main())
