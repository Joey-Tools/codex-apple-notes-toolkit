from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts/apple_notes_helper.py"
SPEC = importlib.util.spec_from_file_location("apple_notes_helper", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
WRAPPER_PATH = REPO_ROOT / "scripts/apple_notes_helper.sh"


class AppleNotesHelperTests(unittest.TestCase):
    def _write_fake_osascript(self, path: Path) -> None:
        path.write_text(
            """#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if args and args[0] == "-" and len(args) >= 3:
    folder = args[1]
    prefix = args[2]
    if prefix == "2026.03.12":
        print(f"2026.03.12 (Wed) {folder}\\n----\\nValidated helper coverage")
        raise SystemExit(0)
    if prefix == "2026.03.dupe":
        print(f"Note title prefix is ambiguous in folder {folder}: {prefix}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Note title prefix not found in folder {folder}: {prefix}", file=sys.stderr)
    raise SystemExit(1)

if args and args[0] == "-e":
    print("(Daily Notes, Inbox)")
    raise SystemExit(0)

raise SystemExit(2)
""",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_show_note_prefix_reads_unique_note(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_osascript = Path(temp_dir) / "fake_osascript.py"
            self._write_fake_osascript(fake_osascript)
            env = os.environ.copy()
            env["OSASCRIPT_BIN"] = str(fake_osascript)
            result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER_PATH),
                    "show-note-prefix",
                    "--folder",
                    "Daily Notes",
                    "--prefix",
                    "2026.03.12",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout,
            "2026.03.12 (Wed) Daily Notes\n----\nValidated helper coverage\n",
        )

    def test_show_note_prefix_rejects_ambiguous_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_osascript = Path(temp_dir) / "fake_osascript.py"
            self._write_fake_osascript(fake_osascript)
            env = os.environ.copy()
            env["OSASCRIPT_BIN"] = str(fake_osascript)
            result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER_PATH),
                    "show-note-prefix",
                    "--folder",
                    "Daily Notes",
                    "--prefix",
                    "2026.03.dupe",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Note title prefix is ambiguous in folder Daily Notes", result.stderr)
        self.assertEqual(result.returncode, 1)

    def test_show_note_prefix_rejects_missing_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_osascript = Path(temp_dir) / "fake_osascript.py"
            self._write_fake_osascript(fake_osascript)
            env = os.environ.copy()
            env["OSASCRIPT_BIN"] = str(fake_osascript)
            result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER_PATH),
                    "show-note-prefix",
                    "--folder",
                    "Daily Notes",
                    "--prefix",
                    "2026.03.99",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Note title prefix not found in folder Daily Notes", result.stderr)

    def test_copy_db_copies_existing_file_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            group = root / "group"
            app = root / "app"
            group.mkdir()
            app.mkdir()
            for basename, payload in (
                ("NoteStore.sqlite", b"sqlite"),
                ("NoteStore.sqlite-wal", b"wal"),
                ("NoteStore.sqlite-shm", b"shm"),
            ):
                (group / basename).write_bytes(payload)
            dest = root / "dest"
            result = MODULE.copy_db(
                MODULE.NoteStorePaths(group_container=group, app_container=app),
                dest=dest,
                require_notes_quit=False,
            )
            copied_names = {Path(row["dest"]).name for row in result["copied_files"]}
            self.assertEqual(
                copied_names,
                {"NoteStore.sqlite", "NoteStore.sqlite-wal", "NoteStore.sqlite-shm"},
            )

    def test_merge_db_creates_readable_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            src = root / "NoteStore.sqlite"
            with closing(sqlite3.connect(src)) as conn:
                conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
                conn.execute("INSERT INTO sample(value) VALUES ('ok')")
                conn.commit()
            merged = root / "merged.sqlite"
            MODULE.merge_db(src, merged)
            with closing(sqlite3.connect(merged)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "ok")

    def test_query_note_tags_reads_expected_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "notes.sqlite"
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    """
                    CREATE TABLE ZICCLOUDSYNCINGOBJECT (
                        Z_PK INTEGER PRIMARY KEY,
                        ZIDENTIFIER TEXT,
                        ZTITLE1 TEXT,
                        ZNOTEDATA INTEGER,
                        ZNOTE1 INTEGER,
                        ZALTTEXT TEXT,
                        ZTOKENCONTENTIDENTIFIER TEXT,
                        ZTYPEUTI1 TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO ZICCLOUDSYNCINGOBJECT
                    (Z_PK, ZIDENTIFIER, ZTITLE1, ZNOTEDATA)
                    VALUES (1677, 'note-id', '2026.03.06 (Fri) Example Note', 653)
                    """
                )
                conn.commit()
                conn.execute(
                    """
                    INSERT INTO ZICCLOUDSYNCINGOBJECT
                    (Z_PK, ZIDENTIFIER, ZNOTE1, ZALTTEXT, ZTOKENCONTENTIDENTIFIER, ZTYPEUTI1)
                    VALUES
                    (1686, 'tag-id-1', 1677, '#example-tag-one', 'example-tag-one', 'com.apple.notes.inlinetextattachment.hashtag'),
                    (1687, 'tag-id-2', 1677, '#example-tag-two', 'example-tag-two', 'com.apple.notes.inlinetextattachment.hashtag')
                    """
                )
                conn.commit()
            result = MODULE.query_note_tags(db_path, "2026.03.06 (Fri) Example Note")
            self.assertEqual(result["note"]["pk"], 1677)
            self.assertEqual(
                [row["tag_text"] for row in result["tags"]],
                ["#example-tag-one", "#example-tag-two"],
            )


if __name__ == "__main__":
    unittest.main()
