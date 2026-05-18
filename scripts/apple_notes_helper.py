#!/usr/bin/env python3
"""Stable Apple Notes helper for read-only export and DB-copy workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GROUP_CONTAINER = Path.home() / "Library/Group Containers/group.com.apple.notes"
APP_CONTAINER = Path.home() / "Library/Containers/com.apple.Notes"
NOTE_STORE_BASENAMES = (
    "NoteStore.sqlite",
    "NoteStore.sqlite-wal",
    "NoteStore.sqlite-shm",
)
@dataclass(frozen=True)
class NoteStorePaths:
    group_container: Path = GROUP_CONTAINER
    app_container: Path = APP_CONTAINER

    def note_store_files(self) -> list[Path]:
        return [self.group_container / name for name in NOTE_STORE_BASENAMES]


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Unsupported JSON value: {value!r}")


def emit_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False, default=_json_default)
    sys.stdout.write("\n")


def notes_is_running() -> bool:
    result = subprocess.run(
        ["pgrep", "-x", "Notes"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def probe_db_access(paths: NoteStorePaths) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in (paths.group_container, paths.app_container):
        record: dict[str, Any] = {
            "path": path,
            "exists": path.exists(),
            "readable": False,
        }
        try:
            children = sorted(child.name for child in path.iterdir())
            record["readable"] = True
            record["sample_children"] = children[:5]
        except PermissionError as exc:
            record["error"] = str(exc)
        except FileNotFoundError:
            record["sample_children"] = []
        entries.append(record)
    file_records: list[dict[str, Any]] = []
    for db_file in paths.note_store_files():
        file_record: dict[str, Any] = {
            "path": db_file,
            "exists": db_file.exists(),
            "readable": False,
        }
        try:
            stat_result = db_file.stat()
            file_record["readable"] = True
            file_record["size"] = stat_result.st_size
            file_record["mtime"] = stat_result.st_mtime
        except PermissionError as exc:
            file_record["error"] = str(exc)
        except FileNotFoundError:
            pass
        file_records.append(file_record)
    return {
        "paths": entries,
        "note_store_files": file_records,
    }


def _timestamped_tmp_dir(prefix: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("/tmp") / f"{prefix}-{timestamp}"


def copy_db(paths: NoteStorePaths, *, dest: Path | None, require_notes_quit: bool) -> dict[str, Any]:
    notes_running = notes_is_running()
    if require_notes_quit and notes_running:
        raise RuntimeError("Notes.app is running; quit it before using --require-notes-quit")

    destination = dest or _timestamped_tmp_dir("apple-notes-probe")
    group_dest = destination / "group.com.apple.notes"
    app_dest = destination / "com.apple.Notes"
    group_dest.mkdir(parents=True, exist_ok=True)
    app_dest.mkdir(parents=True, exist_ok=True)

    copied_files: list[dict[str, Any]] = []
    for basename in NOTE_STORE_BASENAMES:
        src = paths.group_container / basename
        if not src.exists():
            continue
        dst = group_dest / basename
        shutil.copy2(src, dst)
        copied_files.append(
            {
                "source": src,
                "dest": dst,
                "size": dst.stat().st_size,
            }
        )

    return {
        "dest": destination,
        "notes_running": notes_running,
        "notes_quit_required": require_notes_quit,
        "copied_files": copied_files,
    }


def merge_db(src: Path, out: Path | None) -> dict[str, Any]:
    output = out or src.with_name("NoteStore-merged-for-analysis.sqlite")
    with closing(sqlite3.connect(src)) as source_conn, closing(sqlite3.connect(output)) as output_conn:
        source_conn.backup(output_conn)
    return {
        "source_db": src,
        "merged_db": output,
        "size": output.stat().st_size,
    }


def query_note_tags(db_path: Path, note_title: str) -> dict[str, Any]:
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        note_row = conn.execute(
            """
            SELECT Z_PK, ZIDENTIFIER, ZTITLE1, ZNOTEDATA
            FROM ZICCLOUDSYNCINGOBJECT
            WHERE ZTITLE1 = ?
            """,
            (note_title,),
        ).fetchone()
        if note_row is None:
            raise RuntimeError(f"Note not found in database: {note_title}")
        tag_rows = conn.execute(
            """
            SELECT Z_PK, ZIDENTIFIER, ZNOTE1, ZALTTEXT, ZTOKENCONTENTIDENTIFIER, ZTYPEUTI1
            FROM ZICCLOUDSYNCINGOBJECT
            WHERE ZNOTE1 = ?
              AND ZTYPEUTI1 = 'com.apple.notes.inlinetextattachment.hashtag'
            ORDER BY Z_PK
            """,
            (note_row["Z_PK"],),
        ).fetchall()
    return {
        "note": {
            "pk": note_row["Z_PK"],
            "identifier": note_row["ZIDENTIFIER"],
            "title": note_row["ZTITLE1"],
            "note_data_pk": note_row["ZNOTEDATA"],
        },
        "tags": [
            {
                "pk": row["Z_PK"],
                "identifier": row["ZIDENTIFIER"],
                "note_fk": row["ZNOTE1"],
                "tag_text": row["ZALTTEXT"],
                "tag_token": row["ZTOKENCONTENTIDENTIFIER"],
                "type_uti": row["ZTYPEUTI1"],
            }
            for row in tag_rows
        ],
    }


def fingerprint_note_store(paths: NoteStorePaths) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for file_path in paths.note_store_files():
        if not file_path.exists():
            continue
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        stat_result = file_path.stat()
        rows.append(
            {
                "path": file_path,
                "sha256": digest.hexdigest(),
                "size": stat_result.st_size,
                "mtime": stat_result.st_mtime,
            }
        )
    return {"files": rows}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("probe-db-access", help="Probe NoteStore access without copying.")

    copy_parser = subparsers.add_parser("copy-db", help="Copy NoteStore files into /tmp.")
    copy_parser.add_argument("--dest", type=Path, help="Destination directory. Defaults to /tmp timestamped dir.")
    copy_parser.add_argument(
        "--require-notes-quit",
        action="store_true",
        help="Fail if Notes.app is currently running.",
    )

    merge_parser = subparsers.add_parser("merge-db", help="Create a merged analysis DB from a copied NoteStore.")
    merge_parser.add_argument("--src", type=Path, required=True, help="Copied NoteStore.sqlite path.")
    merge_parser.add_argument("--out", type=Path, help="Output merged DB path.")

    tags_parser = subparsers.add_parser("note-tags", help="Read hashtag rows for a note title from a DB copy.")
    tags_parser.add_argument("--db", type=Path, required=True, help="Merged or copied sqlite path.")
    tags_parser.add_argument("--title", required=True, help="Exact note title.")

    subparsers.add_parser("fingerprint-db", help="Hash live NoteStore sqlite/wal/shm files.")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    paths = NoteStorePaths()

    try:
        if args.command == "probe-db-access":
            emit_json(probe_db_access(paths))
            return 0
        if args.command == "copy-db":
            emit_json(copy_db(paths, dest=args.dest, require_notes_quit=args.require_notes_quit))
            return 0
        if args.command == "merge-db":
            emit_json(merge_db(args.src, args.out))
            return 0
        if args.command == "note-tags":
            emit_json(query_note_tags(args.db, args.title))
            return 0
        if args.command == "fingerprint-db":
            emit_json(fingerprint_note_store(paths))
            return 0
    except Exception as exc:  # noqa: BLE001
        emit_json({"error": str(exc), "command": args.command})
        return 1

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
