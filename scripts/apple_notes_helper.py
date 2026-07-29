#!/usr/bin/env python3
"""Compatibility launcher for the packaged Apple Notes DB guardrail helper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable


HELPER_PATH = (
    Path(__file__).resolve().parent.parent
    / ".agents"
    / "skills"
    / "apple-notes-db-guardrails"
    / "scripts"
    / "apple_notes_db.py"
)
DIRECTORY_SUPERVISOR_PATH = HELPER_PATH.with_name("apple_notes_directory_supervisor.py")
WRITE_PRODUCING_COMMANDS = frozenset(
    {
        "copy-db",
        "merge-db",
        "recover-snapshot",
        "stage-patch",
    }
)


def _load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "packaged_apple_notes_db", HELPER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load packaged helper: {HELPER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_directory_supervisor() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "packaged_apple_notes_directory_supervisor",
        DIRECTORY_SUPERVISOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Cannot load packaged directory supervisor: {DIRECTORY_SUPERVISOR_PATH}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_HELPER = _load_helper()

# Preserve the complete legacy public Python API while keeping one implementation.
GROUP_CONTAINER = _HELPER.GROUP_CONTAINER
APP_CONTAINER = _HELPER.APP_CONTAINER
NOTE_STORE_BASENAMES = _HELPER.NOTE_STORE_BASENAMES
NoteStorePaths = _HELPER.NoteStorePaths
StoreSafetyError = _HELPER.StoreSafetyError
emit_json = _HELPER.emit_json
notes_is_running = _HELPER.notes_is_running
copy_db = _HELPER.copy_db
directory_creator_supervisor = _HELPER.directory_creator_supervisor
fingerprint_note_store = _HELPER.fingerprint_note_store
merge_db = _HELPER.merge_db
probe_db_access = _HELPER.probe_db_access
query_note_tags = _HELPER.query_note_tags
build_parser = _HELPER.build_parser

# The packaged implementation also exposes the newer artifact workflows through
# this stable import location. Existing callers remain source-compatible, while
# new callers do not need to bypass the compatibility module.
recover_snapshot = _HELPER.recover_snapshot
stage_patch = _HELPER.stage_patch
validate_database_recovery = _HELPER.validate_database_recovery
validate_patch_stage = _HELPER.validate_patch_stage
validate_snapshot = _HELPER.validate_snapshot
preflight_writeback = _HELPER.preflight_writeback
verify_writeback = _HELPER.verify_writeback

__all__ = [
    "APP_CONTAINER",
    "GROUP_CONTAINER",
    "NOTE_STORE_BASENAMES",
    "NoteStorePaths",
    "StoreSafetyError",
    "build_parser",
    "copy_db",
    "directory_creator_supervisor",
    "emit_json",
    "fingerprint_note_store",
    "main",
    "merge_db",
    "notes_is_running",
    "preflight_writeback",
    "probe_db_access",
    "query_note_tags",
    "recover_snapshot",
    "stage_patch",
    "validate_database_recovery",
    "validate_patch_stage",
    "validate_snapshot",
    "verify_writeback",
]


def _has_directory_creator_fd(arguments: Iterable[str]) -> bool:
    return any(
        argument == "--directory-creator-fd"
        or argument.startswith("--directory-creator-fd=")
        for argument in arguments
    )


def main(argv: Iterable[str] | None = None) -> int:
    """Run the legacy CLI, supervising every write-producing command."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if (
        arguments
        and arguments[0] in WRITE_PRODUCING_COMMANDS
        and not _has_directory_creator_fd(arguments)
    ):
        supervisor = _load_directory_supervisor()
        return supervisor.main(
            [
                "--helper",
                str(HELPER_PATH),
                "--python",
                sys.executable,
                "--",
                *arguments,
            ]
        )
    return _HELPER.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
