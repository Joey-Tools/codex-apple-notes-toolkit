#!/usr/bin/env python3
"""Compatibility launcher for the packaged Apple Notes DB guardrail helper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


HELPER_PATH = (
    Path(__file__).resolve().parent.parent
    / ".agents"
    / "skills"
    / "apple-notes-db-guardrails"
    / "scripts"
    / "apple_notes_db.py"
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


_HELPER = _load_helper()

# Preserve the small Python API used by existing callers while keeping one implementation.
NoteStorePaths = _HELPER.NoteStorePaths
StoreSafetyError = _HELPER.StoreSafetyError
copy_db = _HELPER.copy_db
directory_creator_supervisor = _HELPER.directory_creator_supervisor
fingerprint_note_store = _HELPER.fingerprint_note_store
merge_db = _HELPER.merge_db
probe_db_access = _HELPER.probe_db_access
query_note_tags = _HELPER.query_note_tags
main = _HELPER.main


if __name__ == "__main__":
    raise SystemExit(main())
