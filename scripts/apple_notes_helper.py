#!/usr/bin/env python3
"""Compatibility launcher for the packaged Apple Notes DB guardrail helper."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
HELPER_PATH = (
    REPO_ROOT
    / ".agents"
    / "skills"
    / "apple-notes-db-guardrails"
    / "scripts"
    / "apple_notes_db.py"
)
DIRECTORY_SUPERVISOR_PATH = HELPER_PATH.with_name("apple_notes_directory_supervisor.py")
SUPERVISOR_SOURCE_MAX_BYTES = 2 * 1024 * 1024
SUPERVISOR_SOURCE_READ_CHUNK_BYTES = 64 * 1024
_DARWIN_ACCESS_POLICY_FLAG_MASK = sum(
    (
        0x00000002,  # UF_IMMUTABLE
        0x00000004,  # UF_APPEND
        0x00000080,  # UF_DATAVAULT
        0x00020000,  # SF_IMMUTABLE
        0x00040000,  # SF_APPEND
        0x00080000,  # SF_RESTRICTED
        0x00100000,  # SF_NOUNLINK
    )
)
WRITE_PRODUCING_COMMANDS = frozenset(
    {
        "copy-db",
        "merge-db",
        "recover-snapshot",
        "stage-patch",
    }
)


@dataclass(frozen=True)
class _CapturedSupervisorSource:
    display_path: Path
    source: bytes
    sha256: str
    identity: tuple[int, int, int]
    access_policy: tuple[int, int, int, int]


def _source_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode))


def _source_access_policy(
    value: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
        int(getattr(value, "st_flags", 0)) & _DARWIN_ACCESS_POLICY_FLAG_MASK,
    )


def _read_source_pass(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(
            descriptor,
            min(remaining, SUPERVISOR_SOURCE_READ_CHUNK_BYTES),
        )
        if not chunk:
            raise RuntimeError(
                "packaged directory supervisor source became truncated during capture"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise RuntimeError(
            "packaged directory supervisor source grew during bounded capture"
        )
    return b"".join(chunks)


def _capture_directory_supervisor_source(
    path: Path,
) -> _CapturedSupervisorSource:
    """Capture one stable no-follow supervisor byte object before execution."""

    display_path = Path(os.path.abspath(os.fspath(path)))
    try:
        before_path = os.stat(display_path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(
            f"Cannot inspect packaged directory supervisor: {display_path}: {exc}"
        ) from exc
    if not stat.S_ISREG(before_path.st_mode):
        raise RuntimeError(
            f"Packaged directory supervisor is not a regular file: {display_path}"
        )
    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or cloexec is None or nonblock is None:
        raise RuntimeError(
            "Packaged directory supervisor capture requires "
            "O_NOFOLLOW, O_CLOEXEC, and O_NONBLOCK"
        )
    try:
        descriptor = os.open(
            display_path,
            os.O_RDONLY | nofollow | cloexec | nonblock,
        )
    except OSError as exc:
        raise RuntimeError(
            f"Cannot open packaged directory supervisor safely: {display_path}: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _source_identity(opened) != _source_identity(before_path)
            or _source_access_policy(opened) != _source_access_policy(before_path)
        ):
            raise RuntimeError(
                "Packaged directory supervisor changed across no-follow open: "
                f"{display_path}"
            )
        expected_size = opened.st_size
        if expected_size < 1 or expected_size > SUPERVISOR_SOURCE_MAX_BYTES:
            raise RuntimeError(
                "Packaged directory supervisor size is outside the bounded "
                f"capture contract: {display_path}: {expected_size}"
            )
        first = _read_source_pass(descriptor, expected_size)
        middle = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_source_pass(descriptor, expected_size)
        after = os.fstat(descriptor)
        try:
            after_path = os.stat(display_path, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(
                "Cannot terminally inspect packaged directory supervisor: "
                f"{display_path}: {exc}"
            ) from exc
    finally:
        os.close(descriptor)

    identity = _source_identity(opened)
    access_policy = _source_access_policy(opened)
    if any(
        _source_identity(value) != identity for value in (middle, after, after_path)
    ):
        raise RuntimeError(
            "Packaged directory supervisor identity changed during capture: "
            f"{display_path}"
        )
    if any(
        _source_access_policy(value) != access_policy
        for value in (middle, after, after_path)
    ):
        raise RuntimeError(
            "Packaged directory supervisor access policy changed during capture: "
            f"{display_path}"
        )
    if any(value.st_size != expected_size for value in (middle, after, after_path)):
        raise RuntimeError(
            f"Packaged directory supervisor size changed during capture: {display_path}"
        )
    if first != second:
        raise RuntimeError(
            "Packaged directory supervisor content changed during capture: "
            f"{display_path}"
        )
    return _CapturedSupervisorSource(
        display_path=display_path,
        source=first,
        sha256=hashlib.sha256(first).hexdigest(),
        identity=identity,
        access_policy=access_policy,
    )


def _load_directory_supervisor(
    capture: _CapturedSupervisorSource,
    *,
    module_name: str = "packaged_apple_notes_directory_supervisor",
) -> ModuleType:
    module = ModuleType(module_name)
    module.__file__ = os.fspath(capture.display_path)
    module.__package__ = ""
    module.__cached__ = None
    module.__captured_source_sha256__ = capture.sha256
    sys.modules[module_name] = module
    try:
        code = compile(
            capture.source,
            os.fspath(capture.display_path),
            "exec",
            dont_inherit=True,
        )
        exec(code, module.__dict__, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


DIRECTORY_SUPERVISOR_CAPTURE = _capture_directory_supervisor_source(
    DIRECTORY_SUPERVISOR_PATH
)
_SUPERVISOR = _load_directory_supervisor(DIRECTORY_SUPERVISOR_CAPTURE)
HELPER_CAPTURE = _SUPERVISOR.HELPER_CAPTURE
_HELPER = _SUPERVISOR.HELPER

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
        return _SUPERVISOR.run_supervised(
            HELPER_CAPTURE.display_path,
            arguments,
            python_bin=sys.executable,
        )
    return _HELPER.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
