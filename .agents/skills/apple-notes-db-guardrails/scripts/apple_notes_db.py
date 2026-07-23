#!/usr/bin/env python3
"""Audit, recover, stage, and verify Apple Notes SQLite stores safely."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


GROUP_CONTAINER = Path.home() / "Library/Group Containers/group.com.apple.notes"
APP_CONTAINER = Path.home() / "Library/Containers/com.apple.Notes"
NOTE_STORE_MAIN = "NoteStore.sqlite"
NOTE_STORE_BASENAMES = (
    NOTE_STORE_MAIN,
    f"{NOTE_STORE_MAIN}-wal",
    f"{NOTE_STORE_MAIN}-shm",
)
SNAPSHOT_MANIFEST = "snapshot-manifest.json"
PATCH_MANIFEST = "patch-manifest.json"
SNAPSHOT_SCHEMA = "apple-notes-snapshot/v1"
PATCH_SCHEMA = "apple-notes-patch/v1"
CHUNK_SIZE = 1024 * 1024
MANIFEST_MAX_BYTES = 4 * 1024 * 1024
WAL_MAGIC_NUMBERS = {0x377F0682, 0x377F0683}
WAL_VERSION = 3007000
AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCL = 0x00000004


class StoreSafetyError(RuntimeError):
    """A classified safety failure that must not be treated as absence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class NoteStorePaths:
    group_container: Path = GROUP_CONTAINER
    app_container: Path = APP_CONTAINER

    def note_store_files(self) -> list[Path]:
        return [self.group_container / name for name in NOTE_STORE_BASENAMES]


@dataclass
class _OpenedSource:
    path: Path
    fd: int
    before: os.stat_result
    first_sha256: str | None = None
    copied: dict[str, Any] | None = None


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Unsupported JSON value: {value!r}")


def emit_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False, default=_json_default)
    sys.stdout.write("\n")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamped_tmp_dir(prefix: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    return Path("/tmp") / f"{prefix}-{timestamp}-{uuid.uuid4().hex[:8]}"


def _stat_ns(value: os.stat_result, field: str) -> int:
    exact = getattr(value, f"st_{field}_ns", None)
    if exact is not None:
        return int(exact)
    return int(getattr(value, f"st_{field}") * 1_000_000_000)


def _identity(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "file_type": stat.S_IFMT(value.st_mode),
    }


def _access_policy(value: os.stat_result) -> dict[str, int]:
    return {
        "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "flags": int(getattr(value, "st_flags", 0)),
    }


def _metadata(value: os.stat_result) -> dict[str, int]:
    return {
        "mtime_ns": _stat_ns(value, "mtime"),
        "ctime_ns": _stat_ns(value, "ctime"),
        "link_count": value.st_nlink,
    }


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return _identity(left) == _identity(right)


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    """Atomically rename a directory without replacing an existing name."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise OSError(
                errno.ENOTSUP,
                "renamex_np is unavailable; refusing a non-atomic publication",
            )
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(source_bytes, destination_bytes, RENAME_EXCL)
    elif sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError(
                errno.ENOTSUP,
                "renameat2 is unavailable; refusing a non-atomic publication",
            )
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            AT_FDCWD,
            source_bytes,
            AT_FDCWD,
            destination_bytes,
            RENAME_NOREPLACE,
        )
    else:
        raise OSError(
            errno.ENOTSUP,
            f"Atomic no-replace directory publication is unsupported on {sys.platform}",
        )

    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(
            error_number,
            os.strerror(error_number),
            os.fspath(source),
            os.fspath(destination),
        )


def _observe_path(path: Path) -> tuple[str, os.stat_result | None]:
    try:
        value = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unavailable", None
    return "present", value


def _publish_directory_no_replace(source: Path, destination: Path) -> None:
    try:
        source_before = os.stat(source, follow_symlinks=False)
    except OSError as exc:
        raise StoreSafetyError(
            "destination-install-failed",
            f"Cannot inspect private publication source {source}: {exc}",
        ) from exc
    if not stat.S_ISDIR(source_before.st_mode):
        raise StoreSafetyError(
            "destination-install-failed",
            f"Private publication source is not a directory: {source}",
        )
    source_identity = _identity(source_before)
    source_access_policy = _access_policy(source_before)

    try:
        _rename_directory_no_replace(source, destination)
    except OSError as exc:
        source_state, source_after = _observe_path(source)
        destination_state, destination_after = _observe_path(destination)
        committed = (
            source_state == "absent"
            and destination_state == "present"
            and destination_after is not None
            and _identity(destination_after) == source_identity
        )
        if committed:
            raise StoreSafetyError(
                "destination-install-uncertain",
                "The destination contains the prepared directory, but the "
                f"publication syscall reported an error: {destination}: {exc}",
            ) from exc
        if (
            exc.errno in {errno.EEXIST, errno.ENOTEMPTY}
            and source_state == "present"
            and source_after is not None
            and _identity(source_after) == source_identity
            and destination_state == "present"
        ):
            raise StoreSafetyError(
                "destination-exists",
                f"Destination appeared before atomic installation: {destination}",
            ) from exc
        if (
            source_state == "present"
            and source_after is not None
            and _identity(source_after) == source_identity
            and destination_state == "absent"
        ):
            raise StoreSafetyError(
                "destination-install-failed",
                f"Cannot atomically install directory at {destination}: {exc}",
            ) from exc
        raise StoreSafetyError(
            "destination-install-uncertain",
            "Cannot prove whether directory publication committed; preserve both "
            f"paths for inspection: source={source}, destination={destination}: {exc}",
        ) from exc

    source_state, _ = _observe_path(source)
    destination_state, destination_after = _observe_path(destination)
    if (
        source_state != "absent"
        or destination_state != "present"
        or destination_after is None
        or _identity(destination_after) != source_identity
        or _access_policy(destination_after) != source_access_policy
    ):
        raise StoreSafetyError(
            "destination-install-uncertain",
            "The no-replace syscall returned success, but namespace revalidation "
            f"could not bind the installed directory: {destination}",
        )
    try:
        _fsync_directory(destination.parent)
    except OSError as exc:
        raise StoreSafetyError(
            "destination-install-uncertain",
            f"Directory was published but parent durability is unconfirmed: "
            f"{destination}: {exc}",
        ) from exc


def _open_regular_readonly(path: Path) -> tuple[int, os.stat_result]:
    try:
        path_before = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "source-missing", f"Source file is missing: {path}"
        ) from exc
    except PermissionError as exc:
        raise StoreSafetyError(
            "source-unreadable", f"Source file is unreadable: {path}"
        ) from exc
    if not stat.S_ISREG(path_before.st_mode):
        raise StoreSafetyError(
            "source-not-regular", f"Source path is not a regular file: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "source-missing", f"Source disappeared before open: {path}"
        ) from exc
    except PermissionError as exc:
        raise StoreSafetyError(
            "source-unreadable", f"Source cannot be opened: {path}"
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "source-open-failed", f"Cannot safely open source file {path}: {exc}"
        ) from exc

    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise StoreSafetyError(
                "source-not-regular", f"Opened source is not a regular file: {path}"
            )
        if not _same_identity(path_before, opened):
            raise StoreSafetyError(
                "source-identity-mismatch",
                f"Source object was replaced while opening: {path}",
            )
        return fd, opened
    except Exception:
        os.close(fd)
        raise


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short write while copying database file")
        offset += written


def _copy_fd(fd: int, destination: Path) -> dict[str, Any]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    out_fd = os.open(destination, flags, 0o600)
    digest = hashlib.sha256()
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(fd, CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            _write_all(out_fd, chunk)
        os.fsync(out_fd)
        written_sha256 = digest.hexdigest()
        readback_sha256 = _hash_fd(out_fd)
        if written_sha256 != readback_sha256:
            raise StoreSafetyError(
                "copy-content-mismatch",
                f"Destination readback differs from bytes written: {destination}",
            )
        descriptor_stat = os.fstat(out_fd)
        path_stat = os.stat(destination, follow_symlinks=False)
        if not _same_identity(descriptor_stat, path_stat):
            raise StoreSafetyError(
                "copy-identity-mismatch",
                f"Destination was replaced during copy: {destination}",
            )
        return {
            "path": destination,
            "sha256": written_sha256,
            "size": descriptor_stat.st_size,
            "identity": _identity(descriptor_stat),
            "access_policy": _access_policy(descriptor_stat),
        }
    finally:
        os.close(out_fd)


def _discover_database_files(main_path: Path) -> list[Path]:
    candidates = (
        main_path,
        main_path.with_name(f"{main_path.name}-wal"),
        main_path.with_name(f"{main_path.name}-shm"),
    )
    present: list[Path] = []
    for candidate in candidates:
        try:
            os.stat(candidate, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise StoreSafetyError(
                "source-unreadable",
                f"Cannot determine database file-set membership: {candidate}",
            ) from exc
        present.append(candidate)
    if main_path not in present:
        raise StoreSafetyError(
            "source-missing", f"Main SQLite file is missing: {main_path}"
        )
    return present


def _revalidate_open_source(
    opened: _OpenedSource, second_sha256: str
) -> dict[str, Any]:
    after = os.fstat(opened.fd)
    try:
        path_after = os.stat(opened.path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "source-missing-after-read",
            f"Source path disappeared during read: {opened.path}",
        ) from exc
    except PermissionError as exc:
        raise StoreSafetyError(
            "source-revalidation-unreadable",
            f"Source path became unreadable during revalidation: {opened.path}",
        ) from exc

    if not _same_identity(opened.before, after) or not _same_identity(
        after, path_after
    ):
        raise StoreSafetyError(
            "source-identity-mismatch",
            f"Source object identity changed during read: {opened.path}",
        )
    if opened.first_sha256 != second_sha256 or opened.before.st_size != after.st_size:
        raise StoreSafetyError(
            "source-content-mismatch",
            f"Source bytes changed during read: {opened.path}",
        )
    if _access_policy(opened.before) != _access_policy(after):
        raise StoreSafetyError(
            "source-access-policy-mismatch",
            f"Source access policy changed during read: {opened.path}",
        )

    before_metadata = _metadata(opened.before)
    after_metadata = _metadata(after)
    transitions = {
        key: {"before": before_metadata[key], "after": after_metadata[key]}
        for key in before_metadata
        if before_metadata[key] != after_metadata[key]
    }
    return {
        "path": opened.path,
        "sha256": second_sha256,
        "size": after.st_size,
        "identity": _identity(after),
        "access_policy": _access_policy(after),
        "metadata": after_metadata,
        "metadata_transitions": transitions,
    }


def _capture_database_files(
    main_path: Path, destination_dir: Path | None = None
) -> list[dict[str, Any]]:
    before_paths = _discover_database_files(main_path)
    before_names = [path.name for path in before_paths]
    opened_sources: list[_OpenedSource] = []
    try:
        for path in before_paths:
            fd, opened_stat = _open_regular_readonly(path)
            opened_sources.append(_OpenedSource(path=path, fd=fd, before=opened_stat))

        after_open_names = [path.name for path in _discover_database_files(main_path)]
        if after_open_names != before_names:
            raise StoreSafetyError(
                "store-file-set-mismatch",
                "SQLite/WAL/SHM membership changed while opening the store",
            )

        if destination_dir is not None:
            destination_dir.mkdir(mode=0o700, parents=True, exist_ok=False)

        for opened in opened_sources:
            if destination_dir is None:
                opened.first_sha256 = _hash_fd(opened.fd)
            else:
                opened.copied = _copy_fd(opened.fd, destination_dir / opened.path.name)
                opened.first_sha256 = opened.copied["sha256"]

        records: list[dict[str, Any]] = []
        for opened in opened_sources:
            second_sha256 = _hash_fd(opened.fd)
            source_record = _revalidate_open_source(opened, second_sha256)
            record: dict[str, Any] = {
                "basename": opened.path.name,
                "source": source_record,
            }
            if opened.copied is not None:
                record["copy"] = opened.copied
            records.append(record)

        for opened, record in zip(opened_sources, records, strict=True):
            final_descriptor = os.fstat(opened.fd)
            try:
                final_path = os.stat(opened.path, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise StoreSafetyError(
                    "source-missing-after-read",
                    f"Source path disappeared during final revalidation: {opened.path}",
                ) from exc
            except PermissionError as exc:
                raise StoreSafetyError(
                    "source-revalidation-unreadable",
                    f"Source became unreadable during final revalidation: {opened.path}",
                ) from exc
            if not _same_identity(
                opened.before, final_descriptor
            ) or not _same_identity(final_descriptor, final_path):
                raise StoreSafetyError(
                    "source-identity-mismatch",
                    f"Source object identity changed during final revalidation: {opened.path}",
                )
            if final_descriptor.st_size != record["source"]["size"]:
                raise StoreSafetyError(
                    "source-content-mismatch",
                    f"Source size changed after hashing: {opened.path}",
                )
            if (
                _stat_ns(final_descriptor, "mtime")
                != record["source"]["metadata"]["mtime_ns"]
            ):
                raise StoreSafetyError(
                    "source-revalidation-inconclusive",
                    f"Source mtime changed after its final byte hash: {opened.path}",
                )
            if _access_policy(final_descriptor) != record["source"]["access_policy"]:
                raise StoreSafetyError(
                    "source-access-policy-mismatch",
                    f"Source access policy changed during final revalidation: {opened.path}",
                )

        final_names = [path.name for path in _discover_database_files(main_path)]
        if final_names != before_names:
            raise StoreSafetyError(
                "store-file-set-mismatch",
                "SQLite/WAL/SHM membership changed during capture",
            )
        return records
    finally:
        for opened in opened_sources:
            os.close(opened.fd)


def _fingerprint_exact_file(path: Path) -> dict[str, Any]:
    fd, opened_stat = _open_regular_readonly(path)
    opened = _OpenedSource(path=path, fd=fd, before=opened_stat)
    try:
        opened.first_sha256 = _hash_fd(fd)
        second_sha256 = _hash_fd(fd)
        return _revalidate_open_source(opened, second_sha256)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _scan_exact_directory_entries(
    path: Path,
    expected_types: dict[str, int],
    *,
    missing_code: str,
    mismatch_code: str,
    bound_identity: dict[str, int] | None = None,
    bound_access_policy: dict[str, int] | None = None,
) -> dict[str, Any]:
    try:
        path_before = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise StoreSafetyError(missing_code, f"Directory is missing: {path}") from exc
    except OSError as exc:
        raise StoreSafetyError(
            "directory-scan-inconclusive",
            f"Cannot inspect directory before exact file-set validation: {path}: {exc}",
        ) from exc
    if not stat.S_ISDIR(path_before.st_mode):
        raise StoreSafetyError(
            mismatch_code,
            f"Expected a real directory during exact file-set validation: {path}",
        )

    expected_identity = _identity(path_before)
    expected_access_policy = _access_policy(path_before)
    if bound_identity is not None and expected_identity != bound_identity:
        raise StoreSafetyError(
            "directory-identity-mismatch",
            f"Directory object changed between validation phases: {path}",
        )
    if (
        bound_access_policy is not None
        and expected_access_policy != bound_access_policy
    ):
        raise StoreSafetyError(
            "directory-access-policy-mismatch",
            f"Directory access policy changed between validation phases: {path}",
        )
    scans: list[dict[str, int]] = []
    for _ in range(2):
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(path, flags)
        except FileNotFoundError as exc:
            raise StoreSafetyError(
                "directory-identity-mismatch",
                f"Directory disappeared during exact file-set validation: {path}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                "directory-scan-inconclusive",
                f"Cannot open directory for exact file-set validation: {path}: {exc}",
            ) from exc
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _identity(opened) != expected_identity
            ):
                raise StoreSafetyError(
                    "directory-identity-mismatch",
                    f"Directory object changed during exact file-set validation: {path}",
                )
            if _access_policy(opened) != expected_access_policy:
                raise StoreSafetyError(
                    "directory-access-policy-mismatch",
                    f"Directory access policy changed during validation: {path}",
                )
            try:
                with os.scandir(fd) as entries:
                    scan: dict[str, int] = {}
                    for entry in entries:
                        name = os.fsdecode(entry.name)
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                        except FileNotFoundError as exc:
                            raise StoreSafetyError(
                                mismatch_code,
                                "Directory membership changed during exact file-set "
                                f"validation: {path}",
                            ) from exc
                        except OSError as exc:
                            raise StoreSafetyError(
                                "directory-scan-inconclusive",
                                f"Cannot inspect directory entry without following "
                                f"links: {path / name}: {exc}",
                            ) from exc
                        scan[name] = stat.S_IFMT(entry_stat.st_mode)
            except StoreSafetyError:
                raise
            except OSError as exc:
                raise StoreSafetyError(
                    "directory-scan-inconclusive",
                    f"Cannot enumerate directory for exact file-set validation: "
                    f"{path}: {exc}",
                ) from exc
            opened_after = os.fstat(fd)
            if _identity(opened_after) != expected_identity:
                raise StoreSafetyError(
                    "directory-identity-mismatch",
                    f"Directory object changed during exact file-set validation: {path}",
                )
            if _access_policy(opened_after) != expected_access_policy:
                raise StoreSafetyError(
                    "directory-access-policy-mismatch",
                    f"Directory access policy changed during validation: {path}",
                )
            scans.append(scan)
        finally:
            os.close(fd)

    try:
        path_after = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "directory-identity-mismatch",
            f"Directory disappeared during final file-set revalidation: {path}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "directory-scan-inconclusive",
            f"Cannot revalidate directory after exact file-set scan: {path}: {exc}",
        ) from exc
    if _identity(path_after) != expected_identity:
        raise StoreSafetyError(
            "directory-identity-mismatch",
            f"Directory path was replaced during exact file-set validation: {path}",
        )
    if _access_policy(path_after) != expected_access_policy:
        raise StoreSafetyError(
            "directory-access-policy-mismatch",
            f"Directory access policy changed during validation: {path}",
        )
    if scans[0] != scans[1] or scans[1] != expected_types:
        raise StoreSafetyError(
            mismatch_code,
            f"Directory name/type set differs from the exact expected set: {path}",
        )
    return {
        "identity": expected_identity,
        "access_policy": expected_access_policy,
        "entry_types": scans[1],
    }


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(temp_path, flags, 0o600)
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
                json.dump(
                    payload, handle, indent=2, ensure_ascii=False, default=_json_default
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(fd)
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _load_manifest(path: Path, expected_schema: str) -> dict[str, Any]:
    try:
        fd, opened_stat = _open_regular_readonly(path)
    except StoreSafetyError as exc:
        if exc.code == "source-missing":
            raise StoreSafetyError(
                "manifest-missing", f"Manifest is missing: {path}"
            ) from exc
        if exc.code == "source-unreadable":
            raise StoreSafetyError(
                "manifest-unreadable", f"Manifest is unreadable: {path}"
            ) from exc
        raise
    opened = _OpenedSource(path=path, fd=fd, before=opened_stat)
    try:
        if opened_stat.st_size > MANIFEST_MAX_BYTES:
            raise StoreSafetyError(
                "manifest-too-large",
                f"Manifest exceeds {MANIFEST_MAX_BYTES} bytes: {path}",
            )
        os.lseek(fd, 0, os.SEEK_SET)
        payload_bytes = bytearray()
        while True:
            chunk = os.read(
                fd, min(CHUNK_SIZE, MANIFEST_MAX_BYTES + 1 - len(payload_bytes))
            )
            if not chunk:
                break
            payload_bytes.extend(chunk)
            if len(payload_bytes) > MANIFEST_MAX_BYTES:
                raise StoreSafetyError(
                    "manifest-too-large",
                    f"Manifest exceeds {MANIFEST_MAX_BYTES} bytes: {path}",
                )
        opened.first_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        second_sha256 = _hash_fd(fd)
        _revalidate_open_source(opened, second_sha256)
    finally:
        os.close(fd)
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreSafetyError(
            "manifest-unreadable", f"Cannot read manifest {path}: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema") != expected_schema:
        raise StoreSafetyError(
            "manifest-schema-mismatch",
            f"Unexpected manifest schema in {path}; expected {expected_schema}",
        )
    return payload


def notes_is_running() -> bool:
    try:
        result = subprocess.run(
            ["pgrep", "-x", "Notes"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise StoreSafetyError(
            "notes-state-unknown", f"Cannot inspect Notes.app state: {exc}"
        ) from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise StoreSafetyError(
        "notes-state-unknown",
        f"pgrep could not determine Notes.app state (exit {result.returncode})",
    )


def probe_db_access(paths: NoteStorePaths) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in (paths.group_container, paths.app_container):
        record: dict[str, Any] = {"path": path, "exists": False, "readable": False}
        try:
            with os.scandir(path) as children:
                record["sample_children"] = sorted(entry.name for entry in children)[:5]
            record["exists"] = True
            record["readable"] = True
        except FileNotFoundError:
            record["sample_children"] = []
        except PermissionError as exc:
            record["exists"] = True
            record["error_code"] = "container-unreadable"
            record["error"] = str(exc)
        entries.append(record)

    file_records: list[dict[str, Any]] = []
    for db_file in paths.note_store_files():
        file_record: dict[str, Any] = {
            "path": db_file,
            "exists": False,
            "readable": False,
        }
        try:
            fd, opened = _open_regular_readonly(db_file)
        except StoreSafetyError as exc:
            if exc.code != "source-missing":
                file_record["exists"] = True
                file_record["error_code"] = exc.code
                file_record["error"] = str(exc)
        else:
            os.close(fd)
            file_record.update(
                {
                    "exists": True,
                    "readable": True,
                    "size": opened.st_size,
                    "identity": _identity(opened),
                    "access_policy": _access_policy(opened),
                }
            )
        file_records.append(file_record)
    return {"paths": entries, "note_store_files": file_records}


def _wal_checksum(
    payload: bytes,
    byte_order: str,
    seed: tuple[int, int] = (0, 0),
) -> tuple[int, int]:
    if len(payload) % 8:
        raise StoreSafetyError(
            "wal-invalid", "WAL checksum input is not 8-byte aligned"
        )
    values = struct.unpack(f"{byte_order}{len(payload) // 4}I", payload)
    checksum0, checksum1 = seed
    for index in range(0, len(values), 2):
        checksum0 = (checksum0 + values[index] + checksum1) & 0xFFFFFFFF
        checksum1 = (checksum1 + values[index + 1] + checksum0) & 0xFFFFFFFF
    return checksum0, checksum1


def _inspect_wal(wal_path: Path) -> dict[str, Any]:
    size = wal_path.stat().st_size
    if size == 0:
        return {
            "present": True,
            "status": "empty",
            "size": 0,
            "frame_count": 0,
            "commit_frame_count": 0,
        }
    with wal_path.open("rb") as handle:
        header = handle.read(32)
        if len(header) != 32:
            raise StoreSafetyError(
                "wal-invalid", f"WAL header is truncated: {wal_path}"
            )
        magic, version, raw_page_size, _, salt1, salt2, stored0, stored1 = (
            struct.unpack(">8I", header)
        )
        if magic not in WAL_MAGIC_NUMBERS:
            raise StoreSafetyError("wal-invalid", f"WAL magic is invalid: {wal_path}")
        if version != WAL_VERSION:
            raise StoreSafetyError(
                "wal-version-unsupported",
                f"Unsupported WAL version {version}: {wal_path}",
            )
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
            raise StoreSafetyError(
                "wal-invalid", f"WAL page size is invalid: {wal_path}"
            )
        checksum_byte_order = ">" if magic == 0x377F0683 else "<"
        checksum = _wal_checksum(header[:24], checksum_byte_order)
        if checksum != (stored0, stored1):
            raise StoreSafetyError(
                "wal-invalid", f"WAL header checksum is invalid: {wal_path}"
            )
        frame_size = 24 + page_size
        frame_bytes = size - 32
        physical_frame_count, trailing_bytes = divmod(frame_bytes, frame_size)
        valid_frame_count = 0
        commit_frame_count = 0
        last_valid_commit_frame = 0
        first_invalid_frame: int | None = None
        for index in range(physical_frame_count):
            handle.seek(32 + index * frame_size)
            frame_header = handle.read(24)
            page = handle.read(page_size)
            page_number, database_pages, frame_salt1, frame_salt2, _, _ = struct.unpack(
                ">6I", frame_header
            )
            if page_number == 0 or (frame_salt1, frame_salt2) != (salt1, salt2):
                first_invalid_frame = index + 1
                break
            expected_checksum = struct.unpack(">2I", frame_header[16:24])
            checksum = _wal_checksum(
                frame_header[:8] + page,
                checksum_byte_order,
                checksum,
            )
            if checksum != expected_checksum:
                first_invalid_frame = index + 1
                break
            valid_frame_count = index + 1
            if database_pages:
                commit_frame_count += 1
                last_valid_commit_frame = index + 1
    return {
        "present": True,
        "status": (
            "valid"
            if first_invalid_frame is None and trailing_bytes == 0
            else "valid-prefix-with-ignored-tail"
        ),
        "size": size,
        "page_size": page_size,
        "physical_frame_count": physical_frame_count,
        "valid_frame_count": valid_frame_count,
        "commit_frame_count": commit_frame_count,
        "last_valid_commit_frame": last_valid_commit_frame,
        "first_invalid_frame": first_invalid_frame,
        "trailing_bytes": trailing_bytes,
        "salt": [salt1, salt2],
    }


def _parse_shm_header_copy(payload: bytes, offset: int) -> dict[str, Any] | None:
    if len(payload) < offset + 48:
        return None
    for byte_order in ("<", ">"):
        version = struct.unpack_from(f"{byte_order}I", payload, offset)[0]
        if version != WAL_VERSION:
            continue
        initialized = payload[offset + 12]
        raw_page_size = struct.unpack_from(f"{byte_order}H", payload, offset + 14)[0]
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        max_frame = struct.unpack_from(f"{byte_order}I", payload, offset + 16)[0]
        # WAL-index integers use native byte order, but aSalt is copied byte-for-byte
        # from the big-endian WAL header.
        salt = list(struct.unpack_from(">2I", payload, offset + 32))
        return {
            "byte_order": "little" if byte_order == "<" else "big",
            "initialized": bool(initialized),
            "page_size": page_size,
            "max_frame": max_frame,
            "salt": salt,
        }
    return None


def _inspect_sidecars(main_path: Path) -> dict[str, Any]:
    wal_path = main_path.with_name(f"{main_path.name}-wal")
    shm_path = main_path.with_name(f"{main_path.name}-shm")
    wal: dict[str, Any]
    if wal_path.exists():
        wal = _inspect_wal(wal_path)
    else:
        wal = {"present": False, "status": "absent"}

    shm: dict[str, Any] = {"present": False, "status": "absent"}
    if shm_path.exists():
        with shm_path.open("rb") as handle:
            header = handle.read(96)
        copies = [
            parsed
            for parsed in (
                _parse_shm_header_copy(header, 0),
                _parse_shm_header_copy(header, 48),
            )
            if parsed is not None
        ]
        same_generation = [
            parsed
            for parsed in copies
            if wal.get("status") not in {"absent", "empty"}
            and parsed["initialized"]
            and parsed["salt"] == wal["salt"]
            and parsed["page_size"] == wal["page_size"]
        ]
        matching_copies = sum(
            1
            for parsed in same_generation
            if parsed["max_frame"] == wal["last_valid_commit_frame"]
        )
        if any(
            parsed["max_frame"] > wal["last_valid_commit_frame"]
            for parsed in same_generation
        ):
            raise StoreSafetyError(
                "wal-shm-commit-mismatch",
                "SHM advertises a committed WAL frame whose checksum is invalid",
            )
        shm = {
            "present": True,
            "status": "derived-match"
            if matching_copies
            else "derived-rebuild-required",
            "size": shm_path.stat().st_size,
            "valid_header_copies": len(copies),
            "same_generation_header_copies": len(same_generation),
            "matching_wal_header_copies": matching_copies,
        }

    ignored = [shm_path.name] if shm_path.exists() else []
    authoritative = [main_path.name]
    if wal_path.exists() and wal.get("last_valid_commit_frame", 0) > 0:
        authoritative.append(wal_path.name)
    return {
        "wal": wal,
        "shm": shm,
        "recovery": {
            "authoritative_files": authoritative,
            "ignored_derived_files": ignored,
            "strategy": "copy main and valid WAL, omit SHM, let SQLite rebuild WAL-index state",
        },
    }


def _sqlite_integrity(db_path: Path) -> dict[str, Any]:
    try:
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute("PRAGMA busy_timeout = 5000")
            rows = [
                str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()
            ]
            journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    except sqlite3.Error as exc:
        raise StoreSafetyError(
            "sqlite-integrity-failed",
            f"SQLite could not validate {db_path}: {exc}",
        ) from exc
    if rows != ["ok"]:
        raise StoreSafetyError(
            "sqlite-integrity-failed",
            f"SQLite integrity_check failed for {db_path}: {rows[:5]}",
        )
    return {
        "result": "ok",
        "check": "PRAGMA integrity_check",
        "journal_mode": journal_mode,
        "page_count": page_count,
    }


def _make_recovery_clone(
    src_main: Path, destination: Path
) -> tuple[Path, dict[str, Any]]:
    records = _capture_database_files(src_main, destination)
    copied_main = destination / src_main.name
    sidecars = _inspect_sidecars(copied_main)
    copied_shm = copied_main.with_name(f"{copied_main.name}-shm")
    if copied_shm.exists():
        copied_shm.unlink()
    return copied_main, {"capture": records, "sidecars": sidecars}


def validate_database_recovery(src_main: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apple-notes-recovery-") as temp_dir:
        recovered_main, evidence = _make_recovery_clone(
            src_main, Path(temp_dir) / "store"
        )
        evidence["sqlite_integrity"] = _sqlite_integrity(recovered_main)
        return evidence


def _fingerprint_file(path: Path) -> dict[str, Any]:
    records = _capture_database_files(path)
    if len(records) != 1:
        raise StoreSafetyError(
            "unexpected-sidecars",
            f"Expected a standalone SQLite file but found sidecars beside {path}",
        )
    return records[0]["source"]


def _recover_to_standalone(src: Path, out: Path) -> dict[str, Any]:
    if any(
        _lexists(candidate)
        for candidate in (
            out,
            out.with_name(f"{out.name}-wal"),
            out.with_name(f"{out.name}-shm"),
            out.with_name(f"{out.name}-journal"),
        )
    ):
        raise StoreSafetyError(
            "destination-exists", f"Recovery destination already exists: {out}"
        )
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp_out = out.parent / f".{out.name}.tmp-{uuid.uuid4().hex}"
    try:
        with tempfile.TemporaryDirectory(prefix="apple-notes-merge-") as temp_dir:
            recovered_main, recovery_evidence = _make_recovery_clone(
                src, Path(temp_dir) / "store"
            )
            source_integrity = _sqlite_integrity(recovered_main)
            try:
                with (
                    closing(sqlite3.connect(recovered_main)) as source_conn,
                    closing(sqlite3.connect(temp_out)) as output_conn,
                ):
                    source_conn.backup(output_conn)
                    output_conn.execute("PRAGMA journal_mode = DELETE")
                    output_conn.commit()
            except sqlite3.Error as exc:
                raise StoreSafetyError(
                    "sqlite-recovery-failed",
                    f"SQLite backup could not create a standalone database: {exc}",
                ) from exc
        os.chmod(temp_out, 0o600)
        output_integrity = _sqlite_integrity(temp_out)
        with temp_out.open("rb") as handle:
            os.fsync(handle.fileno())
        try:
            os.link(temp_out, out, follow_symlinks=False)
        except FileExistsError as exc:
            raise StoreSafetyError(
                "destination-exists",
                f"Recovery destination appeared before installation: {out}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                "destination-install-failed",
                f"Cannot install recovered database at {out}: {exc}",
            ) from exc
        temp_out.unlink()
        _fsync_directory(out.parent)
        fingerprint = _fingerprint_file(out)
        return {
            "source_db": src,
            "standalone_db": out,
            "source_recovery": recovery_evidence,
            "source_integrity": source_integrity,
            "output_integrity": output_integrity,
            "sha256": fingerprint["sha256"],
            "size": fingerprint["size"],
        }
    finally:
        if temp_out.exists():
            temp_out.unlink()
        for suffix in ("-wal", "-shm", "-journal"):
            temp_sidecar = temp_out.with_name(f"{temp_out.name}{suffix}")
            if temp_sidecar.exists():
                temp_sidecar.unlink()


def copy_db(
    paths: NoteStorePaths,
    *,
    dest: Path | None,
    require_notes_quit: bool,
) -> dict[str, Any]:
    notes_running = notes_is_running()
    if require_notes_quit and notes_running:
        raise StoreSafetyError(
            "notes-running",
            "Notes.app is running; quit it before using --require-notes-quit",
        )

    destination = dest or _timestamped_tmp_dir("apple-notes-probe")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _lexists(destination):
        raise StoreSafetyError(
            "destination-exists", f"Destination already exists: {destination}"
        )
    partial = destination.parent / f".{destination.name}.partial-{uuid.uuid4().hex}"
    partial.mkdir(mode=0o700)
    retain_partial = False
    try:
        store_dir = partial / "group.com.apple.notes"
        captured = _capture_database_files(
            paths.group_container / NOTE_STORE_MAIN,
            store_dir,
        )
        copied_main = store_dir / NOTE_STORE_MAIN
        sidecars = _inspect_sidecars(copied_main)
        sqlite_validation = validate_database_recovery(copied_main)
        manifest_files = []
        for record in captured:
            source = record["source"]
            copied = record["copy"]
            manifest_files.append(
                {
                    "basename": record["basename"],
                    "relative_path": str(
                        Path("group.com.apple.notes") / record["basename"]
                    ),
                    "sha256": copied["sha256"],
                    "size": copied["size"],
                    "source": source,
                    "copy": {
                        "identity": copied["identity"],
                        "access_policy": copied["access_policy"],
                    },
                }
            )
        manifest = {
            "schema": SNAPSHOT_SCHEMA,
            "created_at": _utc_now(),
            "source_root": str(paths.group_container),
            "notes_running": notes_running,
            "notes_quit_required": require_notes_quit,
            "classification": (
                "tentative-open-notes"
                if notes_running
                else "writeback-baseline"
                if require_notes_quit
                else "read-only-snapshot"
            ),
            "protected_properties": {
                "object_identity": ["device", "inode", "file_type"],
                "content_stability": ["sha256", "size"],
                "access_policy": ["mode", "uid", "gid", "flags"],
                "metadata_only_transitions_are_reported": [
                    "mtime_ns",
                    "ctime_ns",
                    "link_count",
                ],
            },
            "files": manifest_files,
            "sidecar_consistency": sidecars,
            "sqlite_validation": sqlite_validation["sqlite_integrity"],
        }
        if require_notes_quit and notes_is_running():
            raise StoreSafetyError(
                "notes-started-during-capture",
                "Notes.app started before the writeback-grade snapshot was finalized",
            )
        _write_json_atomic(partial / SNAPSHOT_MANIFEST, manifest)
        _publish_directory_no_replace(partial, destination)
    except StoreSafetyError as exc:
        if exc.code == "destination-install-uncertain":
            retain_partial = True
        raise
    finally:
        if not retain_partial and partial.exists():
            shutil.rmtree(partial)

    return {
        "dest": destination,
        "manifest": destination / SNAPSHOT_MANIFEST,
        "notes_running": notes_running,
        "notes_quit_required": require_notes_quit,
        "classification": manifest["classification"],
        "copied_files": [
            {
                "source": row["source"]["path"],
                "dest": destination / row["relative_path"],
                "size": row["size"],
                "sha256": row["sha256"],
            }
            for row in manifest["files"]
        ],
        "sidecar_consistency": manifest["sidecar_consistency"],
        "sqlite_validation": manifest["sqlite_validation"],
    }


def validate_snapshot(snapshot_dir: Path) -> dict[str, Any]:
    manifest = _load_manifest(snapshot_dir / SNAPSHOT_MANIFEST, SNAPSHOT_SCHEMA)
    rows = manifest.get("files")
    if (
        not isinstance(rows, list)
        or not rows
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise StoreSafetyError("manifest-invalid", "Snapshot manifest has no files")
    manifest_names = [row.get("basename") for row in rows]
    expected_names = set(manifest_names)
    if (
        len(expected_names) != len(manifest_names)
        or NOTE_STORE_MAIN not in expected_names
        or not expected_names.issubset(NOTE_STORE_BASENAMES)
    ):
        raise StoreSafetyError(
            "manifest-invalid",
            "Snapshot manifest has duplicate or unsupported database file entries",
        )
    store_dir = snapshot_dir / "group.com.apple.notes"
    expected_store_types = {name: stat.S_IFREG for name in expected_names}
    store_directory = _scan_exact_directory_entries(
        store_dir,
        expected_store_types,
        missing_code="snapshot-missing",
        mismatch_code="snapshot-file-set-mismatch",
    )
    copied_main = store_dir / NOTE_STORE_MAIN
    manifest_by_name = {row.get("basename"): row for row in rows}
    for basename, row in manifest_by_name.items():
        expected_relative = Path("group.com.apple.notes") / str(basename)
        if (
            basename not in NOTE_STORE_BASENAMES
            or Path(str(row.get("relative_path"))) != expected_relative
        ):
            raise StoreSafetyError(
                "manifest-invalid",
                f"Manifest path is not canonical for {basename}: {row.get('relative_path')}",
            )
    with tempfile.TemporaryDirectory(
        prefix="apple-notes-snapshot-validation-"
    ) as temp_dir:
        recovered_main, recovery = _make_recovery_clone(
            copied_main,
            Path(temp_dir) / "store",
        )
        verified = [record["source"] for record in recovery["capture"]]
        for record in recovery["capture"]:
            basename = record["basename"]
            row = manifest_by_name.get(basename)
            source = record["source"]
            if (
                row is None
                or source["sha256"] != row.get("sha256")
                or source["size"] != row.get("size")
            ):
                raise StoreSafetyError(
                    "snapshot-content-mismatch",
                    f"Snapshot bytes no longer match the manifest: {basename}",
                )
        sqlite_integrity = _sqlite_integrity(recovered_main)
    _scan_exact_directory_entries(
        store_dir,
        expected_store_types,
        missing_code="snapshot-missing",
        mismatch_code="snapshot-file-set-mismatch",
        bound_identity=store_directory["identity"],
        bound_access_policy=store_directory["access_policy"],
    )
    return {
        "snapshot_dir": snapshot_dir,
        "manifest": manifest,
        "verified_files": verified,
        "sidecar_consistency": recovery["sidecars"],
        "sqlite_validation": sqlite_integrity,
    }


def merge_db(src: Path, out: Path | None) -> dict[str, Any]:
    output = out or src.with_name("NoteStore-merged-for-analysis.sqlite")
    return _recover_to_standalone(src, output)


def recover_snapshot(snapshot_dir: Path, out: Path) -> dict[str, Any]:
    validation = validate_snapshot(snapshot_dir)
    source = snapshot_dir / "group.com.apple.notes" / NOTE_STORE_MAIN
    recovered = _recover_to_standalone(source, out)
    return {
        "snapshot_dir": snapshot_dir,
        "snapshot_validation": {
            "sqlite_validation": validation["sqlite_validation"],
            "sidecar_consistency": validation["sidecar_consistency"],
        },
        "recovered": recovered,
    }


def stage_patch(src: Path, dest: Path) -> dict[str, Any]:
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _lexists(dest):
        raise StoreSafetyError(
            "destination-exists", f"Patch stage already exists: {dest}"
        )
    partial = dest.parent / f".{dest.name}.partial-{uuid.uuid4().hex}"
    partial.mkdir(mode=0o700)
    retain_partial = False
    try:
        staged_db = partial / NOTE_STORE_MAIN
        recovery = _recover_to_standalone(src, staged_db)
        fingerprint = _fingerprint_file(staged_db)
        manifest = {
            "schema": PATCH_SCHEMA,
            "created_at": _utc_now(),
            "source_db": str(src),
            "database": {
                "basename": NOTE_STORE_MAIN,
                "relative_path": NOTE_STORE_MAIN,
                "sha256": fingerprint["sha256"],
                "size": fingerprint["size"],
            },
            "sqlite_validation": recovery["output_integrity"],
            "sidecar_policy": {
                "allowed": False,
                "reason": "A patch stage must be a standalone SQLite database",
            },
        }
        _write_json_atomic(partial / PATCH_MANIFEST, manifest)
        _publish_directory_no_replace(partial, dest)
    except StoreSafetyError as exc:
        if exc.code == "destination-install-uncertain":
            retain_partial = True
        raise
    finally:
        if not retain_partial and partial.exists():
            shutil.rmtree(partial)
    return {
        "stage_dir": dest,
        "manifest": dest / PATCH_MANIFEST,
        "database": dest / NOTE_STORE_MAIN,
        "sha256": manifest["database"]["sha256"],
        "size": manifest["database"]["size"],
        "sqlite_validation": manifest["sqlite_validation"],
        "live_mutation_performed": False,
    }


def validate_patch_stage(stage_dir: Path) -> dict[str, Any]:
    expected_stage_types = {
        NOTE_STORE_MAIN: stat.S_IFREG,
        PATCH_MANIFEST: stat.S_IFREG,
    }
    stage_directory = _scan_exact_directory_entries(
        stage_dir,
        expected_stage_types,
        missing_code="stage-missing",
        mismatch_code="patch-file-set-mismatch",
    )
    manifest = _load_manifest(stage_dir / PATCH_MANIFEST, PATCH_SCHEMA)
    database = manifest.get("database")
    if not isinstance(database, dict):
        raise StoreSafetyError(
            "manifest-invalid", "Patch manifest has no database entry"
        )
    if (
        database.get("basename") != NOTE_STORE_MAIN
        or database.get("relative_path") != NOTE_STORE_MAIN
    ):
        raise StoreSafetyError(
            "manifest-invalid",
            "Patch manifest database path is not canonical",
        )
    with tempfile.TemporaryDirectory(
        prefix="apple-notes-stage-validation-"
    ) as temp_dir:
        recovered_main, recovery = _make_recovery_clone(
            stage_dir / NOTE_STORE_MAIN,
            Path(temp_dir) / "store",
        )
        fingerprint = recovery["capture"][0]["source"]
        if fingerprint["sha256"] != database.get("sha256") or fingerprint[
            "size"
        ] != database.get("size"):
            raise StoreSafetyError(
                "patch-content-mismatch",
                "Patch database no longer matches its manifest",
            )
        integrity = _sqlite_integrity(recovered_main)
    _scan_exact_directory_entries(
        stage_dir,
        expected_stage_types,
        missing_code="stage-missing",
        mismatch_code="patch-file-set-mismatch",
        bound_identity=stage_directory["identity"],
        bound_access_policy=stage_directory["access_policy"],
    )
    return {
        "stage_dir": stage_dir,
        "manifest": manifest,
        "fingerprint": fingerprint,
        "sqlite_validation": integrity,
    }


def fingerprint_note_store(paths: NoteStorePaths) -> dict[str, Any]:
    records = _capture_database_files(paths.group_container / NOTE_STORE_MAIN)
    return {
        "source_root": paths.group_container,
        "files": [
            {
                "basename": record["basename"],
                **record["source"],
            }
            for record in records
        ],
        "protected_properties": {
            "object_identity": ["device", "inode", "file_type"],
            "content_stability": ["sha256", "size"],
            "access_policy": ["mode", "uid", "gid", "flags"],
        },
    }


def _source_manifest_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("files")
    if not isinstance(rows, list) or any(
        not isinstance(row, dict)
        or not isinstance(row.get("basename"), str)
        or not isinstance(row.get("source"), dict)
        for row in rows
    ):
        raise StoreSafetyError(
            "manifest-invalid", "Snapshot manifest file list is invalid"
        )
    result = {str(row["basename"]): row["source"] for row in rows}
    if len(result) != len(rows) or NOTE_STORE_MAIN not in result:
        raise StoreSafetyError(
            "manifest-invalid",
            "Snapshot manifest has duplicate or missing database file entries",
        )
    required_source_fields = {"sha256", "size", "identity", "access_policy"}
    if any(
        not required_source_fields.issubset(source)
        or not isinstance(source["identity"], dict)
        or not isinstance(source["access_policy"], dict)
        for source in result.values()
    ):
        raise StoreSafetyError(
            "manifest-invalid",
            "Snapshot manifest source evidence is incomplete",
        )
    return result


def _fingerprint_map(fingerprint: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(row["basename"]): row for row in fingerprint["files"]}


def _compare_live_to_baseline(
    fingerprint: dict[str, Any],
    baseline_manifest: dict[str, Any],
) -> None:
    current = _fingerprint_map(fingerprint)
    baseline = _source_manifest_map(baseline_manifest)
    if set(current) != set(baseline):
        raise StoreSafetyError(
            "baseline-file-set-mismatch",
            "Live SQLite/WAL/SHM membership differs from the backup baseline",
        )
    for basename in sorted(current):
        current_row = current[basename]
        baseline_row = baseline[basename]
        if current_row["identity"] != baseline_row["identity"]:
            raise StoreSafetyError(
                "baseline-identity-mismatch",
                f"Live object identity changed since backup: {basename}",
            )
        if (
            current_row["sha256"] != baseline_row["sha256"]
            or current_row["size"] != baseline_row["size"]
        ):
            raise StoreSafetyError(
                "baseline-content-mismatch",
                f"Live bytes changed since backup: {basename}",
            )
        if current_row["access_policy"] != baseline_row["access_policy"]:
            raise StoreSafetyError(
                "baseline-access-policy-mismatch",
                f"Live access policy changed since backup: {basename}",
            )


def preflight_writeback(
    paths: NoteStorePaths,
    *,
    backup_dir: Path,
    stage_dir: Path,
) -> dict[str, Any]:
    if notes_is_running():
        raise StoreSafetyError(
            "notes-running", "Notes.app must stay quit for writeback preflight"
        )
    backup = validate_snapshot(backup_dir)
    manifest = backup["manifest"]
    if (
        manifest.get("notes_running") is not False
        or manifest.get("notes_quit_required") is not True
    ):
        raise StoreSafetyError(
            "backup-not-writeback-grade",
            "Backup was not captured with Notes quit and --require-notes-quit",
        )
    if Path(str(manifest.get("source_root"))) != paths.group_container:
        raise StoreSafetyError(
            "backup-source-mismatch",
            "Backup source root does not match the selected live store",
        )
    stage = validate_patch_stage(stage_dir)
    live = fingerprint_note_store(paths)
    _compare_live_to_baseline(live, manifest)
    if notes_is_running():
        raise StoreSafetyError(
            "notes-started-during-preflight",
            "Notes.app started during writeback preflight",
        )
    current_names = sorted(_fingerprint_map(live))
    return {
        "ready_for_explicit_writeback": True,
        "live_mutation_performed": False,
        "backup_dir": backup_dir,
        "stage_dir": stage_dir,
        "live_source_root": paths.group_container,
        "live_files": current_names,
        "stage_sha256": stage["fingerprint"]["sha256"],
        "required_whole_store_boundary": {
            "install": [NOTE_STORE_MAIN],
            "remove_or_restore_as_one_boundary": [
                name for name in current_names if name != NOTE_STORE_MAIN
            ],
            "multi_file_atomic_swap_available": False,
            "notes_must_remain_quit": True,
            "retain_backup_until_user_acceptance": True,
        },
    }


def verify_writeback(
    paths: NoteStorePaths,
    *,
    backup_dir: Path,
    stage_dir: Path,
) -> dict[str, Any]:
    if notes_is_running():
        raise StoreSafetyError(
            "notes-running", "Notes.app must stay quit for writeback verification"
        )
    backup = validate_snapshot(backup_dir)
    baseline_manifest = backup["manifest"]
    if (
        baseline_manifest.get("notes_running") is not False
        or baseline_manifest.get("notes_quit_required") is not True
    ):
        raise StoreSafetyError(
            "backup-not-writeback-grade",
            "Backup was not captured with Notes quit and --require-notes-quit",
        )
    if Path(str(baseline_manifest.get("source_root"))) != paths.group_container:
        raise StoreSafetyError(
            "backup-source-mismatch",
            "Backup source root does not match the selected live store",
        )
    stage = validate_patch_stage(stage_dir)
    live = validate_database_recovery(paths.group_container / NOTE_STORE_MAIN)
    current = {record["basename"]: record["source"] for record in live["capture"]}
    if set(current) != {NOTE_STORE_MAIN}:
        raise StoreSafetyError(
            "post-writeback-file-set-mismatch",
            "Post-writeback live store contains missing or stale WAL/SHM files",
        )
    baseline_main = _source_manifest_map(baseline_manifest)[NOTE_STORE_MAIN]
    if current[NOTE_STORE_MAIN]["identity"] == baseline_main["identity"]:
        raise StoreSafetyError(
            "post-writeback-identity-mismatch",
            "Live NoteStore.sqlite was not replaced as a whole object",
        )
    staged_fingerprint = stage["fingerprint"]
    if (
        current[NOTE_STORE_MAIN]["sha256"] != staged_fingerprint["sha256"]
        or current[NOTE_STORE_MAIN]["size"] != staged_fingerprint["size"]
    ):
        raise StoreSafetyError(
            "post-writeback-content-mismatch",
            "Live NoteStore.sqlite does not match the staged patch",
        )
    if current[NOTE_STORE_MAIN]["access_policy"] != baseline_main["access_policy"]:
        raise StoreSafetyError(
            "post-writeback-access-policy-mismatch",
            "Live NoteStore.sqlite did not preserve the baseline access policy",
        )
    if notes_is_running():
        raise StoreSafetyError(
            "notes-started-during-verification",
            "Notes.app started during writeback verification",
        )
    return {
        "writeback_verified": True,
        "notes_running": False,
        "live_source_root": paths.group_container,
        "backup_dir": backup_dir,
        "stage_dir": stage_dir,
        "sha256": staged_fingerprint["sha256"],
        "sqlite_validation": live["sqlite_integrity"],
        "sidecars_absent": True,
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


def _paths_from_args(args: argparse.Namespace) -> NoteStorePaths:
    return NoteStorePaths(
        group_container=args.group_container,
        app_container=args.app_container,
    )


def _add_container_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--group-container",
        type=Path,
        default=GROUP_CONTAINER,
        help="Apple Notes group-container root.",
    )
    parser.add_argument(
        "--app-container",
        type=Path,
        default=APP_CONTAINER,
        help="Apple Notes app-container root.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe_parser = subparsers.add_parser(
        "probe-db-access",
        help="Probe NoteStore access without copying.",
    )
    _add_container_options(probe_parser)

    copy_parser = subparsers.add_parser(
        "copy-db", help="Copy and validate NoteStore files."
    )
    _add_container_options(copy_parser)
    copy_parser.add_argument("--dest", type=Path, help="New snapshot directory.")
    copy_parser.add_argument(
        "--require-notes-quit",
        action="store_true",
        help="Fail unless Notes.app is quit; required for a writeback-grade baseline.",
    )

    merge_parser = subparsers.add_parser(
        "merge-db",
        help="Recover a copied store into a standalone analysis DB.",
    )
    merge_parser.add_argument(
        "--src", type=Path, required=True, help="Copied NoteStore.sqlite."
    )
    merge_parser.add_argument("--out", type=Path, help="New standalone output DB.")

    validate_parser = subparsers.add_parser(
        "validate-snapshot",
        help="Revalidate a snapshot manifest, sidecars, and SQLite integrity.",
    )
    validate_parser.add_argument("--snapshot-dir", type=Path, required=True)

    recover_parser = subparsers.add_parser(
        "recover-snapshot",
        help="Recover a validated snapshot to a standalone SQLite DB.",
    )
    recover_parser.add_argument("--snapshot-dir", type=Path, required=True)
    recover_parser.add_argument("--out", type=Path, required=True)

    stage_parser = subparsers.add_parser(
        "stage-patch",
        help="Normalize an edited DB into a validated, sidecar-free patch stage.",
    )
    stage_parser.add_argument("--src", type=Path, required=True)
    stage_parser.add_argument("--dest", type=Path, required=True)

    preflight_parser = subparsers.add_parser(
        "preflight-writeback",
        help="Read-only gate for an explicit whole-store writeback.",
    )
    _add_container_options(preflight_parser)
    preflight_parser.add_argument("--backup-dir", type=Path, required=True)
    preflight_parser.add_argument("--stage-dir", type=Path, required=True)

    verify_parser = subparsers.add_parser(
        "verify-writeback",
        help="Verify live bytes, sidecar absence, and integrity after writeback.",
    )
    _add_container_options(verify_parser)
    verify_parser.add_argument("--backup-dir", type=Path, required=True)
    verify_parser.add_argument("--stage-dir", type=Path, required=True)

    tags_parser = subparsers.add_parser(
        "note-tags",
        help="Read hashtag rows for a note title from a DB copy.",
    )
    tags_parser.add_argument("--db", type=Path, required=True)
    tags_parser.add_argument("--title", required=True)

    fingerprint_parser = subparsers.add_parser(
        "fingerprint-db",
        help="Stably fingerprint live NoteStore sqlite/wal/shm files.",
    )
    _add_container_options(fingerprint_parser)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "probe-db-access":
            emit_json(probe_db_access(_paths_from_args(args)))
        elif args.command == "copy-db":
            emit_json(
                copy_db(
                    _paths_from_args(args),
                    dest=args.dest,
                    require_notes_quit=args.require_notes_quit,
                )
            )
        elif args.command == "merge-db":
            emit_json(merge_db(args.src, args.out))
        elif args.command == "validate-snapshot":
            emit_json(validate_snapshot(args.snapshot_dir))
        elif args.command == "recover-snapshot":
            emit_json(recover_snapshot(args.snapshot_dir, args.out))
        elif args.command == "stage-patch":
            emit_json(stage_patch(args.src, args.dest))
        elif args.command == "preflight-writeback":
            emit_json(
                preflight_writeback(
                    _paths_from_args(args),
                    backup_dir=args.backup_dir,
                    stage_dir=args.stage_dir,
                )
            )
        elif args.command == "verify-writeback":
            emit_json(
                verify_writeback(
                    _paths_from_args(args),
                    backup_dir=args.backup_dir,
                    stage_dir=args.stage_dir,
                )
            )
        elif args.command == "note-tags":
            emit_json(query_note_tags(args.db, args.title))
        elif args.command == "fingerprint-db":
            emit_json(fingerprint_note_store(_paths_from_args(args)))
        else:
            parser.error(f"Unsupported command: {args.command}")
    except StoreSafetyError as exc:
        emit_json({"error": str(exc), "error_code": exc.code, "command": args.command})
        return 1
    except Exception as exc:  # noqa: BLE001
        emit_json(
            {
                "error": str(exc),
                "error_code": "unexpected-error",
                "command": args.command,
            }
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
