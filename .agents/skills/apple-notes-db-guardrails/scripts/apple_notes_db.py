#!/usr/bin/env python3
"""Audit, recover, stage, and verify Apple Notes SQLite stores safely."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import hashlib
import json
import os
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Union


GROUP_CONTAINER = Path.home() / "Library/Group Containers/group.com.apple.notes"
APP_CONTAINER = Path.home() / "Library/Containers/com.apple.Notes"
NOTE_STORE_MAIN = "NoteStore.sqlite"
NOTE_STORE_ROLLBACK_JOURNAL = f"{NOTE_STORE_MAIN}-journal"
NOTE_STORE_BASENAMES = (
    NOTE_STORE_MAIN,
    f"{NOTE_STORE_MAIN}-wal",
    f"{NOTE_STORE_MAIN}-shm",
)
NOTE_STORE_DISCOVERY_BASENAMES = (
    *NOTE_STORE_BASENAMES,
    NOTE_STORE_ROLLBACK_JOURNAL,
)
SNAPSHOT_MANIFEST = "snapshot-manifest.json"
PATCH_MANIFEST = "patch-manifest.json"
SNAPSHOT_SCHEMA = "apple-notes-snapshot/v1"
PATCH_SCHEMA = "apple-notes-patch/v1"
CHUNK_SIZE = 1024 * 1024
MANIFEST_MAX_BYTES = 4 * 1024 * 1024
WAL_MAGIC_NUMBERS = {0x377F0682, 0x377F0683}
WAL_VERSION = 3007000
RENAME_NOREPLACE = 1
RENAME_EXCL = 0x00000004


class StoreSafetyError(RuntimeError):
    """A classified safety failure that must not be treated as absence."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclass(frozen=True)
class NoteStorePaths:
    group_container: Path = GROUP_CONTAINER
    app_container: Path = APP_CONTAINER

    def note_store_files(self) -> list[Path]:
        return [
            self.group_container / name for name in NOTE_STORE_DISCOVERY_BASENAMES
        ]


@dataclass
class _OpenedSource:
    path: Path
    fd: int
    before: os.stat_result
    first_sha256: str | None = None
    copied: dict[str, Any] | None = None


@dataclass(frozen=True)
class _FileProtectionCodes:
    missing: str
    identity: str
    content: str
    access_policy: str
    inconclusive: str


@dataclass
class _BoundRegularFile:
    path: Path
    fd: int
    opened: os.stat_result
    sha256: str
    parent_opened: os.stat_result | None = None


@dataclass
class _BoundDirectory:
    path: Path
    fd: int
    opened: os.stat_result
    parent_opened: os.stat_result
    parent_fd: int | None = None


@dataclass
class _BoundRecoveryStore:
    directory: _BoundDirectory
    main_name: str
    files: dict[str, _BoundRegularFile]
    entry_types: dict[str, int]


@dataclass(frozen=True)
class _RecoveryStoreReceipt:
    directory_identity: dict[str, int]
    directory_access_policy: dict[str, int]
    entry_types: dict[str, int]
    files: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class _RecoveryClone:
    main_path: Path
    evidence: dict[str, Any]
    receipt: _RecoveryStoreReceipt


@dataclass(frozen=True)
class _ValidatedSnapshotArtifact:
    public_result: dict[str, Any]
    recovered_main: Path
    recovery_evidence: dict[str, Any]
    source_integrity: dict[str, Any]
    revalidate_recovery_clone: Callable[[], None]
    backup_recovery_clone: Callable[[Path], dict[str, Any]]


SNAPSHOT_FILE_CODES = _FileProtectionCodes(
    missing="snapshot-missing",
    identity="snapshot-file-identity-mismatch",
    content="snapshot-content-mismatch",
    access_policy="snapshot-file-access-policy-mismatch",
    inconclusive="snapshot-file-revalidation-inconclusive",
)
PATCH_FILE_CODES = _FileProtectionCodes(
    missing="stage-missing",
    identity="patch-file-identity-mismatch",
    content="patch-content-mismatch",
    access_policy="patch-file-access-policy-mismatch",
    inconclusive="patch-file-revalidation-inconclusive",
)
PREPARED_FILE_CODES = _FileProtectionCodes(
    missing="prepared-file-missing",
    identity="prepared-file-identity-mismatch",
    content="prepared-file-content-mismatch",
    access_policy="prepared-file-access-policy-mismatch",
    inconclusive="prepared-file-revalidation-inconclusive",
)


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


def _rename_directory_no_replace_at(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Atomically rename one directory within a bound parent."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
    if sys.platform == "darwin":
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is None:
            raise OSError(
                errno.ENOTSUP,
                "renameatx_np is unavailable; refusing a non-atomic publication",
            )
        renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            RENAME_EXCL,
        )
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
            parent_fd,
            source_bytes,
            parent_fd,
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
            source_name,
            destination_name,
        )


def _rename_file_no_replace_at(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Atomically rename one file within a bound parent without replacement."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
    if sys.platform == "darwin":
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is None:
            raise OSError(
                errno.ENOTSUP,
                "renameatx_np is unavailable; refusing a non-atomic publication",
            )
        renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            RENAME_EXCL,
        )
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
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            RENAME_NOREPLACE,
        )
    else:
        raise OSError(
            errno.ENOTSUP,
            f"Atomic no-replace file publication is unsupported on {sys.platform}",
        )

    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(
            error_number,
            os.strerror(error_number),
            source_name,
            destination_name,
        )


def _observe_path(path: Path) -> tuple[str, os.stat_result | None]:
    try:
        value = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unavailable", None
    return "present", value


def _observe_bound_name(
    parent_fd: int,
    basename: str,
) -> tuple[str, os.stat_result | None]:
    try:
        value = os.stat(
            basename,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unavailable", None
    return "present", value


def _publish_directory_no_replace(
    source: Path,
    destination: Path,
    *,
    binding: _BoundDirectory | None = None,
    before_rename: Callable[[], None] | None = None,
) -> None:
    if binding is None or binding.parent_fd is None:
        raise StoreSafetyError(
            "destination-install-failed",
            "Directory publication requires creation-time source and parent "
            f"descriptors: {source}",
        )
    if source.parent != destination.parent or source.parent != binding.path.parent:
        raise StoreSafetyError(
            "destination-install-failed",
            "Descriptor-relative directory publication requires one bound parent: "
            f"source={source}, destination={destination}",
        )
    parent_fd = binding.parent_fd
    _verify_bound_parent_descriptor(
        parent_fd,
        binding.parent_opened,
        display_path=source.parent,
        identity_code="prepared-directory-identity-mismatch",
        access_policy_code="prepared-directory-access-policy-mismatch",
        inconclusive_code="prepared-directory-revalidation-inconclusive",
    )
    _verify_bound_directory_at(
        binding,
        parent_fd=parent_fd,
        basename=source.name,
        display_path=source,
    )
    source_before = os.fstat(binding.fd)
    source_identity = _identity(source_before)
    source_access_policy = _access_policy(source_before)
    if before_rename is not None:
        before_rename()
    _verify_bound_parent_descriptor(
        parent_fd,
        binding.parent_opened,
        display_path=source.parent,
        identity_code="prepared-directory-identity-mismatch",
        access_policy_code="prepared-directory-access-policy-mismatch",
        inconclusive_code="prepared-directory-revalidation-inconclusive",
    )
    _verify_bound_directory_at(
        binding,
        parent_fd=parent_fd,
        basename=source.name,
        display_path=source,
    )

    try:
        _rename_directory_no_replace_at(
            parent_fd,
            source.name,
            destination.name,
        )
    except OSError as exc:
        source_state, source_after = _observe_bound_name(parent_fd, source.name)
        destination_state, destination_after = _observe_bound_name(
            parent_fd,
            destination.name,
        )
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

    try:
        source_state, _ = _observe_bound_name(parent_fd, source.name)
        destination_state, destination_after = _observe_bound_name(
            parent_fd,
            destination.name,
        )
        if (
            source_state != "absent"
            or destination_state != "present"
            or destination_after is None
            or _identity(destination_after) != source_identity
            or _access_policy(destination_after) != source_access_policy
        ):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                "The no-replace syscall returned success, but the bound namespace "
                f"does not identify the installed directory: {destination}",
            )
        _verify_bound_directory_at(
            binding,
            parent_fd=parent_fd,
            basename=destination.name,
            display_path=destination,
        )
        _fsync_bound_parent_descriptor(
            parent_fd,
            binding.parent_opened,
            display_path=destination.parent,
            identity_code="prepared-directory-identity-mismatch",
            access_policy_code="prepared-directory-access-policy-mismatch",
            inconclusive_code="prepared-directory-revalidation-inconclusive",
        )
        _verify_bound_directory_at(
            binding,
            parent_fd=parent_fd,
            basename=destination.name,
            display_path=destination,
        )
        terminal_source, _ = _observe_bound_name(parent_fd, source.name)
        if terminal_source != "absent":
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                "The private source name reappeared after publication: "
                f"{source}",
            )
    except (OSError, StoreSafetyError) as exc:
        raise StoreSafetyError(
            "destination-install-uncertain",
            "The directory was renamed into place, but descriptor-relative "
            f"durability or terminal validation is unconfirmed: {destination}: "
            f"{exc}",
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


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _translate_bound_open_error(
    path: Path,
    codes: _FileProtectionCodes,
    error: StoreSafetyError,
) -> StoreSafetyError:
    if error.code in {"source-missing", "source-missing-after-read"}:
        code = codes.missing
    elif error.code in {
        "source-identity-mismatch",
        "source-not-regular",
    }:
        code = codes.identity
    else:
        code = codes.inconclusive
    return StoreSafetyError(
        code,
        f"Cannot bind regular file for protected validation: {path}: {error}",
    )


def _verify_bound_regular_file_with_stat(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    *,
    target: Path,
    stat_target: Callable[[], os.stat_result],
) -> dict[str, Any]:
    def stat_descriptor() -> os.stat_result:
        try:
            return os.fstat(bound.fd)
        except OSError as exc:
            raise StoreSafetyError(
                codes.inconclusive,
                f"Cannot revalidate opened file descriptor for {target}: {exc}",
            ) from exc

    def stat_path() -> os.stat_result:
        try:
            return stat_target()
        except FileNotFoundError as exc:
            raise StoreSafetyError(
                codes.missing,
                f"Bound regular-file path is missing during revalidation: {target}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                codes.inconclusive,
                f"Cannot revalidate bound regular-file path {target}: {exc}",
            ) from exc

    def verify_properties(
        descriptor: os.stat_result,
        path_stat: os.stat_result,
    ) -> None:
        if (
            not stat.S_ISREG(descriptor.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or not _same_identity(bound.opened, descriptor)
            or not _same_identity(descriptor, path_stat)
        ):
            raise StoreSafetyError(
                codes.identity,
                f"Regular-file object identity changed during validation: {target}",
            )
        baseline_access = _access_policy(bound.opened)
        if (
            _access_policy(descriptor) != baseline_access
            or _access_policy(path_stat) != baseline_access
        ):
            raise StoreSafetyError(
                codes.access_policy,
                f"Regular-file access policy changed during validation: {target}",
            )

    descriptor_before = stat_descriptor()
    path_before = stat_path()
    verify_properties(descriptor_before, path_before)
    try:
        first_sha256 = _hash_fd(bound.fd)
    except OSError as exc:
        raise StoreSafetyError(
            codes.inconclusive,
            f"Cannot hash bound regular file during revalidation: {target}: {exc}",
        ) from exc
    descriptor_between = stat_descriptor()
    path_between = stat_path()
    verify_properties(descriptor_between, path_between)
    try:
        second_sha256 = _hash_fd(bound.fd)
    except OSError as exc:
        raise StoreSafetyError(
            codes.inconclusive,
            f"Cannot repeat bound regular-file hash during revalidation: "
            f"{target}: {exc}",
        ) from exc
    descriptor_after = stat_descriptor()
    path_after = stat_path()
    verify_properties(descriptor_after, path_after)
    if (
        first_sha256 != bound.sha256
        or second_sha256 != bound.sha256
        or descriptor_before.st_size != bound.opened.st_size
        or descriptor_between.st_size != bound.opened.st_size
        or descriptor_after.st_size != bound.opened.st_size
    ):
        raise StoreSafetyError(
            codes.content,
            f"Regular-file content changed during validation: {target}",
        )
    before_metadata = _metadata(bound.opened)
    after_metadata = _metadata(descriptor_after)
    return {
        "path": target,
        "sha256": bound.sha256,
        "size": descriptor_after.st_size,
        "identity": _identity(descriptor_after),
        "access_policy": _access_policy(descriptor_after),
        "metadata": after_metadata,
        "metadata_transitions": {
            key: {"before": before_metadata[key], "after": after_metadata[key]}
            for key in before_metadata
            if before_metadata[key] != after_metadata[key]
        },
    }


def _verify_bound_regular_file(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    target = path or bound.path
    return _verify_bound_regular_file_with_stat(
        bound,
        codes,
        target=target,
        stat_target=lambda: os.stat(target, follow_symlinks=False),
    )


def _verify_bound_regular_file_at(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    *,
    dir_fd: int,
    basename: str,
) -> dict[str, Any]:
    return _verify_bound_regular_file_with_stat(
        bound,
        codes,
        target=bound.path,
        stat_target=lambda: os.stat(
            basename,
            dir_fd=dir_fd,
            follow_symlinks=False,
        ),
    )


@contextmanager
def _bind_regular_file(
    path: Path,
    codes: _FileProtectionCodes,
) -> Iterator[_BoundRegularFile]:
    parent_fd: int | None = None
    try:
        parent_fd = os.open(path.parent, _directory_open_flags())
        parent_opened = os.fstat(parent_fd)
        parent_path_before = os.stat(path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or not stat.S_ISDIR(parent_path_before.st_mode)
            or not _same_identity(parent_opened, parent_path_before)
        ):
            raise StoreSafetyError(
                codes.identity,
                f"Regular-file parent changed while binding: {path.parent}",
            )
    except StoreSafetyError:
        if parent_fd is not None:
            os.close(parent_fd)
        raise
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise StoreSafetyError(
            codes.inconclusive,
            f"Cannot bind regular-file parent {path.parent}: {exc}",
        ) from exc
    try:
        fd, opened = _open_regular_readonly(path)
    except StoreSafetyError as exc:
        os.close(parent_fd)
        raise _translate_bound_open_error(path, codes, exc) from exc
    try:
        try:
            sha256 = _hash_fd(fd)
        except OSError as exc:
            raise StoreSafetyError(
                codes.inconclusive,
                f"Cannot hash regular file while binding it: {path}: {exc}",
            ) from exc
        bound = _BoundRegularFile(
            path=path,
            fd=fd,
            opened=opened,
            sha256=sha256,
            parent_opened=parent_opened,
        )
        _verify_bound_regular_file(bound, codes)
        parent_descriptor = os.fstat(parent_fd)
        parent_path_after = os.stat(path.parent, follow_symlinks=False)
        if not _same_identity(parent_opened, parent_descriptor) or not _same_identity(
            parent_descriptor, parent_path_after
        ):
            raise StoreSafetyError(
                codes.identity,
                f"Regular-file parent changed while binding: {path.parent}",
            )
        yield bound
    finally:
        os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _scan_bound_directory_entry_types(
    binding: _BoundDirectory,
) -> dict[str, int]:
    scans: list[dict[str, int]] = []
    for _ in range(2):
        child_fd: int | None = None
        try:
            child_fd = os.open(
                ".",
                _directory_open_flags(),
                dir_fd=binding.fd,
            )
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode) or not _same_identity(
                binding.opened, opened
            ):
                raise StoreSafetyError(
                    "prepared-directory-identity-mismatch",
                    "The descriptor-relative recovery directory no longer "
                    f"identifies its bound object: {binding.path}",
                )
            if _access_policy(opened) != _access_policy(binding.opened):
                raise StoreSafetyError(
                    "prepared-directory-access-policy-mismatch",
                    "The descriptor-relative recovery directory access policy "
                    f"changed: {binding.path}",
                )
            with os.scandir(child_fd) as entries:
                scan: dict[str, int] = {}
                for entry in entries:
                    name = os.fsdecode(entry.name)
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except FileNotFoundError as exc:
                        raise StoreSafetyError(
                            "prepared-file-set-mismatch",
                            "Recovery-directory membership changed during "
                            f"descriptor-relative scan: {binding.path}",
                        ) from exc
                    except OSError as exc:
                        raise StoreSafetyError(
                            "prepared-directory-revalidation-inconclusive",
                            "Cannot inspect a recovery-directory entry without "
                            f"following links: {binding.path / name}: {exc}",
                        ) from exc
                    scan[name] = stat.S_IFMT(entry_stat.st_mode)
            after = os.fstat(child_fd)
            if not _same_identity(binding.opened, after):
                raise StoreSafetyError(
                    "prepared-directory-identity-mismatch",
                    "Recovery-directory identity changed during descriptor-relative "
                    f"scan: {binding.path}",
                )
            if _access_policy(after) != _access_policy(binding.opened):
                raise StoreSafetyError(
                    "prepared-directory-access-policy-mismatch",
                    "Recovery-directory access policy changed during "
                    f"descriptor-relative scan: {binding.path}",
                )
            scans.append(scan)
        except StoreSafetyError:
            raise
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                "Cannot scan the bound recovery directory through its descriptor: "
                f"{binding.path}: {exc}",
            ) from exc
        finally:
            if child_fd is not None:
                os.close(child_fd)
    if scans[0] != scans[1]:
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Recovery-directory membership changed between descriptor-relative "
            f"scans: {binding.path}",
        )
    return scans[1]


@contextmanager
def _bind_regular_file_at(
    path: Path,
    parent: _BoundDirectory,
    codes: _FileProtectionCodes,
) -> Iterator[_BoundRegularFile]:
    try:
        path_before = os.stat(
            path.name,
            dir_fd=parent.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            codes.missing,
            f"Descriptor-relative regular-file path is missing: {path}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            codes.inconclusive,
            f"Cannot inspect descriptor-relative regular file {path}: {exc}",
        ) from exc
    if not stat.S_ISREG(path_before.st_mode):
        raise StoreSafetyError(
            codes.identity,
            f"Descriptor-relative source is not a regular file: {path}",
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path.name, flags, dir_fd=parent.fd)
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            codes.missing,
            f"Descriptor-relative regular file disappeared before open: {path}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            codes.inconclusive,
            f"Cannot safely open descriptor-relative regular file {path}: {exc}",
        ) from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(path_before, opened):
            raise StoreSafetyError(
                codes.identity,
                f"Descriptor-relative regular file was replaced while opening: {path}",
            )
        try:
            sha256 = _hash_fd(fd)
        except OSError as exc:
            raise StoreSafetyError(
                codes.inconclusive,
                f"Cannot hash descriptor-relative regular file {path}: {exc}",
            ) from exc
        bound = _BoundRegularFile(
            path=path,
            fd=fd,
            opened=opened,
            sha256=sha256,
            parent_opened=parent.opened,
        )
        _verify_bound_regular_file_at(
            bound,
            codes,
            dir_fd=parent.fd,
            basename=path.name,
        )
        yield bound
    finally:
        os.close(fd)


def _verify_bound_recovery_store(
    store: _BoundRecoveryStore,
) -> dict[str, Any]:
    directory = _verify_bound_directory(store.directory)
    files = {
        basename: _verify_bound_regular_file_at(
            bound,
            PREPARED_FILE_CODES,
            dir_fd=store.directory.fd,
            basename=basename,
        )
        for basename, bound in store.files.items()
    }
    entries = _scan_bound_directory_entry_types(store.directory)
    if entries != store.entry_types:
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Recovery-directory name/type membership changed while SQLite "
            f"consumed the bound store: {store.directory.path}",
        )
    return {
        "directory": directory,
        "files": files,
        "entry_types": entries,
    }


def _assert_recovery_store_matches_receipt(
    store: _BoundRecoveryStore,
    receipt: _RecoveryStoreReceipt,
) -> dict[str, Any]:
    current = _verify_bound_recovery_store(store)
    directory = current["directory"]
    if directory["identity"] != receipt.directory_identity:
        raise StoreSafetyError(
            "prepared-directory-identity-mismatch",
            "Recovery-directory identity differs from its creation receipt: "
            f"{store.directory.path}",
        )
    if directory["access_policy"] != receipt.directory_access_policy:
        raise StoreSafetyError(
            "prepared-directory-access-policy-mismatch",
            "Recovery-directory access policy differs from its creation receipt: "
            f"{store.directory.path}",
        )
    if current["entry_types"] != receipt.entry_types:
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Recovery-directory membership differs from its creation receipt: "
            f"{store.directory.path}",
        )
    if set(store.files) != set(receipt.files):
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Bound recovery files differ from the creation receipt: "
            f"{store.directory.path}",
        )
    for basename, file_receipt in receipt.files.items():
        _assert_bound_matches_receipt(
            store.files[basename],
            file_receipt,
            dir_fd=store.directory.fd,
            basename=basename,
        )
    return current


def _recovery_store_creation_receipt(
    directory: _BoundDirectory,
    main_name: str,
    file_receipts: dict[str, dict[str, Any]],
) -> _RecoveryStoreReceipt:
    expected_entries = {basename: stat.S_IFREG for basename in file_receipts}
    directory_receipt = _verify_bound_directory(directory)
    entries = _scan_bound_directory_entry_types(directory)
    if entries != expected_entries:
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Recovery clone membership differs from the exact copied file set: "
            f"{directory.path}",
        )
    receipt = _RecoveryStoreReceipt(
        directory_identity=dict(directory_receipt["identity"]),
        directory_access_policy=dict(directory_receipt["access_policy"]),
        entry_types=dict(expected_entries),
        files={
            basename: dict(file_receipt)
            for basename, file_receipt in file_receipts.items()
        },
    )
    if main_name not in file_receipts:
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Recovery clone creation receipt does not contain its main database: "
            f"{directory.path / main_name}",
        )
    with _bind_recovery_store(
        directory.path / main_name,
        creation_receipt=receipt,
    ) as store:
        _assert_recovery_store_matches_receipt(store, receipt)
    return receipt


def _require_authoritative_wal(
    store: _BoundRecoveryStore,
    recovery_evidence: dict[str, Any],
) -> None:
    authoritative = (
        recovery_evidence.get("sidecars", {})
        .get("recovery", {})
        .get("authoritative_files", [])
    )
    wal_name = f"{store.main_name}-wal"
    if wal_name in authoritative and wal_name not in store.files:
        raise StoreSafetyError(
            "prepared-file-missing",
            "The validated recovery evidence requires a committed WAL, but the "
            f"bound recovery store no longer contains it: "
            f"{store.directory.path / wal_name}",
        )


@contextmanager
def _bind_recovery_store(
    main_path: Path,
    *,
    creation_receipt: _RecoveryStoreReceipt | None = None,
) -> Iterator[_BoundRecoveryStore]:
    directory_path = main_path.parent
    parent_fd: int | None = None
    directory_fd: int | None = None
    try:
        parent_fd = os.open(directory_path.parent, _directory_open_flags())
        parent_opened = os.fstat(parent_fd)
        directory_before = os.stat(
            directory_path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        directory_fd = os.open(
            directory_path.name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        directory_opened = os.fstat(directory_fd)
        directory_after = os.stat(
            directory_path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or not stat.S_ISDIR(directory_opened.st_mode)
            or not _same_identity(directory_before, directory_opened)
            or not _same_identity(directory_opened, directory_after)
        ):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                f"Recovery directory was replaced while binding: {directory_path}",
            )
        if _access_policy(directory_before) != _access_policy(
            directory_opened
        ) or _access_policy(directory_opened) != _access_policy(directory_after):
            raise StoreSafetyError(
                "prepared-directory-access-policy-mismatch",
                "Recovery-directory access policy changed while binding: "
                f"{directory_path}",
            )
    except StoreSafetyError:
        if directory_fd is not None:
            os.close(directory_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise
    except FileNotFoundError as exc:
        if directory_fd is not None:
            os.close(directory_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise StoreSafetyError(
            "prepared-directory-missing",
            f"Recovery directory is missing: {directory_path}",
        ) from exc
    except OSError as exc:
        if directory_fd is not None:
            os.close(directory_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Cannot bind recovery directory {directory_path}: {exc}",
        ) from exc
    assert directory_fd is not None
    assert parent_fd is not None
    directory = _BoundDirectory(
        path=directory_path,
        fd=directory_fd,
        opened=directory_opened,
        parent_opened=parent_opened,
    )
    os.close(parent_fd)
    parent_fd = None
    try:
        initial_entries = _scan_bound_directory_entry_types(directory)
        if creation_receipt is not None:
            current_directory = _verify_bound_directory(directory)
            if current_directory["identity"] != creation_receipt.directory_identity:
                raise StoreSafetyError(
                    "prepared-directory-identity-mismatch",
                    "Recovery directory differs from its creation receipt: "
                    f"{directory_path}",
                )
            if (
                current_directory["access_policy"]
                != creation_receipt.directory_access_policy
            ):
                raise StoreSafetyError(
                    "prepared-directory-access-policy-mismatch",
                    "Recovery-directory access policy differs from its creation "
                    f"receipt: {directory_path}",
                )
            if initial_entries != creation_receipt.entry_types:
                raise StoreSafetyError(
                    "prepared-file-set-mismatch",
                    "Recovery-directory membership differs from its creation "
                    f"receipt: {directory_path}",
                )
        main_name = main_path.name
        wal_name = f"{main_name}-wal"
        if initial_entries.get(main_name) != stat.S_IFREG:
            code = (
                "prepared-file-missing"
                if main_name not in initial_entries
                else "prepared-file-identity-mismatch"
            )
            raise StoreSafetyError(
                code,
                f"Recovery main database is missing or not regular: {main_path}",
            )
        if wal_name in initial_entries and initial_entries[wal_name] != stat.S_IFREG:
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                "Recovery WAL is present but not a regular file: "
                f"{directory_path / wal_name}",
            )
        with ExitStack() as stack:
            basenames = (
                list(creation_receipt.files)
                if creation_receipt is not None
                else [
                    basename
                    for basename in (main_name, wal_name)
                    if basename in initial_entries
                ]
            )
            files: dict[str, _BoundRegularFile] = {}
            for basename in basenames:
                if initial_entries.get(basename) != stat.S_IFREG:
                    raise StoreSafetyError(
                        "prepared-file-identity-mismatch",
                        "Recovery receipt names a missing or non-regular file: "
                        f"{directory_path / basename}",
                    )
                files[basename] = stack.enter_context(
                    _bind_regular_file_at(
                        directory_path / basename,
                        directory,
                        PREPARED_FILE_CODES,
                    )
                )
            store = _BoundRecoveryStore(
                directory=directory,
                main_name=main_name,
                files=files,
                entry_types=initial_entries,
            )
            _verify_bound_recovery_store(store)
            if creation_receipt is not None:
                _assert_recovery_store_matches_receipt(
                    store,
                    creation_receipt,
                )
            yield store
    finally:
        os.close(directory_fd)


def _read_bound_file_bytes(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    *,
    max_bytes: int,
    too_large_code: str,
    path: Path | None = None,
    dir_fd: int | None = None,
    basename: str | None = None,
) -> bytes:
    if bound.opened.st_size > max_bytes:
        raise StoreSafetyError(
            too_large_code,
            f"File exceeds {max_bytes} bytes: {bound.path}",
        )
    os.lseek(bound.fd, 0, os.SEEK_SET)
    payload = bytearray()
    while True:
        chunk = os.read(
            bound.fd,
            min(CHUNK_SIZE, max_bytes + 1 - len(payload)),
        )
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > max_bytes:
            raise StoreSafetyError(
                too_large_code,
                f"File exceeds {max_bytes} bytes: {bound.path}",
            )
    if hashlib.sha256(payload).hexdigest() != bound.sha256:
        raise StoreSafetyError(
            codes.content,
            f"Bound file bytes changed while reading: {bound.path}",
        )
    if dir_fd is not None and basename is not None:
        _verify_bound_regular_file_at(
            bound,
            codes,
            dir_fd=dir_fd,
            basename=basename,
        )
    else:
        _verify_bound_regular_file(bound, codes, path=path)
    return bytes(payload)


@contextmanager
def _create_bound_directory(
    path: Path,
    *,
    retain_failure_receipt: bool = False,
) -> Iterator[_BoundDirectory]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = _directory_open_flags()
    parent_fd = os.open(path.parent, flags)
    parent_opened = os.fstat(parent_fd)
    fd: int | None = None
    created_and_bound = False
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
        fd = os.open(path.name, flags, dir_fd=parent_fd)
        created_path = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        created_fd = os.fstat(fd)
        if not _same_identity(created_path, created_fd):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                f"Prepared directory was replaced while being created: {path}",
            )
        created_and_bound = True
    except StoreSafetyError:
        raise
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Cannot create and bind private prepared directory {path}: {exc}",
        ) from exc
    finally:
        if not created_and_bound:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
    assert fd is not None
    binding = _BoundDirectory(
        path=path,
        fd=fd,
        opened=os.fstat(fd),
        parent_opened=parent_opened,
        parent_fd=parent_fd,
    )
    try:
        try:
            _verify_bound_directory_at(
                binding,
                parent_fd=parent_fd,
                basename=path.name,
                display_path=path,
            )
            yield binding
        except Exception as exc:
            safety_error = exc if isinstance(exc, StoreSafetyError) else None
            existing_details = dict(safety_error.details) if safety_error else {}
            publication_state = existing_details.get("publication_state")
            if (
                retain_failure_receipt
                and (
                    safety_error is None
                    or safety_error.code != "destination-install-uncertain"
                )
                and publication_state not in {"committed", "uncertain"}
            ):
                try:
                    retained = _retained_bound_directory_receipt(binding, path)
                except Exception as receipt_error:
                    merged = dict(existing_details)
                    if isinstance(receipt_error, StoreSafetyError):
                        merged.update(receipt_error.details)
                        cleanup_error_code = receipt_error.code
                    else:
                        merged.update(
                            {
                                "cleanup_state": "preserved-or-incomplete",
                                "recovery_locators": {
                                    "prepared_namespace": str(path),
                                    "prepared_parent": str(path.parent),
                                },
                                "cleanup_error_type": type(receipt_error).__name__,
                            }
                        )
                        cleanup_error_code = (
                            "prepared-directory-revalidation-inconclusive"
                        )
                    merged["cleanup_error_code"] = cleanup_error_code
                    merged["cleanup_error"] = str(receipt_error)
                    existing_details = merged
                else:
                    if retained is not None:
                        merged = dict(existing_details)
                        merged.update(retained)
                        existing_details = merged
            if safety_error is not None:
                safety_error.details = existing_details
                raise
            if not retain_failure_receipt:
                raise
            existing_details.update(
                {
                    "underlying_error_type": type(exc).__name__,
                    "underlying_errno": getattr(exc, "errno", None),
                }
            )
            raise StoreSafetyError(
                "prepared-operation-failed",
                "A prepared-tree operation failed before a safe terminal "
                f"publication state: {path}: {exc}",
                details=existing_details,
            ) from exc
    finally:
        os.close(fd)
        os.close(parent_fd)


def _verify_bound_directory_with_stat(
    binding: _BoundDirectory,
    *,
    target: Path,
    stat_target: Callable[[], os.stat_result],
) -> dict[str, Any]:
    try:
        descriptor = os.fstat(binding.fd)
        path_stat = stat_target()
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "prepared-directory-identity-mismatch",
            f"Bound prepared directory is missing: {target}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Cannot revalidate bound prepared directory {target}: {exc}",
        ) from exc
    if (
        not stat.S_ISDIR(descriptor.st_mode)
        or not stat.S_ISDIR(path_stat.st_mode)
        or not _same_identity(binding.opened, descriptor)
        or not _same_identity(descriptor, path_stat)
    ):
        raise StoreSafetyError(
            "prepared-directory-identity-mismatch",
            f"Prepared directory object identity changed: {target}",
        )
    baseline_access = _access_policy(binding.opened)
    if (
        _access_policy(descriptor) != baseline_access
        or _access_policy(path_stat) != baseline_access
    ):
        raise StoreSafetyError(
            "prepared-directory-access-policy-mismatch",
            f"Prepared directory access policy changed: {target}",
        )
    return {
        "identity": _identity(descriptor),
        "access_policy": _access_policy(descriptor),
        "metadata": _metadata(descriptor),
    }


def _verify_bound_directory(
    binding: _BoundDirectory,
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    target = path or binding.path
    return _verify_bound_directory_with_stat(
        binding,
        target=target,
        stat_target=lambda: os.stat(target, follow_symlinks=False),
    )


def _verify_bound_directory_at(
    binding: _BoundDirectory,
    *,
    parent_fd: int,
    basename: str,
    display_path: Path,
) -> dict[str, Any]:
    return _verify_bound_directory_with_stat(
        binding,
        target=display_path,
        stat_target=lambda: os.stat(
            basename,
            dir_fd=parent_fd,
            follow_symlinks=False,
        ),
    )


def _verify_bound_parent_descriptor(
    parent_fd: int,
    opened: os.stat_result,
    *,
    display_path: Path,
    identity_code: str,
    access_policy_code: str,
    inconclusive_code: str,
) -> os.stat_result:
    try:
        current = os.fstat(parent_fd)
    except OSError as exc:
        raise StoreSafetyError(
            inconclusive_code,
            f"Cannot revalidate bound parent descriptor {display_path}: {exc}",
        ) from exc
    if not stat.S_ISDIR(current.st_mode) or not _same_identity(opened, current):
        raise StoreSafetyError(
            identity_code,
            f"Bound parent directory identity changed: {display_path}",
        )
    if _access_policy(opened) != _access_policy(current):
        raise StoreSafetyError(
            access_policy_code,
            f"Bound parent directory access policy changed: {display_path}",
        )
    return current


def _fsync_bound_parent_descriptor(
    parent_fd: int,
    opened: os.stat_result,
    *,
    display_path: Path,
    identity_code: str,
    access_policy_code: str,
    inconclusive_code: str,
) -> None:
    _verify_bound_parent_descriptor(
        parent_fd,
        opened,
        display_path=display_path,
        identity_code=identity_code,
        access_policy_code=access_policy_code,
        inconclusive_code=inconclusive_code,
    )
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        raise StoreSafetyError(
            inconclusive_code,
            f"Cannot fsync bound parent directory {display_path}: {exc}",
        ) from exc
    _verify_bound_parent_descriptor(
        parent_fd,
        opened,
        display_path=display_path,
        identity_code=identity_code,
        access_policy_code=access_policy_code,
        inconclusive_code=inconclusive_code,
    )


def _inventory_file_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _scan_sensitive_partial_inventory(
    binding: _BoundDirectory,
    *,
    max_entries: int = 64,
    max_depth: int = 4,
) -> list[dict[str, Any]]:
    """Inventory a retained partial without following any child links."""

    def scan_directory(
        directory_fd: int,
        relative_parent: Path,
        depth: int,
        records: list[dict[str, Any]],
    ) -> None:
        if depth > max_depth:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                "Retained partial exceeds the descriptor-safe inventory depth cap",
            )
        try:
            names = sorted(os.fsdecode(name) for name in os.listdir(directory_fd))
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                "Cannot list retained partial through its bound descriptor: "
                f"{binding.path}: {exc}",
            ) from exc
        for name in names:
            if len(records) >= max_entries:
                raise StoreSafetyError(
                    "prepared-directory-revalidation-inconclusive",
                    "Retained partial exceeds the descriptor-safe inventory "
                    f"entry cap ({max_entries})",
                )
            relative_path = relative_parent / name
            try:
                entry_stat = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise StoreSafetyError(
                    "prepared-directory-revalidation-inconclusive",
                    "Cannot inspect retained partial entry without following links: "
                    f"{binding.path / relative_path}: {exc}",
                ) from exc
            record: dict[str, Any] = {
                "relative_path": str(relative_path),
                "file_type": _inventory_file_type(entry_stat.st_mode),
                "identity": _identity(entry_stat),
                "access_policy": _access_policy(entry_stat),
            }
            if stat.S_ISREG(entry_stat.st_mode):
                record["size"] = entry_stat.st_size
            records.append(record)
            if not stat.S_ISDIR(entry_stat.st_mode):
                continue
            child_fd: int | None = None
            try:
                child_fd = os.open(
                    name,
                    _directory_open_flags(),
                    dir_fd=directory_fd,
                )
                child_stat = os.fstat(child_fd)
                if not _same_identity(entry_stat, child_stat):
                    raise StoreSafetyError(
                        "prepared-directory-identity-mismatch",
                        "Retained partial child directory changed while binding: "
                        f"{binding.path / relative_path}",
                    )
                scan_directory(
                    child_fd,
                    relative_path,
                    depth + 1,
                    records,
                )
                child_after = os.fstat(child_fd)
                current_child = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (
                    not _same_identity(entry_stat, child_after)
                    or not _same_identity(child_after, current_child)
                ):
                    raise StoreSafetyError(
                        "prepared-directory-identity-mismatch",
                        "Retained partial child directory changed during inventory: "
                        f"{binding.path / relative_path}",
                    )
                if (
                    _access_policy(entry_stat) != _access_policy(child_after)
                    or _access_policy(child_after) != _access_policy(current_child)
                ):
                    raise StoreSafetyError(
                        "prepared-directory-access-policy-mismatch",
                        "Retained partial child access policy changed during "
                        f"inventory: {binding.path / relative_path}",
                    )
            finally:
                if child_fd is not None:
                    os.close(child_fd)

    inventories: list[list[dict[str, Any]]] = []
    for _ in range(2):
        inventory_fd: int | None = None
        try:
            inventory_fd = os.open(
                ".",
                _directory_open_flags(),
                dir_fd=binding.fd,
            )
            opened = os.fstat(inventory_fd)
            if not _same_identity(binding.opened, opened):
                raise StoreSafetyError(
                    "prepared-directory-identity-mismatch",
                    "Retained partial root descriptor no longer identifies the "
                    f"creation-time object: {binding.path}",
                )
            records: list[dict[str, Any]] = []
            scan_directory(inventory_fd, Path(), 0, records)
            inventories.append(records)
        finally:
            if inventory_fd is not None:
                os.close(inventory_fd)
    if inventories[0] != inventories[1]:
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            "Retained partial inventory changed between descriptor-relative scans: "
            f"{binding.path}",
        )
    return inventories[1]


def _retained_bound_directory_receipt(
    binding: _BoundDirectory | None,
    path: Path,
) -> dict[str, Any] | None:
    """Preserve and precisely describe a failed sensitive prepared tree."""

    recovery_details = {
        "cleanup_state": "preserved-or-incomplete",
        "recovery_locators": {
            "prepared_namespace": str(path),
            "prepared_parent": str(path.parent),
        },
    }
    if binding is None:
        state, _ = _observe_path(path)
        if state == "absent":
            return None
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            "Cannot prove ownership of a prepared directory without its "
            f"creation receipt; preserving {path}",
            details=recovery_details,
        )
    if binding.parent_fd is None:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            "The creation-time parent descriptor is unavailable while preserving "
            f"the retained partial: {path}",
            details=recovery_details,
        )

    try:
        _verify_bound_parent_descriptor(
            binding.parent_fd,
            binding.parent_opened,
            display_path=path.parent,
            identity_code="prepared-directory-identity-mismatch",
            access_policy_code="prepared-directory-access-policy-mismatch",
            inconclusive_code="prepared-directory-revalidation-inconclusive",
        )
        root = _verify_bound_directory_at(
            binding,
            parent_fd=binding.parent_fd,
            basename=path.name,
            display_path=path,
        )
        inventory = _scan_sensitive_partial_inventory(binding)
        terminal_root = _verify_bound_directory_at(
            binding,
            parent_fd=binding.parent_fd,
            basename=path.name,
            display_path=path,
        )
        terminal_parent = _verify_bound_parent_descriptor(
            binding.parent_fd,
            binding.parent_opened,
            display_path=path.parent,
            identity_code="prepared-directory-identity-mismatch",
            access_policy_code="prepared-directory-access-policy-mismatch",
            inconclusive_code="prepared-directory-revalidation-inconclusive",
        )
        return {
            "cleanup_state": "retained",
            "recovery_locators": {
                "prepared_namespace": str(path),
                "prepared_parent": str(path.parent),
                "namespace_verification": "creation-receipt-matched",
                "prepared_identity": root["identity"],
                "prepared_parent_identity": _identity(terminal_parent),
            },
            "sensitive_partial_inventory": inventory,
            "terminal_prepared_identity": terminal_root["identity"],
        }
    except StoreSafetyError as exc:
        details = dict(recovery_details)
        details.update(exc.details)
        raise StoreSafetyError(
            exc.code,
            str(exc),
            details=details,
        ) from exc


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
        main_path.with_name(f"{main_path.name}-journal"),
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
        except OSError as exc:
            raise StoreSafetyError(
                "source-revalidation-inconclusive",
                "Cannot safely determine database file-set membership: "
                f"{candidate}: {exc}",
            ) from exc
        present.append(candidate)
    if main_path not in present:
        raise StoreSafetyError(
            "source-missing", f"Main SQLite file is missing: {main_path}"
        )
    return present


def _reject_bound_rollback_journal(
    opened_sources: list[_OpenedSource],
    main_path: Path,
) -> None:
    journal_name = f"{main_path.name}-journal"
    journal = next(
        (opened for opened in opened_sources if opened.path.name == journal_name),
        None,
    )
    if journal is None:
        return
    try:
        journal.first_sha256 = _hash_fd(journal.fd)
        second_sha256 = _hash_fd(journal.fd)
        receipt = _revalidate_open_source(journal, second_sha256)
    except StoreSafetyError as exc:
        raise StoreSafetyError(
            "rollback-journal-present",
            "A SQLite rollback journal is present, but its stable bytes and "
            f"identity cannot be proven: {journal.path}: {exc}",
            details={
                "journal": str(journal.path),
                "binding_status": "inconclusive",
                "reason_code": exc.code,
                "safe_action": "preserve-main-and-journal-and-retry-after-quiescence",
            },
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "rollback-journal-present",
            "A SQLite rollback journal is present, but its descriptor bytes "
            f"cannot be read stably: {journal.path}: {exc}",
            details={
                "journal": str(journal.path),
                "binding_status": "inconclusive",
                "reason_code": "journal-read-inconclusive",
                "safe_action": "preserve-main-and-journal-and-retry-after-quiescence",
            },
        ) from exc
    raise StoreSafetyError(
        "rollback-journal-present",
        "A descriptor-bound SQLite rollback journal is present; refusing to "
        "capture or recover the main database without SQLite owning rollback: "
        f"{journal.path}",
        details={
            "journal": str(journal.path),
            "binding_status": "stable",
            "journal_receipt": receipt,
            "safe_action": "preserve-main-and-journal-and-retry-after-quiescence",
        },
    )


def _reject_new_rollback_journal_membership(
    main_path: Path,
    *,
    baseline_names: list[str],
    observed_names: list[str],
    phase: str,
) -> None:
    journal_name = f"{main_path.name}-journal"
    if journal_name not in observed_names or journal_name in baseline_names:
        return
    journal_path = main_path.with_name(journal_name)
    raise StoreSafetyError(
        "rollback-journal-present",
        "A SQLite rollback journal appeared while binding the database file set; "
        f"refusing an ambiguous capture: {journal_path}",
        details={
            "journal": str(journal_path),
            "binding_status": "inconclusive",
            "reason_code": "journal-membership-changed",
            "phase": phase,
            "safe_action": "preserve-main-and-journal-and-retry-after-quiescence",
        },
    )


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
    main_path: Path,
    destination_dir: Path | None = None,
    *,
    destination_binding: _BoundDirectory | None = None,
) -> list[dict[str, Any]]:
    before_paths = _discover_database_files(main_path)
    before_names = [path.name for path in before_paths]
    opened_sources: list[_OpenedSource] = []
    try:
        for path in before_paths:
            try:
                fd, opened_stat = _open_regular_readonly(path)
            except StoreSafetyError as exc:
                if path.name != f"{main_path.name}-journal":
                    raise
                raise StoreSafetyError(
                    "rollback-journal-present",
                    "A SQLite rollback-journal namespace is present but cannot "
                    f"be bound as one stable regular file: {path}: {exc}",
                    details={
                        "journal": str(path),
                        "binding_status": "inconclusive",
                        "reason_code": exc.code,
                        "safe_action": (
                            "preserve-main-and-journal-and-retry-after-quiescence"
                        ),
                    },
                ) from exc
            opened_sources.append(_OpenedSource(path=path, fd=fd, before=opened_stat))

        after_open_names = [path.name for path in _discover_database_files(main_path)]
        _reject_new_rollback_journal_membership(
            main_path,
            baseline_names=before_names,
            observed_names=after_open_names,
            phase="after-open",
        )
        if after_open_names != before_names:
            raise StoreSafetyError(
                "store-file-set-mismatch",
                "SQLite main/WAL/SHM/rollback-journal membership changed while "
                "opening the store",
            )
        _reject_bound_rollback_journal(opened_sources, main_path)

        if destination_dir is not None:
            if destination_binding is None:
                destination_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            else:
                if destination_binding.path != destination_dir:
                    raise StoreSafetyError(
                        "prepared-directory-identity-mismatch",
                        "Recovery destination binding does not match the copy target: "
                        f"{destination_dir}",
                    )
                _verify_bound_directory(destination_binding)

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

        if len(opened_sources) != len(records):
            raise StoreSafetyError(
                "source-revalidation-inconclusive",
                "Internal capture records do not match the bound source set",
            )
        for opened, record in zip(opened_sources, records):
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
        _reject_new_rollback_journal_membership(
            main_path,
            baseline_names=before_names,
            observed_names=final_names,
            phase="final-revalidation",
        )
        if final_names != before_names:
            raise StoreSafetyError(
                "store-file-set-mismatch",
                "SQLite main/WAL/SHM/rollback-journal membership changed during "
                "capture",
            )
        if destination_binding is not None:
            _verify_bound_directory(destination_binding)
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


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    temp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(temp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
            json.dump(
                payload, handle, indent=2, ensure_ascii=False, default=_json_default
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        opened = os.fstat(fd)
        sha256 = _hash_fd(fd)
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
        bound = _BoundRegularFile(
            path=path,
            fd=fd,
            opened=opened,
            sha256=sha256,
        )
        return _verify_bound_regular_file(bound, PREPARED_FILE_CODES)
    finally:
        os.close(fd)
        if _lexists(temp_path):
            os.unlink(temp_path)


def _parse_manifest_bytes(
    payload_bytes: bytes,
    *,
    path: Path,
    expected_schema: str,
) -> dict[str, Any]:
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


def _normalized_json_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = json.loads(
        json.dumps(payload, ensure_ascii=False, default=_json_default)
    )
    if not isinstance(normalized, dict):
        raise TypeError("Expected a JSON object")
    return normalized


def _load_bound_manifest(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    expected_schema: str,
) -> dict[str, Any]:
    payload_bytes = _read_bound_file_bytes(
        bound,
        codes,
        max_bytes=MANIFEST_MAX_BYTES,
        too_large_code="manifest-too-large",
    )
    return _parse_manifest_bytes(
        payload_bytes,
        path=bound.path,
        expected_schema=expected_schema,
    )


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
    return _parse_manifest_bytes(
        bytes(payload_bytes),
        path=path,
        expected_schema=expected_schema,
    )


def _assert_bound_matches_receipt(
    bound: _BoundRegularFile,
    receipt: dict[str, Any],
    *,
    path: Path | None = None,
    dir_fd: int | None = None,
    basename: str | None = None,
) -> dict[str, Any]:
    if (dir_fd is None) != (basename is None):
        raise ValueError("dir_fd and basename must be supplied together")
    if dir_fd is not None and basename is not None:
        current = _verify_bound_regular_file_at(
            bound,
            PREPARED_FILE_CODES,
            dir_fd=dir_fd,
            basename=basename,
        )
        target = bound.path
    else:
        current = _verify_bound_regular_file(
            bound,
            PREPARED_FILE_CODES,
            path=path,
        )
        target = path or bound.path
    if current["identity"] != receipt.get("identity"):
        raise StoreSafetyError(
            "prepared-file-identity-mismatch",
            f"Prepared file identity differs from its creation receipt: {target}",
        )
    if current["access_policy"] != receipt.get("access_policy"):
        raise StoreSafetyError(
            "prepared-file-access-policy-mismatch",
            f"Prepared file access policy differs from its creation receipt: {target}",
        )
    if current["sha256"] != receipt.get("sha256") or current["size"] != receipt.get(
        "size"
    ):
        raise StoreSafetyError(
            "prepared-file-content-mismatch",
            f"Prepared file bytes differ from its creation receipt: {target}",
        )
    return current


@contextmanager
def _bind_prepared_regular_files(
    root: Path,
    *,
    manifest_name: str,
    manifest_payload: dict[str, Any],
    manifest_receipt: dict[str, Any],
    file_receipts: dict[Path, dict[str, Any]],
) -> Iterator[dict[Path, _BoundRegularFile]]:
    with ExitStack() as stack:
        manifest_relative = Path(manifest_name)
        bindings = {
            manifest_relative: stack.enter_context(
                _bind_regular_file(
                    root / manifest_relative,
                    PREPARED_FILE_CODES,
                )
            )
        }
        for relative_path in file_receipts:
            bindings[relative_path] = stack.enter_context(
                _bind_regular_file(
                    root / relative_path,
                    PREPARED_FILE_CODES,
                )
            )
        loaded_manifest = _load_bound_manifest(
            bindings[manifest_relative],
            PREPARED_FILE_CODES,
            str(manifest_payload["schema"]),
        )
        if loaded_manifest != _normalized_json_payload(manifest_payload):
            raise StoreSafetyError(
                "prepared-manifest-mismatch",
                f"Prepared manifest differs from the in-memory payload: "
                f"{root / manifest_relative}",
            )
        _assert_bound_matches_receipt(
            bindings[manifest_relative],
            manifest_receipt,
        )
        for relative_path, receipt in file_receipts.items():
            _assert_bound_matches_receipt(
                bindings[relative_path],
                receipt,
            )
        yield bindings


def _revalidate_published_regular_files(
    destination: Path,
    bindings: dict[Path, _BoundRegularFile],
    *,
    manifest_name: str,
    manifest_payload: dict[str, Any],
    manifest_receipt: dict[str, Any],
    file_receipts: dict[Path, dict[str, Any]],
) -> None:
    manifest_relative = Path(manifest_name)
    _assert_bound_matches_receipt(
        bindings[manifest_relative],
        manifest_receipt,
        path=destination / manifest_relative,
    )
    for relative_path, receipt in file_receipts.items():
        _assert_bound_matches_receipt(
            bindings[relative_path],
            receipt,
            path=destination / relative_path,
        )
    manifest_bytes = _read_bound_file_bytes(
        bindings[manifest_relative],
        PREPARED_FILE_CODES,
        max_bytes=MANIFEST_MAX_BYTES,
        too_large_code="manifest-too-large",
        path=destination / manifest_relative,
    )
    installed_manifest = _parse_manifest_bytes(
        manifest_bytes,
        path=destination / manifest_relative,
        expected_schema=str(manifest_payload["schema"]),
    )
    if installed_manifest != _normalized_json_payload(manifest_payload):
        raise StoreSafetyError(
            "prepared-manifest-mismatch",
            f"Published manifest differs from the in-memory payload: "
            f"{destination / manifest_relative}",
        )


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


def _inspect_wal_payload(payload: bytes, wal_path: Path) -> dict[str, Any]:
    size = len(payload)
    if size == 0:
        return {
            "present": True,
            "status": "empty",
            "size": 0,
            "frame_count": 0,
            "commit_frame_count": 0,
        }
    header = payload[:32]
    if len(header) != 32:
        raise StoreSafetyError("wal-invalid", f"WAL header is truncated: {wal_path}")
    magic, version, raw_page_size, _, salt1, salt2, stored0, stored1 = struct.unpack(
        ">8I", header
    )
    if magic not in WAL_MAGIC_NUMBERS:
        raise StoreSafetyError("wal-invalid", f"WAL magic is invalid: {wal_path}")
    if version != WAL_VERSION:
        raise StoreSafetyError(
            "wal-version-unsupported",
            f"Unsupported WAL version {version}: {wal_path}",
        )
    page_size = raw_page_size
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise StoreSafetyError("wal-invalid", f"WAL page size is invalid: {wal_path}")
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
        offset = 32 + index * frame_size
        frame_header = payload[offset : offset + 24]
        page = payload[offset + 24 : offset + frame_size]
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
        "checksum_byte_order": (
            "little" if checksum_byte_order == "<" else "big"
        ),
        "big_end_checksum": checksum_byte_order == ">",
    }


def _inspect_wal(wal_path: Path) -> dict[str, Any]:
    try:
        payload = wal_path.read_bytes()
    except OSError as exc:
        raise StoreSafetyError(
            "wal-invalid",
            f"Cannot read WAL for validation: {wal_path}: {exc}",
        ) from exc
    return _inspect_wal_payload(payload, wal_path)


def _parse_shm_header_copy(payload: bytes, offset: int) -> dict[str, Any] | None:
    if len(payload) < offset + 48:
        return None
    for byte_order in ("<", ">"):
        version = struct.unpack_from(f"{byte_order}I", payload, offset)[0]
        if version != WAL_VERSION:
            continue
        initialized = payload[offset + 12]
        if initialized not in {0, 1}:
            continue
        big_end_checksum = payload[offset + 13]
        if big_end_checksum not in {0, 1}:
            continue
        calculated_checksum = _wal_checksum(
            payload[offset : offset + 40],
            byte_order,
        )
        stored_checksum = struct.unpack_from(
            f"{byte_order}2I",
            payload,
            offset + 40,
        )
        if calculated_checksum != stored_checksum:
            continue
        raw_page_size = struct.unpack_from(f"{byte_order}H", payload, offset + 14)[0]
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        max_frame = struct.unpack_from(f"{byte_order}I", payload, offset + 16)[0]
        # WAL-index integers use native byte order, but aSalt is copied byte-for-byte
        # from the big-endian WAL header.
        salt = list(struct.unpack_from(">2I", payload, offset + 32))
        return {
            "byte_order": "little" if byte_order == "<" else "big",
            "initialized": bool(initialized),
            "change_counter": struct.unpack_from(
                f"{byte_order}I",
                payload,
                offset + 8,
            )[0],
            "big_end_checksum": bool(big_end_checksum),
            "raw_page_size": raw_page_size,
            "page_size": page_size,
            "max_frame": max_frame,
            "database_page_count": struct.unpack_from(
                f"{byte_order}I",
                payload,
                offset + 20,
            )[0],
            "frame_checksum": list(
                struct.unpack_from(
                    f"{byte_order}2I",
                    payload,
                    offset + 24,
                )
            ),
            "salt": salt,
            "header_checksum": list(stored_checksum),
        }
    return None


def _classify_sidecar_payloads(
    main_path: Path,
    *,
    wal_payload: bytes | None,
    shm_payload: bytes | None,
) -> dict[str, Any]:
    wal_path = main_path.with_name(f"{main_path.name}-wal")
    shm_path = main_path.with_name(f"{main_path.name}-shm")
    wal: dict[str, Any]
    if wal_payload is not None:
        wal = _inspect_wal_payload(wal_payload, wal_path)
    else:
        wal = {"present": False, "status": "absent"}

    shm: dict[str, Any] = {"present": False, "status": "absent"}
    if shm_payload is not None:
        header = shm_payload[:96]
        parsed_copies = (
            _parse_shm_header_copy(header, 0),
            _parse_shm_header_copy(header, 48),
        )
        copies = [parsed for parsed in parsed_copies if parsed is not None]
        duplicate_headers_consistent = (
            len(copies) == 2
            and parsed_copies[0] == parsed_copies[1]
            and header[:48] == header[48:96]
        )
        trusted_header = parsed_copies[0] if duplicate_headers_consistent else None
        same_generation = [
            parsed
            for parsed in ([trusted_header] if trusted_header is not None else [])
            if wal.get("status") not in {"absent", "empty"}
            and parsed["initialized"]
            and parsed["salt"] == wal["salt"]
            and parsed["page_size"] == wal["page_size"]
            and parsed["big_end_checksum"] == wal["big_end_checksum"]
        ]
        matching_headers = sum(
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
            if matching_headers
            else "derived-rebuild-required",
            "size": len(shm_payload),
            "valid_header_copies": len(copies),
            "duplicate_headers_consistent": duplicate_headers_consistent,
            "same_generation_header_copies": 2 if same_generation else 0,
            "matching_wal_header_copies": (
                2 if matching_headers and duplicate_headers_consistent else 0
            ),
        }

    ignored = [shm_path.name] if shm_payload is not None else []
    authoritative = [main_path.name]
    if wal_payload is not None and wal.get("last_valid_commit_frame", 0) > 0:
        authoritative.append(wal_path.name)
    return {
        "wal": wal,
        "shm": shm,
        "recovery": {
            "authoritative_files": authoritative,
            "ignored_derived_files": ignored,
            "strategy": (
                "bind copied main/WAL/SHM, ignore derived SHM bytes, and apply the "
                "checksum-valid committed WAL prefix to an anonymous image"
            ),
        },
    }


def _inspect_sidecars(main_path: Path) -> dict[str, Any]:
    wal_path = main_path.with_name(f"{main_path.name}-wal")
    shm_path = main_path.with_name(f"{main_path.name}-shm")
    try:
        wal_payload = wal_path.read_bytes() if wal_path.exists() else None
        shm_payload = shm_path.read_bytes() if shm_path.exists() else None
    except OSError as exc:
        raise StoreSafetyError(
            "wal-invalid",
            f"Cannot read copied recovery sidecars beside {main_path}: {exc}",
        ) from exc
    return _classify_sidecar_payloads(
        main_path,
        wal_payload=wal_payload,
        shm_payload=shm_payload,
    )


def _inspect_bound_sidecars(
    store: _BoundRecoveryStore,
) -> dict[str, Any]:
    wal_name = f"{store.main_name}-wal"
    shm_name = f"{store.main_name}-shm"

    def read_if_present(basename: str) -> bytes | None:
        bound = store.files.get(basename)
        if bound is None:
            return None
        return _read_bound_file_bytes(
            bound,
            PREPARED_FILE_CODES,
            max_bytes=bound.opened.st_size,
            too_large_code="prepared-file-content-mismatch",
            dir_fd=store.directory.fd,
            basename=basename,
        )

    _verify_bound_recovery_store(store)
    result = _classify_sidecar_payloads(
        store.directory.path / store.main_name,
        wal_payload=read_if_present(wal_name),
        shm_payload=read_if_present(shm_name),
    )
    _verify_bound_recovery_store(store)
    return result


def _sqlite_integrity(
    database: Path | _BoundRegularFile,
) -> dict[str, Any]:
    db_path = database.path if isinstance(database, _BoundRegularFile) else database
    connect_target: Path | str
    connect_kwargs: dict[str, Any] = {}
    if isinstance(database, _BoundRegularFile):
        _verify_bound_regular_file(database, PREPARED_FILE_CODES)
        connect_target = _bound_sqlite_readonly_uri(database)
        connect_kwargs["uri"] = True
    else:
        connect_target = db_path
    try:
        with closing(sqlite3.connect(connect_target, **connect_kwargs)) as conn:
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
    if isinstance(database, _BoundRegularFile):
        _verify_bound_regular_file(database, PREPARED_FILE_CODES)
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


def _make_recovery_clone(src_main: Path, destination: Path) -> _RecoveryClone:
    with _create_bound_directory(destination) as destination_binding:
        records = _capture_database_files(
            src_main,
            destination,
            destination_binding=destination_binding,
        )
        copied_main = destination / src_main.name
        file_receipts = {str(record["basename"]): record["copy"] for record in records}
        receipt = _recovery_store_creation_receipt(
            destination_binding,
            src_main.name,
            file_receipts,
        )
        with _bind_recovery_store(
            copied_main,
            creation_receipt=receipt,
        ) as copied_store:
            sidecars = _inspect_bound_sidecars(copied_store)
            _assert_recovery_store_matches_receipt(copied_store, receipt)
        _verify_bound_directory(destination_binding)
    return _RecoveryClone(
        main_path=copied_main,
        evidence={"capture": records, "sidecars": sidecars},
        receipt=receipt,
    )


def _make_recovery_clone_from_bound(
    files: dict[str, _BoundRegularFile],
    destination: Path,
    codes: _FileProtectionCodes,
) -> _RecoveryClone:
    """Copy an already-bound store without reopening mutable source paths."""

    if NOTE_STORE_MAIN not in files:
        raise StoreSafetyError(
            "manifest-invalid",
            "The bound recovery file set has no main SQLite database",
        )
    with _create_bound_directory(destination) as destination_binding:
        records: list[dict[str, Any]] = []
        for basename in NOTE_STORE_BASENAMES:
            bound = files.get(basename)
            if bound is None:
                continue
            source = _verify_bound_regular_file(bound, codes)
            copied = _copy_fd(bound.fd, destination / basename)
            if (
                copied["sha256"] != bound.sha256
                or copied["size"] != bound.opened.st_size
            ):
                raise StoreSafetyError(
                    codes.content,
                    f"Bound source changed while creating recovery clone: {bound.path}",
                )
            records.append(
                {
                    "basename": basename,
                    "source": source,
                    "copy": copied,
                }
            )
        copied_main = destination / NOTE_STORE_MAIN
        file_receipts = {str(record["basename"]): record["copy"] for record in records}
        receipt = _recovery_store_creation_receipt(
            destination_binding,
            NOTE_STORE_MAIN,
            file_receipts,
        )
        with _bind_recovery_store(
            copied_main,
            creation_receipt=receipt,
        ) as copied_store:
            sidecars = _inspect_bound_sidecars(copied_store)
            _assert_recovery_store_matches_receipt(copied_store, receipt)
        _verify_bound_directory(destination_binding)
    return _RecoveryClone(
        main_path=copied_main,
        evidence={"capture": records, "sidecars": sidecars},
        receipt=receipt,
    )


def validate_database_recovery(src_main: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apple-notes-recovery-") as temp_dir:
        clone = _make_recovery_clone(src_main, Path(temp_dir) / "store")
        with _bind_recovery_store(
            clone.main_path,
            creation_receipt=clone.receipt,
        ) as recovered_store:
            _require_authoritative_wal(recovered_store, clone.evidence)
            clone.evidence["sqlite_integrity"] = _bound_recovery_integrity(
                recovered_store
            )
        return clone.evidence


def _fingerprint_file(path: Path) -> dict[str, Any]:
    records = _capture_database_files(path)
    if len(records) != 1:
        raise StoreSafetyError(
            "unexpected-sidecars",
            f"Expected a standalone SQLite file but found sidecars beside {path}",
        )
    return records[0]["source"]


def _publication_details(
    state: str,
    *,
    prepared: _BoundRegularFile | None,
    destination: Path,
    retry_safe: bool,
) -> dict[str, Any]:
    locators: dict[str, Any] = {"destination": str(destination)}
    if prepared is not None:
        receipt: dict[str, Any] = {
            "path": str(prepared.path),
            "identity": _identity(prepared.opened),
        }
        if prepared.parent_opened is not None:
            receipt["parent_identity"] = _identity(prepared.parent_opened)
        try:
            parent = os.stat(prepared.path.parent, follow_symlinks=False)
            leaf = os.stat(prepared.path, follow_symlinks=False)
        except FileNotFoundError:
            receipt["verification"] = "absent-or-parent-missing"
            locators["prepared_unverified"] = receipt
        except OSError as exc:
            receipt["verification"] = f"inconclusive: {exc}"
            locators["prepared_unverified"] = receipt
        else:
            parent_matches = (
                prepared.parent_opened is not None
                and stat.S_ISDIR(parent.st_mode)
                and _same_identity(prepared.parent_opened, parent)
                and _access_policy(prepared.parent_opened) == _access_policy(parent)
            )
            leaf_matches = (
                stat.S_ISREG(leaf.st_mode)
                and _same_identity(prepared.opened, leaf)
                and _access_policy(prepared.opened) == _access_policy(leaf)
            )
            if parent_matches and leaf_matches:
                locators["prepared"] = str(prepared.path)
            else:
                receipt["verification"] = "creation-receipt-mismatch"
                receipt["observed_identity"] = _identity(leaf)
                receipt["observed_parent_identity"] = _identity(parent)
                locators["prepared_unverified"] = receipt
    return {
        "publication_state": state,
        "retry_safe": retry_safe,
        "recovery_locators": locators,
    }


@contextmanager
def _bind_publication_parent(
    prepared: _BoundRegularFile,
) -> Iterator[int]:
    parent_fd: int | None = None
    try:
        parent_before = os.stat(prepared.path.parent, follow_symlinks=False)
        parent_fd = os.open(prepared.path.parent, _directory_open_flags())
        parent_descriptor = os.fstat(parent_fd)
        parent_after = os.stat(prepared.path.parent, follow_symlinks=False)
        prepared_leaf = os.stat(
            prepared.path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
            parent_fd = None
        raise StoreSafetyError(
            "prepared-file-missing",
            f"The private publication parent or leaf is missing: {prepared.path}",
        ) from exc
    except PermissionError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
            parent_fd = None
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"The private publication parent or leaf is unreadable: {prepared.path}",
        ) from exc
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
            parent_fd = None
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot bind the private publication parent and leaf: "
            f"{prepared.path}: {exc}",
        ) from exc
    try:
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or not stat.S_ISDIR(parent_descriptor.st_mode)
            or not stat.S_ISDIR(parent_after.st_mode)
            or not _same_identity(parent_before, parent_descriptor)
            or not _same_identity(parent_descriptor, parent_after)
            or prepared.parent_opened is None
            or not _same_identity(prepared.parent_opened, parent_descriptor)
            or not stat.S_ISREG(prepared_leaf.st_mode)
            or not _same_identity(prepared.opened, prepared_leaf)
        ):
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                f"The private publication parent or leaf changed identity: "
                f"{prepared.path}",
            )
        if (
            _access_policy(parent_before) != _access_policy(parent_descriptor)
            or _access_policy(parent_descriptor) != _access_policy(parent_after)
            or _access_policy(prepared.parent_opened)
            != _access_policy(parent_descriptor)
            or _access_policy(prepared.opened) != _access_policy(prepared_leaf)
        ):
            raise StoreSafetyError(
                "prepared-file-access-policy-mismatch",
                f"The private publication parent or leaf changed access policy: "
                f"{prepared.path}",
            )
        yield parent_fd
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _observe_bound_sibling(
    parent_fd: int,
    prepared: _BoundRegularFile,
    path: Path,
) -> tuple[str, os.stat_result | None]:
    if path.parent != prepared.path.parent:
        return "unavailable", None
    try:
        value = os.stat(
            path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unavailable", None
    return "present", value


def _publish_file_no_replace(
    prepared: _BoundRegularFile,
    destination: Path,
) -> dict[str, Any]:
    """Install one bound file and classify every publication failure."""

    _verify_bound_regular_file(prepared, PREPARED_FILE_CODES)
    if destination.parent != prepared.path.parent:
        raise StoreSafetyError(
            "destination-install-failed",
            "Bound single-file publication requires the private and destination "
            f"leaves to share one parent: prepared={prepared.path}, "
            f"destination={destination}",
            details=_publication_details(
                "uncommitted",
                prepared=prepared,
                destination=destination,
                retry_safe=True,
            ),
        )
    try:
        with _bind_publication_parent(prepared) as parent_fd:
            return _publish_file_no_replace_from_parent(
                prepared,
                destination,
                parent_fd,
            )
    except StoreSafetyError as exc:
        if exc.details:
            raise
        raise StoreSafetyError(
            exc.code,
            str(exc),
            details=_publication_details(
                "uncommitted",
                prepared=prepared,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc


def _publish_file_no_replace_from_parent(
    prepared: _BoundRegularFile,
    destination: Path,
    parent_fd: int,
) -> dict[str, Any]:
    if prepared.parent_opened is None:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            "Prepared file has no creation-time parent receipt: "
            f"{prepared.path}",
        )
    before_rename = os.fstat(prepared.fd)
    try:
        _rename_file_no_replace_at(
            parent_fd,
            prepared.path.name,
            destination.name,
        )
    except OSError as exc:
        source_state, source_after = _observe_bound_sibling(
            parent_fd,
            prepared,
            prepared.path,
        )
        destination_state, destination_after = _observe_bound_sibling(
            parent_fd,
            prepared,
            destination,
        )
        committed = (
            source_state == "absent"
            and destination_state == "present"
            and destination_after is not None
            and _same_identity(prepared.opened, destination_after)
        )
        source_is_prepared = (
            source_state == "present"
            and source_after is not None
            and _same_identity(prepared.opened, source_after)
        )
        if committed:
            raise StoreSafetyError(
                "destination-install-uncertain",
                "The destination contains the prepared database, but the "
                f"publication syscall reported an error: {destination}: {exc}",
                details=_publication_details(
                    "uncertain",
                    prepared=prepared,
                    destination=destination,
                    retry_safe=False,
                ),
            ) from exc
        if (
            exc.errno == errno.EEXIST
            and source_is_prepared
            and destination_state == "present"
        ):
            raise StoreSafetyError(
                "destination-exists",
                f"Recovery destination appeared before installation: {destination}",
                details=_publication_details(
                    "uncommitted",
                    prepared=prepared,
                    destination=destination,
                    retry_safe=False,
                ),
            ) from exc
        if source_is_prepared and destination_state == "absent":
            raise StoreSafetyError(
                "destination-install-failed",
                f"Cannot install recovered database at {destination}: {exc}",
                details=_publication_details(
                    "uncommitted",
                    prepared=prepared,
                    destination=destination,
                    retry_safe=True,
                ),
            ) from exc
        raise StoreSafetyError(
            "destination-install-uncertain",
            "Cannot prove whether recovered-file publication committed; preserve "
            f"the reported locators: prepared={prepared.path}, "
            f"destination={destination}: {exc}",
            details=_publication_details(
                "uncertain",
                prepared=prepared,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc

    try:
        source_state, _ = _observe_bound_sibling(
            parent_fd,
            prepared,
            prepared.path,
        )
        destination_state, destination_after = _observe_bound_sibling(
            parent_fd,
            prepared,
            destination,
        )
        if (
            source_state != "absent"
            or destination_state != "present"
            or destination_after is None
            or not _same_identity(before_rename, destination_after)
            or _access_policy(destination_after) != _access_policy(prepared.opened)
        ):
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                "The no-replace rename succeeded, but the source/destination "
                f"namespace does not identify the prepared object: {destination}",
            )
        fingerprint = _verify_bound_regular_file_at(
            prepared,
            PREPARED_FILE_CODES,
            dir_fd=parent_fd,
            basename=destination.name,
        )
        _fsync_bound_parent_descriptor(
            parent_fd,
            prepared.parent_opened,
            display_path=destination.parent,
            identity_code="prepared-file-identity-mismatch",
            access_policy_code="prepared-file-access-policy-mismatch",
            inconclusive_code="prepared-file-revalidation-inconclusive",
        )
        fingerprint = _verify_bound_regular_file_at(
            prepared,
            PREPARED_FILE_CODES,
            dir_fd=parent_fd,
            basename=destination.name,
        )
        terminal_source, _ = _observe_bound_sibling(
            parent_fd,
            prepared,
            prepared.path,
        )
        if terminal_source != "absent":
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                "The private source name reappeared after publication: "
                f"{prepared.path}",
            )
    except (OSError, StoreSafetyError) as exc:
        raise StoreSafetyError(
            "destination-install-uncertain",
            "The recovered database was renamed into place, but final durability "
            f"or fingerprint validation is unconfirmed: {destination}: {exc}",
            details=_publication_details(
                "uncertain",
                prepared=prepared,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc
    return fingerprint


def _sqlite_descriptor_uri(
    fd: int,
    expected: os.stat_result,
    display_path: Path,
    *,
    mode: str,
    immutable: bool,
) -> str:
    descriptor_path = Path("/dev/fd") / str(fd)
    probe_fd: int | None = None
    try:
        descriptor = os.fstat(fd)
        probe_fd = os.open(
            descriptor_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor_path_stat = os.fstat(probe_fd)
        if (
            not stat.S_ISREG(descriptor.st_mode)
            or not stat.S_ISREG(descriptor_path_stat.st_mode)
            or not _same_identity(expected, descriptor)
            or not _same_identity(descriptor, descriptor_path_stat)
        ):
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                "The SQLite descriptor path does not identify the validated "
                f"object: {display_path}",
            )
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            "SQLite cannot bind the validated descriptor through "
            f"{descriptor_path}: {exc}",
        ) from exc
    finally:
        if probe_fd is not None:
            os.close(probe_fd)
    immutable_arg = "&immutable=1" if immutable else ""
    return f"file:{descriptor_path}?mode={mode}{immutable_arg}"


def _bound_sqlite_readonly_uri(
    source: _BoundRegularFile,
) -> str:
    return _sqlite_descriptor_uri(
        source.fd,
        source.opened,
        source.path,
        mode="ro",
        immutable=True,
    )


def _apply_committed_wal(
    main_payload: bytes,
    wal_payload: bytes,
    wal: dict[str, Any],
    source_path: Path,
) -> bytes:
    last_commit = int(wal.get("last_valid_commit_frame", 0))
    if last_commit == 0:
        return main_payload
    if len(main_payload) < 100 or main_payload[:16] != b"SQLite format 3\0":
        raise StoreSafetyError(
            "sqlite-recovery-failed",
            f"Recovery main database has an invalid SQLite header: {source_path}",
        )
    raw_main_page_size = struct.unpack(">H", main_payload[16:18])[0]
    main_page_size = 65536 if raw_main_page_size == 1 else raw_main_page_size
    page_size = int(wal["page_size"])
    if (
        main_page_size != page_size
        or len(main_payload) % page_size != 0
        or len(main_payload) < page_size
    ):
        raise StoreSafetyError(
            "wal-invalid",
            "The bound WAL page size does not match the complete main database: "
            f"{source_path}",
        )
    frame_size = 24 + page_size
    final_header_offset = 32 + (last_commit - 1) * frame_size
    final_database_pages = struct.unpack(
        ">I",
        wal_payload[final_header_offset + 4 : final_header_offset + 8],
    )[0]
    if final_database_pages == 0:
        raise StoreSafetyError(
            "wal-invalid",
            f"The selected final WAL frame is not a commit frame: {source_path}",
        )
    main_pages = len(main_payload) // page_size
    if final_database_pages > main_pages + last_commit:
        raise StoreSafetyError(
            "wal-invalid",
            "The committed WAL database size exceeds the bounded growth implied "
            f"by the main database and committed frame count: {source_path}",
        )
    recovered = bytearray(main_payload[: final_database_pages * page_size])
    if len(recovered) < final_database_pages * page_size:
        recovered.extend(b"\0" * (final_database_pages * page_size - len(recovered)))
    for index in range(last_commit):
        offset = 32 + index * frame_size
        page_number = struct.unpack(">I", wal_payload[offset : offset + 4])[0]
        if page_number <= final_database_pages:
            page_start = (page_number - 1) * page_size
            recovered[page_start : page_start + page_size] = wal_payload[
                offset + 24 : offset + frame_size
            ]
    return bytes(recovered)


def _bound_recovery_payload(
    store: _BoundRecoveryStore,
) -> bytes:
    _verify_bound_recovery_store(store)
    main = store.files[store.main_name]
    main_payload = _read_bound_file_bytes(
        main,
        PREPARED_FILE_CODES,
        max_bytes=main.opened.st_size,
        too_large_code="prepared-file-content-mismatch",
        dir_fd=store.directory.fd,
        basename=store.main_name,
    )
    wal_name = f"{store.main_name}-wal"
    wal_bound = store.files.get(wal_name)
    if wal_bound is None:
        recovered = main_payload
    else:
        wal_payload = _read_bound_file_bytes(
            wal_bound,
            PREPARED_FILE_CODES,
            max_bytes=wal_bound.opened.st_size,
            too_large_code="prepared-file-content-mismatch",
            dir_fd=store.directory.fd,
            basename=wal_name,
        )
        wal = _inspect_wal_payload(
            wal_payload,
            store.directory.path / wal_name,
        )
        recovered = _apply_committed_wal(
            main_payload,
            wal_payload,
            wal,
            store.directory.path / store.main_name,
        )
    _verify_bound_recovery_store(store)
    return recovered


def _verify_anonymous_recovery_file(
    bound: _BoundRegularFile,
    descriptor_path: Path,
) -> None:
    probe_fd: int | None = None
    try:
        descriptor_before = os.fstat(bound.fd)
        probe_fd = os.open(
            descriptor_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        probe = os.fstat(probe_fd)
        first_sha256 = _hash_fd(bound.fd)
        descriptor_between = os.fstat(bound.fd)
        second_sha256 = _hash_fd(bound.fd)
        descriptor_after = os.fstat(bound.fd)
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            "Cannot revalidate the anonymous descriptor-backed recovery image "
            f"for {bound.path}: {exc}",
        ) from exc
    finally:
        if probe_fd is not None:
            os.close(probe_fd)
    if (
        not stat.S_ISREG(descriptor_before.st_mode)
        or not stat.S_ISREG(probe.st_mode)
        or not _same_identity(bound.opened, descriptor_before)
        or not _same_identity(descriptor_before, probe)
        or not _same_identity(descriptor_before, descriptor_between)
        or not _same_identity(descriptor_between, descriptor_after)
    ):
        raise StoreSafetyError(
            "prepared-file-identity-mismatch",
            "Anonymous descriptor-backed recovery image identity changed for "
            f"{bound.path}",
        )
    baseline_access = _access_policy(bound.opened)
    if any(
        _access_policy(current) != baseline_access
        for current in (descriptor_before, probe, descriptor_between, descriptor_after)
    ):
        raise StoreSafetyError(
            "prepared-file-access-policy-mismatch",
            "Anonymous descriptor-backed recovery image access policy changed for "
            f"{bound.path}",
        )
    if (
        first_sha256 != bound.sha256
        or second_sha256 != bound.sha256
        or descriptor_before.st_size != bound.opened.st_size
        or descriptor_between.st_size != bound.opened.st_size
        or descriptor_after.st_size != bound.opened.st_size
    ):
        raise StoreSafetyError(
            "prepared-file-content-mismatch",
            "Anonymous descriptor-backed recovery image bytes changed for "
            f"{bound.path}",
        )


@contextmanager
def _anonymous_recovery_file(
    payload: bytes,
    source_path: Path,
) -> Iterator[_BoundRegularFile]:
    try:
        with tempfile.TemporaryFile(prefix="apple-notes-recovered-image-") as handle:
            fd = handle.fileno()
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            _write_all(fd, payload)
            os.fsync(fd)
            os.fchmod(fd, 0o600)
            opened = os.fstat(fd)
            bound = _BoundRegularFile(
                path=source_path,
                fd=fd,
                opened=opened,
                sha256=_hash_fd(fd),
            )
            descriptor_path = Path("/dev/fd") / str(fd)
            _verify_anonymous_recovery_file(bound, descriptor_path)
            try:
                yield bound
            except Exception:
                raise
            else:
                _verify_anonymous_recovery_file(bound, descriptor_path)
    except StoreSafetyError:
        raise
    except OSError as exc:
        raise StoreSafetyError(
            "sqlite-recovery-failed",
            "Cannot prepare the anonymous descriptor-backed recovery image for "
            f"{source_path}: {exc}",
        ) from exc


def _sqlite_backup_bytes_from_payload(
    payload: bytes,
    source_path: Path,
) -> bytes:
    """Let SQLite consume only an anonymous descriptor-backed recovery image."""

    with _anonymous_recovery_file(payload, source_path) as bound:
        source_uri = _bound_sqlite_readonly_uri(bound)
        return _sqlite_backup_bytes(source_uri, source_path)


def _sqlite_integrity_from_payload(
    payload: bytes,
    source_path: Path,
) -> dict[str, Any]:
    with _anonymous_recovery_file(payload, source_path) as bound:
        source_uri = _bound_sqlite_readonly_uri(bound)
        try:
            with closing(sqlite3.connect(source_uri, uri=True)) as conn:
                conn.execute("PRAGMA busy_timeout = 5000")
                rows = [
                    str(row[0])
                    for row in conn.execute("PRAGMA integrity_check").fetchall()
                ]
                journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
                page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        except sqlite3.Error as exc:
            raise StoreSafetyError(
                "sqlite-integrity-failed",
                f"SQLite could not validate recovered image for {source_path}: {exc}",
            ) from exc
    if rows != ["ok"]:
        raise StoreSafetyError(
            "sqlite-integrity-failed",
            f"SQLite integrity_check failed for {source_path}: {rows[:5]}",
        )
    return {
        "result": "ok",
        "check": "PRAGMA integrity_check",
        "journal_mode": journal_mode,
        "page_count": page_count,
    }


def _bound_recovery_integrity(
    store: _BoundRecoveryStore,
) -> dict[str, Any]:
    recovered_payload = _bound_recovery_payload(store)
    result = _sqlite_integrity_from_payload(
        recovered_payload,
        store.directory.path / store.main_name,
    )
    _verify_bound_recovery_store(store)
    return result


def _sqlite_backup_bytes(source_uri: str, source_path: Path) -> bytes:
    """Run the native SQLite backup API into memory and serialize its bytes."""

    library_path = ctypes.util.find_library("sqlite3")
    if library_path is None:
        raise StoreSafetyError(
            "sqlite-recovery-failed",
            "Cannot locate the native SQLite library required for "
            f"descriptor-bound backup of {source_path}",
        )
    try:
        library = ctypes.CDLL(library_path)
        open_v2 = library.sqlite3_open_v2
        close_v2 = library.sqlite3_close_v2
        error_message = library.sqlite3_errmsg
        backup_init = library.sqlite3_backup_init
        backup_step = library.sqlite3_backup_step
        backup_finish = library.sqlite3_backup_finish
        serialize = library.sqlite3_serialize
        sqlite_free = library.sqlite3_free
    except (AttributeError, OSError) as exc:
        raise StoreSafetyError(
            "sqlite-recovery-failed",
            "The native SQLite library lacks the required backup/serialize "
            f"interface for {source_path}: {exc}",
        ) from exc

    open_v2.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    open_v2.restype = ctypes.c_int
    close_v2.argtypes = [ctypes.c_void_p]
    close_v2.restype = ctypes.c_int
    error_message.argtypes = [ctypes.c_void_p]
    error_message.restype = ctypes.c_char_p
    backup_init.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    backup_init.restype = ctypes.c_void_p
    backup_step.argtypes = [ctypes.c_void_p, ctypes.c_int]
    backup_step.restype = ctypes.c_int
    backup_finish.argtypes = [ctypes.c_void_p]
    backup_finish.restype = ctypes.c_int
    serialize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_longlong),
        ctypes.c_uint,
    ]
    serialize.restype = ctypes.c_void_p
    sqlite_free.argtypes = [ctypes.c_void_p]
    sqlite_free.restype = None

    sqlite_ok = 0
    sqlite_done = 101
    sqlite_open_readonly = 0x00000001
    sqlite_open_readwrite = 0x00000002
    sqlite_open_create = 0x00000004
    sqlite_open_uri = 0x00000040
    source_db = ctypes.c_void_p()
    destination_db = ctypes.c_void_p()
    backup: int | None = None
    serialized: int | None = None

    def message(handle: ctypes.c_void_p) -> str:
        if not handle:
            return "unknown SQLite error"
        raw = error_message(handle)
        return raw.decode("utf-8", errors="replace") if raw else "unknown SQLite error"

    try:
        result = open_v2(
            os.fsencode(source_uri),
            ctypes.byref(source_db),
            sqlite_open_readonly | sqlite_open_uri,
            None,
        )
        if result != sqlite_ok:
            raise StoreSafetyError(
                "sqlite-recovery-failed",
                f"SQLite cannot open the bound source {source_path}: "
                f"{message(source_db)}",
            )
        result = open_v2(
            b":memory:",
            ctypes.byref(destination_db),
            sqlite_open_readwrite | sqlite_open_create,
            None,
        )
        if result != sqlite_ok:
            raise StoreSafetyError(
                "sqlite-recovery-failed",
                "SQLite cannot create the in-memory backup destination for "
                f"{source_path}: {message(destination_db)}",
            )
        backup = backup_init(destination_db, b"main", source_db, b"main")
        if not backup:
            raise StoreSafetyError(
                "sqlite-recovery-failed",
                f"SQLite cannot initialize backup of {source_path}: "
                f"{message(destination_db)}",
            )
        step_result = backup_step(backup, -1)
        finish_result = backup_finish(backup)
        backup = None
        if step_result != sqlite_done or finish_result != sqlite_ok:
            raise StoreSafetyError(
                "sqlite-recovery-failed",
                f"SQLite backup failed for {source_path}: {message(destination_db)}",
            )
        byte_count = ctypes.c_longlong()
        serialized = serialize(
            destination_db,
            b"main",
            ctypes.byref(byte_count),
            0,
        )
        if not serialized or byte_count.value <= 0:
            raise StoreSafetyError(
                "sqlite-recovery-failed",
                f"SQLite could not serialize the standalone backup of {source_path}",
            )
        return ctypes.string_at(serialized, byte_count.value)
    finally:
        if backup is not None:
            backup_finish(backup)
        if serialized is not None:
            sqlite_free(serialized)
        if destination_db:
            close_v2(destination_db)
        if source_db:
            close_v2(source_db)


def _write_standalone_backup_payload(
    payload: bytes,
    output: Path,
) -> dict[str, Any]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        output_fd = os.open(output, flags, 0o600)
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot exclusively create standalone recovery output {output}: {exc}",
        ) from exc
    created = os.fstat(output_fd)
    try:
        path_before = os.stat(output, follow_symlinks=False)
        if not _same_identity(created, path_before):
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                f"Standalone recovery output was replaced before backup: {output}",
            )
        os.lseek(output_fd, 0, os.SEEK_SET)
        os.ftruncate(output_fd, 0)
        _write_all(output_fd, payload)
        os.fsync(output_fd)
        os.fchmod(output_fd, 0o600)
        descriptor_after = os.fstat(output_fd)
        path_after = os.stat(output, follow_symlinks=False)
        if (
            not stat.S_ISREG(descriptor_after.st_mode)
            or not _same_identity(created, descriptor_after)
            or not _same_identity(descriptor_after, path_after)
        ):
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                f"Standalone recovery output was replaced during backup: {output}",
            )
        if _access_policy(descriptor_after) != _access_policy(path_after):
            raise StoreSafetyError(
                "prepared-file-access-policy-mismatch",
                f"Standalone recovery output access policy changed during backup: "
                f"{output}",
            )
        sha256 = _hash_fd(output_fd)
        return {
            "path": output,
            "sha256": sha256,
            "size": descriptor_after.st_size,
            "identity": _identity(descriptor_after),
            "access_policy": _access_policy(descriptor_after),
        }
    except StoreSafetyError:
        raise
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot revalidate standalone recovery output {output}: {exc}",
        ) from exc
    finally:
        os.close(output_fd)


def _backup_bound_store_to_standalone(
    source: _BoundRecoveryStore,
    output: Path,
) -> dict[str, Any]:
    recovered_payload = _bound_recovery_payload(source)
    payload = _sqlite_backup_bytes_from_payload(
        recovered_payload,
        source.directory.path / source.main_name,
    )
    _verify_bound_recovery_store(source)
    return _write_standalone_backup_payload(payload, output)


def _backup_bound_regular_to_standalone(
    source: _BoundRegularFile,
    output: Path,
) -> dict[str, Any]:
    """Back up an already validated standalone file without sidecar discovery."""

    _verify_bound_regular_file(source, PREPARED_FILE_CODES)
    source_payload = _read_bound_file_bytes(
        source,
        PREPARED_FILE_CODES,
        max_bytes=source.opened.st_size,
        too_large_code="prepared-file-content-mismatch",
    )
    payload = _sqlite_backup_bytes_from_payload(source_payload, source.path)
    _verify_bound_regular_file(source, PREPARED_FILE_CODES)
    result = _write_standalone_backup_payload(payload, output)
    _verify_bound_regular_file(source, PREPARED_FILE_CODES)
    return result


def _backup_sqlite_to_standalone(
    source: Union[_BoundRegularFile, _BoundRecoveryStore],
    output: Path,
) -> dict[str, Any]:
    if isinstance(source, _BoundRecoveryStore):
        return _backup_bound_store_to_standalone(source, output)
    source_receipt = _verify_bound_regular_file(source, PREPARED_FILE_CODES)
    with _bind_recovery_store(source.path) as store:
        _assert_bound_matches_receipt(
            store.files[store.main_name],
            source_receipt,
        )
        result = _backup_bound_store_to_standalone(store, output)
    _verify_bound_regular_file(source, PREPARED_FILE_CODES)
    return result


def _recover_validated_clone_to_standalone(
    recovered_main: Path,
    out: Path,
    *,
    source_db: Path,
    recovery_evidence: dict[str, Any],
    source_integrity: dict[str, Any],
    source_revalidate: Callable[[], None] | None = None,
    source_backup: Callable[[Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if source_backup is None:
        with _bind_recovery_store(recovered_main) as recovered_store:
            _require_authoritative_wal(recovered_store, recovery_evidence)

            def revalidate_bound_source() -> None:
                _verify_bound_recovery_store(recovered_store)
                _require_authoritative_wal(recovered_store, recovery_evidence)

            return _recover_validated_clone_to_standalone(
                recovered_main,
                out,
                source_db=source_db,
                recovery_evidence=recovery_evidence,
                source_integrity=source_integrity,
                source_revalidate=revalidate_bound_source,
                source_backup=lambda output: _backup_sqlite_to_standalone(
                    recovered_store,
                    output,
                ),
            )
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
    if source_revalidate is not None:
        source_revalidate()
    temp_receipt = source_backup(temp_out)
    if source_revalidate is not None:
        source_revalidate()
    with _bind_regular_file(temp_out, PREPARED_FILE_CODES) as prepared:
        _assert_bound_matches_receipt(prepared, temp_receipt)
        output_integrity = _sqlite_integrity(prepared)
        _verify_bound_regular_file(prepared, PREPARED_FILE_CODES)
        try:
            os.fsync(prepared.fd)
        except OSError as exc:
            raise StoreSafetyError(
                "destination-install-failed",
                "The prepared recovered database could not be made durable "
                f"before publication: {temp_out}: {exc}",
                details=_publication_details(
                    "uncommitted",
                    prepared=prepared,
                    destination=out,
                    retry_safe=True,
                ),
            ) from exc
        fingerprint = _publish_file_no_replace(prepared, out)
    return {
        "source_db": source_db,
        "standalone_db": out,
        "source_recovery": recovery_evidence,
        "source_integrity": source_integrity,
        "output_integrity": output_integrity,
        "sha256": fingerprint["sha256"],
        "size": fingerprint["size"],
        "identity": fingerprint["identity"],
        "access_policy": fingerprint["access_policy"],
    }


def _recover_to_standalone(src: Path, out: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apple-notes-merge-") as temp_dir:
        clone = _make_recovery_clone(src, Path(temp_dir) / "store")
        with _bind_recovery_store(
            clone.main_path,
            creation_receipt=clone.receipt,
        ) as recovered_store:
            _require_authoritative_wal(recovered_store, clone.evidence)
            source_integrity = _bound_recovery_integrity(recovered_store)

            def revalidate_bound_source() -> None:
                _assert_recovery_store_matches_receipt(
                    recovered_store,
                    clone.receipt,
                )
                _require_authoritative_wal(recovered_store, clone.evidence)

            return _recover_validated_clone_to_standalone(
                clone.main_path,
                out,
                source_db=src,
                recovery_evidence=clone.evidence,
                source_integrity=source_integrity,
                source_revalidate=revalidate_bound_source,
                source_backup=lambda output: _backup_sqlite_to_standalone(
                    recovered_store,
                    output,
                ),
            )


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
    try:
        with _create_bound_directory(
            partial,
            retain_failure_receipt=True,
        ) as bound_root:
            store_dir = partial / "group.com.apple.notes"
            captured = _capture_database_files(
                paths.group_container / NOTE_STORE_MAIN,
                store_dir,
            )
            _verify_bound_directory(bound_root)
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
                    "Notes.app started before the writeback-grade snapshot was "
                    "finalized",
                )
            manifest_receipt = _write_json_atomic(
                partial / SNAPSHOT_MANIFEST,
                manifest,
            )
            expected_names = {
                str(record["basename"]): stat.S_IFREG for record in captured
            }
            root_receipt = _scan_exact_directory_entries(
                partial,
                {
                    "group.com.apple.notes": stat.S_IFDIR,
                    SNAPSHOT_MANIFEST: stat.S_IFREG,
                },
                missing_code="prepared-directory-identity-mismatch",
                mismatch_code="prepared-file-set-mismatch",
                bound_identity=_identity(bound_root.opened),
                bound_access_policy=_access_policy(bound_root.opened),
            )
            store_receipt = _scan_exact_directory_entries(
                store_dir,
                expected_names,
                missing_code="prepared-file-missing",
                mismatch_code="prepared-file-set-mismatch",
            )
            file_receipts = {
                Path("group.com.apple.notes") / str(record["basename"]): record["copy"]
                for record in captured
            }
            with _bind_prepared_regular_files(
                partial,
                manifest_name=SNAPSHOT_MANIFEST,
                manifest_payload=manifest,
                manifest_receipt=manifest_receipt,
                file_receipts=file_receipts,
            ) as prepared_files:

                def verify_before_snapshot_rename() -> None:
                    _scan_exact_directory_entries(
                        store_dir,
                        expected_names,
                        missing_code="prepared-file-missing",
                        mismatch_code="prepared-file-set-mismatch",
                        bound_identity=store_receipt["identity"],
                        bound_access_policy=store_receipt["access_policy"],
                    )
                    _revalidate_published_regular_files(
                        partial,
                        prepared_files,
                        manifest_name=SNAPSHOT_MANIFEST,
                        manifest_payload=manifest,
                        manifest_receipt=manifest_receipt,
                        file_receipts=file_receipts,
                    )

                _verify_bound_directory(bound_root)
                _publish_directory_no_replace(
                    partial,
                    destination,
                    binding=bound_root,
                    before_rename=verify_before_snapshot_rename,
                )
                try:
                    _scan_exact_directory_entries(
                        destination,
                        {
                            "group.com.apple.notes": stat.S_IFDIR,
                            SNAPSHOT_MANIFEST: stat.S_IFREG,
                        },
                        missing_code="prepared-directory-identity-mismatch",
                        mismatch_code="prepared-file-set-mismatch",
                        bound_identity=root_receipt["identity"],
                        bound_access_policy=root_receipt["access_policy"],
                    )
                    _scan_exact_directory_entries(
                        destination / "group.com.apple.notes",
                        expected_names,
                        missing_code="prepared-file-missing",
                        mismatch_code="prepared-file-set-mismatch",
                        bound_identity=store_receipt["identity"],
                        bound_access_policy=store_receipt["access_policy"],
                    )
                    _revalidate_published_regular_files(
                        destination,
                        prepared_files,
                        manifest_name=SNAPSHOT_MANIFEST,
                        manifest_payload=manifest,
                        manifest_receipt=manifest_receipt,
                        file_receipts=file_receipts,
                    )
                except Exception as exc:
                    raise StoreSafetyError(
                        "destination-install-uncertain",
                        "Snapshot publication committed, but the exact prepared "
                        f"tree could not be revalidated: {destination}: {exc}",
                        details=_publication_details(
                            "uncertain",
                            prepared=None,
                            destination=destination,
                            retry_safe=False,
                        ),
                    ) from exc
    except StoreSafetyError:
        raise

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


@contextmanager
def _validated_snapshot_artifact(
    snapshot_dir: Path,
) -> Iterator[_ValidatedSnapshotArtifact]:
    """Bind snapshot inputs and expose only a private validated recovery clone."""

    manifest_path = snapshot_dir / SNAPSHOT_MANIFEST
    store_dir = snapshot_dir / "group.com.apple.notes"
    with (
        tempfile.TemporaryDirectory(
            prefix="apple-notes-snapshot-validation-"
        ) as temp_dir,
        ExitStack() as stack,
    ):
        try:
            manifest_bound = stack.enter_context(
                _bind_regular_file(manifest_path, SNAPSHOT_FILE_CODES)
            )
        except StoreSafetyError as exc:
            if exc.code == SNAPSHOT_FILE_CODES.missing:
                raise StoreSafetyError(
                    "manifest-missing",
                    f"Manifest is missing: {manifest_path}",
                ) from exc
            raise
        manifest = _load_bound_manifest(
            manifest_bound,
            SNAPSHOT_FILE_CODES,
            SNAPSHOT_SCHEMA,
        )
        rows = manifest.get("files")
        if (
            not isinstance(rows, list)
            or not rows
            or any(not isinstance(row, dict) for row in rows)
        ):
            raise StoreSafetyError(
                "manifest-invalid",
                "Snapshot manifest has no files",
            )
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
        expected_store_types = {str(name): stat.S_IFREG for name in expected_names}
        store_directory = _scan_exact_directory_entries(
            store_dir,
            expected_store_types,
            missing_code="snapshot-missing",
            mismatch_code="snapshot-file-set-mismatch",
        )
        manifest_by_name = {row.get("basename"): row for row in rows}
        for basename, row in manifest_by_name.items():
            expected_relative = Path("group.com.apple.notes") / str(basename)
            if (
                basename not in NOTE_STORE_BASENAMES
                or Path(str(row.get("relative_path"))) != expected_relative
            ):
                raise StoreSafetyError(
                    "manifest-invalid",
                    f"Manifest path is not canonical for {basename}: "
                    f"{row.get('relative_path')}",
                )

        bound_files: dict[str, _BoundRegularFile] = {}
        for basename in NOTE_STORE_BASENAMES:
            if basename in expected_names:
                bound_files[basename] = stack.enter_context(
                    _bind_regular_file(
                        store_dir / basename,
                        SNAPSHOT_FILE_CODES,
                    )
                )
        clone = _make_recovery_clone_from_bound(
            bound_files,
            Path(temp_dir) / "store",
            SNAPSHOT_FILE_CODES,
        )
        for record in clone.evidence["capture"]:
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
        validated_recovery = Path(temp_dir) / "validated-recovery.sqlite"
        with _bind_recovery_store(
            clone.main_path,
            creation_receipt=clone.receipt,
        ) as recovered_store:
            _require_authoritative_wal(recovered_store, clone.evidence)
            sqlite_integrity = _bound_recovery_integrity(recovered_store)
            validated_recovery_receipt = _backup_sqlite_to_standalone(
                recovered_store,
                validated_recovery,
            )
        validated_recovery_bound = stack.enter_context(
            _bind_regular_file(
                validated_recovery,
                PREPARED_FILE_CODES,
            )
        )
        validated_recovery_integrity = _sqlite_integrity(validated_recovery_bound)
        _assert_bound_matches_receipt(
            validated_recovery_bound,
            validated_recovery_receipt,
        )

        def revalidate_recovery_clone() -> None:
            _assert_bound_matches_receipt(
                validated_recovery_bound,
                validated_recovery_receipt,
            )

        def backup_recovery_clone(output: Path) -> dict[str, Any]:
            _assert_bound_matches_receipt(
                validated_recovery_bound,
                validated_recovery_receipt,
            )
            result = _backup_bound_regular_to_standalone(
                validated_recovery_bound,
                output,
            )
            _assert_bound_matches_receipt(
                validated_recovery_bound,
                validated_recovery_receipt,
            )
            return result

        _scan_exact_directory_entries(
            store_dir,
            expected_store_types,
            missing_code="snapshot-missing",
            mismatch_code="snapshot-file-set-mismatch",
            bound_identity=store_directory["identity"],
            bound_access_policy=store_directory["access_policy"],
        )
        verified = [
            _verify_bound_regular_file(
                bound_files[basename],
                SNAPSHOT_FILE_CODES,
            )
            for basename in NOTE_STORE_BASENAMES
            if basename in bound_files
        ]
        manifest_integrity = _verify_bound_regular_file(
            manifest_bound,
            SNAPSHOT_FILE_CODES,
        )
        source_integrity = {
            "protected_properties": {
                "object_identity": ["device", "inode", "file_type"],
                "content_stability": ["sha256", "size"],
                "access_policy": ["mode", "uid", "gid", "flags"],
                "benign_metadata_transitions": [
                    "mtime_ns",
                    "ctime_ns",
                    "link_count",
                ],
            },
            "manifest": manifest_integrity,
            "files": verified,
        }
        public_result = {
            "snapshot_dir": snapshot_dir,
            "manifest": manifest,
            "verified_files": verified,
            "sidecar_consistency": clone.evidence["sidecars"],
            "sqlite_validation": sqlite_integrity,
            "validated_recovery_integrity": validated_recovery_integrity,
            "source_integrity": source_integrity,
        }
        yield _ValidatedSnapshotArtifact(
            public_result=public_result,
            recovered_main=validated_recovery,
            recovery_evidence=clone.evidence,
            source_integrity=source_integrity,
            revalidate_recovery_clone=revalidate_recovery_clone,
            backup_recovery_clone=backup_recovery_clone,
        )


def validate_snapshot(snapshot_dir: Path) -> dict[str, Any]:
    with _validated_snapshot_artifact(snapshot_dir) as artifact:
        return artifact.public_result


def merge_db(src: Path, out: Path | None) -> dict[str, Any]:
    output = out or src.with_name("NoteStore-merged-for-analysis.sqlite")
    return _recover_to_standalone(src, output)


def recover_snapshot(snapshot_dir: Path, out: Path) -> dict[str, Any]:
    source = snapshot_dir / "group.com.apple.notes" / NOTE_STORE_MAIN
    with _validated_snapshot_artifact(snapshot_dir) as artifact:
        validation = artifact.public_result
        recovered = _recover_validated_clone_to_standalone(
            artifact.recovered_main,
            out,
            source_db=source,
            recovery_evidence=artifact.recovery_evidence,
            source_integrity=validation["sqlite_validation"],
            source_revalidate=artifact.revalidate_recovery_clone,
            source_backup=artifact.backup_recovery_clone,
        )
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
    try:
        with _create_bound_directory(
            partial,
            retain_failure_receipt=True,
        ) as bound_root:
            staged_db = partial / NOTE_STORE_MAIN
            recovery = _recover_to_standalone(src, staged_db)
            fingerprint = {
                "path": staged_db,
                "sha256": recovery["sha256"],
                "size": recovery["size"],
                "identity": recovery["identity"],
                "access_policy": recovery["access_policy"],
            }
            _verify_bound_directory(bound_root)
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
            manifest_receipt = _write_json_atomic(
                partial / PATCH_MANIFEST,
                manifest,
            )
            root_receipt = _scan_exact_directory_entries(
                partial,
                {
                    NOTE_STORE_MAIN: stat.S_IFREG,
                    PATCH_MANIFEST: stat.S_IFREG,
                },
                missing_code="prepared-directory-identity-mismatch",
                mismatch_code="prepared-file-set-mismatch",
                bound_identity=_identity(bound_root.opened),
                bound_access_policy=_access_policy(bound_root.opened),
            )
            file_receipts = {Path(NOTE_STORE_MAIN): fingerprint}
            with _bind_prepared_regular_files(
                partial,
                manifest_name=PATCH_MANIFEST,
                manifest_payload=manifest,
                manifest_receipt=manifest_receipt,
                file_receipts=file_receipts,
            ) as prepared_files:

                def verify_before_stage_rename() -> None:
                    _revalidate_published_regular_files(
                        partial,
                        prepared_files,
                        manifest_name=PATCH_MANIFEST,
                        manifest_payload=manifest,
                        manifest_receipt=manifest_receipt,
                        file_receipts=file_receipts,
                    )

                _verify_bound_directory(bound_root)
                _publish_directory_no_replace(
                    partial,
                    dest,
                    binding=bound_root,
                    before_rename=verify_before_stage_rename,
                )
                try:
                    _scan_exact_directory_entries(
                        dest,
                        {
                            NOTE_STORE_MAIN: stat.S_IFREG,
                            PATCH_MANIFEST: stat.S_IFREG,
                        },
                        missing_code="prepared-directory-identity-mismatch",
                        mismatch_code="prepared-file-set-mismatch",
                        bound_identity=root_receipt["identity"],
                        bound_access_policy=root_receipt["access_policy"],
                    )
                    _revalidate_published_regular_files(
                        dest,
                        prepared_files,
                        manifest_name=PATCH_MANIFEST,
                        manifest_payload=manifest,
                        manifest_receipt=manifest_receipt,
                        file_receipts=file_receipts,
                    )
                except Exception as exc:
                    raise StoreSafetyError(
                        "destination-install-uncertain",
                        "Patch-stage publication committed, but the exact prepared "
                        f"tree could not be revalidated: {dest}: {exc}",
                        details=_publication_details(
                            "uncertain",
                            prepared=None,
                            destination=dest,
                            retry_safe=False,
                        ),
                    ) from exc
    except StoreSafetyError:
        raise
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
    with ExitStack() as stack:
        manifest_bound = stack.enter_context(
            _bind_regular_file(
                stage_dir / PATCH_MANIFEST,
                PATCH_FILE_CODES,
            )
        )
        manifest = _load_bound_manifest(
            manifest_bound,
            PATCH_FILE_CODES,
            PATCH_SCHEMA,
        )
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
        database_bound = stack.enter_context(
            _bind_regular_file(
                stage_dir / NOTE_STORE_MAIN,
                PATCH_FILE_CODES,
            )
        )
        with tempfile.TemporaryDirectory(
            prefix="apple-notes-stage-validation-"
        ) as temp_dir:
            clone = _make_recovery_clone_from_bound(
                {NOTE_STORE_MAIN: database_bound},
                Path(temp_dir) / "store",
                PATCH_FILE_CODES,
            )
            fingerprint = clone.evidence["capture"][0]["source"]
            if fingerprint["sha256"] != database.get("sha256") or fingerprint[
                "size"
            ] != database.get("size"):
                raise StoreSafetyError(
                    "patch-content-mismatch",
                    "Patch database no longer matches its manifest",
                )
            with _bind_recovery_store(
                clone.main_path,
                creation_receipt=clone.receipt,
            ) as recovered_store:
                _assert_recovery_store_matches_receipt(
                    recovered_store,
                    clone.receipt,
                )
            integrity = _sqlite_integrity(database_bound)
        _scan_exact_directory_entries(
            stage_dir,
            expected_stage_types,
            missing_code="stage-missing",
            mismatch_code="patch-file-set-mismatch",
            bound_identity=stage_directory["identity"],
            bound_access_policy=stage_directory["access_policy"],
        )
        database_integrity = _verify_bound_regular_file(
            database_bound,
            PATCH_FILE_CODES,
        )
        manifest_integrity = _verify_bound_regular_file(
            manifest_bound,
            PATCH_FILE_CODES,
        )
        return {
            "stage_dir": stage_dir,
            "manifest": manifest,
            "fingerprint": fingerprint,
            "sqlite_validation": integrity,
            "source_integrity": {
                "protected_properties": {
                    "object_identity": ["device", "inode", "file_type"],
                    "content_stability": ["sha256", "size"],
                    "access_policy": ["mode", "uid", "gid", "flags"],
                    "benign_metadata_transitions": [
                        "mtime_ns",
                        "ctime_ns",
                        "link_count",
                    ],
                },
                "manifest": manifest_integrity,
                "database": database_integrity,
            },
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
        payload = {
            "error": str(exc),
            "error_code": exc.code,
            "command": args.command,
        }
        if exc.details:
            payload["details"] = exc.details
        emit_json(payload)
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
