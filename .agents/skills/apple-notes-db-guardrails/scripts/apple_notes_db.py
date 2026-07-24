#!/usr/bin/env python3
"""Audit, recover, stage, and verify Apple Notes SQLite stores safely."""

from __future__ import annotations

import argparse
import ctypes
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
from typing import Any, Callable, Iterable, Iterator


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
        return [self.group_container / name for name in NOTE_STORE_BASENAMES]


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


@dataclass
class _BoundDirectory:
    path: Path
    fd: int
    opened: os.stat_result
    parent_opened: os.stat_result


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


def _publish_directory_no_replace(
    source: Path,
    destination: Path,
    *,
    binding: _BoundDirectory | None = None,
    before_rename: Callable[[], None] | None = None,
) -> None:
    if binding is not None:
        _verify_bound_directory(binding, path=source)
        source_before = os.fstat(binding.fd)
    else:
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
    if before_rename is not None:
        before_rename()
    if binding is not None:
        _verify_bound_directory(binding, path=source)

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
    if binding is not None:
        try:
            _verify_bound_directory(binding, path=destination)
        except StoreSafetyError as exc:
            raise StoreSafetyError(
                "destination-install-uncertain",
                "The directory was published, but its creation-time descriptor "
                f"cannot be rebound to the destination: {destination}: {exc}",
            ) from exc
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


def _verify_bound_regular_file(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    target = path or bound.path

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
            return os.stat(target, follow_symlinks=False)
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


@contextmanager
def _bind_regular_file(
    path: Path,
    codes: _FileProtectionCodes,
) -> Iterator[_BoundRegularFile]:
    try:
        fd, opened = _open_regular_readonly(path)
    except StoreSafetyError as exc:
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
        )
        _verify_bound_regular_file(bound, codes)
        yield bound
    finally:
        os.close(fd)


def _read_bound_file_bytes(
    bound: _BoundRegularFile,
    codes: _FileProtectionCodes,
    *,
    max_bytes: int,
    too_large_code: str,
    path: Path | None = None,
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
    _verify_bound_regular_file(bound, codes, path=path)
    return bytes(payload)


@contextmanager
def _create_bound_directory(path: Path) -> Iterator[_BoundDirectory]:
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
        os.close(parent_fd)
        if not created_and_bound and fd is not None:
            os.close(fd)
    assert fd is not None
    binding = _BoundDirectory(
        path=path,
        fd=fd,
        opened=os.fstat(fd),
        parent_opened=parent_opened,
    )
    try:
        _verify_bound_directory(binding)
        yield binding
    finally:
        os.close(fd)


def _verify_bound_directory(
    binding: _BoundDirectory,
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    target = path or binding.path
    try:
        descriptor = os.fstat(binding.fd)
        path_stat = os.stat(target, follow_symlinks=False)
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


def _remove_bound_directory_if_owned(
    binding: _BoundDirectory | None,
    path: Path,
) -> bool:
    """Remove only the created directory object through bound descriptors."""

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
            return False
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            "Cannot prove ownership of a prepared directory without its "
            f"creation receipt; preserving {path}",
            details=recovery_details,
        )

    parent_fd: int | None = None
    root_fd: int | None = None
    try:
        try:
            parent_fd = os.open(path.parent, _directory_open_flags())
            parent_descriptor = os.fstat(parent_fd)
            parent_path = os.stat(path.parent, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise StoreSafetyError(
                "prepared-directory-missing",
                f"Prepared-directory parent is missing during cleanup: {path.parent}",
            ) from exc
        except PermissionError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Prepared-directory parent is unreadable during cleanup: "
                f"{path.parent}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Cannot bind prepared-directory parent for cleanup: "
                f"{path.parent}: {exc}",
            ) from exc
        if (
            not stat.S_ISDIR(parent_descriptor.st_mode)
            or not stat.S_ISDIR(parent_path.st_mode)
            or not _same_identity(binding.parent_opened, parent_descriptor)
            or not _same_identity(parent_descriptor, parent_path)
        ):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                f"Prepared-directory parent identity changed before cleanup: "
                f"{path.parent}",
            )
        try:
            root_path_before = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            root_fd = os.open(
                path.name,
                _directory_open_flags(),
                dir_fd=parent_fd,
            )
            root_descriptor = os.fstat(root_fd)
            root_path_after = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise StoreSafetyError(
                "prepared-directory-missing",
                f"Prepared directory is missing during cleanup: {path}",
            ) from exc
        except PermissionError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Prepared directory is unreadable during cleanup: {path}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Cannot bind prepared directory for cleanup: {path}: {exc}",
            ) from exc
        if (
            not stat.S_ISDIR(root_path_before.st_mode)
            or not stat.S_ISDIR(root_descriptor.st_mode)
            or not stat.S_ISDIR(root_path_after.st_mode)
            or not _same_identity(binding.opened, root_path_before)
            or not _same_identity(root_path_before, root_descriptor)
            or not _same_identity(root_descriptor, root_path_after)
        ):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                f"Prepared directory identity changed before cleanup: {path}",
            )
        _remove_bound_directory_contents(root_fd, path)

        try:
            root_before_remove = os.fstat(root_fd)
            current_root = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise StoreSafetyError(
                "prepared-directory-missing",
                f"Prepared-directory root name disappeared during cleanup: {path}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Cannot revalidate prepared-directory root before removal: "
                f"{path}: {exc}",
            ) from exc
        if (
            not stat.S_ISDIR(root_before_remove.st_mode)
            or not stat.S_ISDIR(current_root.st_mode)
            or not _same_identity(binding.opened, root_before_remove)
            or not _same_identity(root_before_remove, current_root)
        ):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                "Prepared-directory root name no longer identifies the owned "
                f"directory; preserving the current namespace: {path}",
            )
        os.rmdir(path.name, dir_fd=parent_fd)
        root_after_remove = os.fstat(root_fd)
        try:
            replacement = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            replacement = None
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Cannot prove the prepared-directory root-name transition: "
                f"{path}: {exc}",
            ) from exc
        if not _same_identity(root_before_remove, root_after_remove):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                f"Prepared-directory descriptor identity changed during removal: "
                f"{path}",
            )
        if replacement is not None:
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                "A different object occupies the prepared-directory root name "
                f"after cleanup; preserving it: {path}",
            )
        os.fsync(parent_fd)
        return True
    except StoreSafetyError as exc:
        details = dict(recovery_details)
        details.update(exc.details)
        raise StoreSafetyError(
            exc.code,
            str(exc),
            details=details,
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Prepared-directory cleanup is inconclusive; preserving recovery "
            f"locators for {path}: {exc}",
            details=recovery_details,
        ) from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _remove_bound_directory_contents(
    directory_fd: int,
    display_path: Path,
) -> None:
    """Delete regular files and directories through an already-bound root."""

    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Cannot list bound prepared directory during cleanup: "
            f"{display_path}: {exc}",
        ) from exc
    for name in names:
        entry_path = display_path / name
        try:
            before = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise StoreSafetyError(
                "prepared-file-missing",
                f"Prepared cleanup entry disappeared: {entry_path}",
            ) from exc
        except OSError as exc:
            raise StoreSafetyError(
                "prepared-directory-revalidation-inconclusive",
                f"Cannot inspect prepared cleanup entry {entry_path}: {exc}",
            ) from exc

        if stat.S_ISREG(before.st_mode):
            _remove_bound_regular_cleanup_entry(
                directory_fd,
                name,
                entry_path,
            )
            continue
        if stat.S_ISDIR(before.st_mode):
            _remove_bound_directory_cleanup_entry(
                directory_fd,
                name,
                entry_path,
                before,
            )
            continue
        raise StoreSafetyError(
            "prepared-file-set-mismatch",
            f"Refusing to remove an unbound non-regular cleanup entry: {entry_path}",
        )


def _remove_bound_regular_cleanup_entry(
    parent_fd: int,
    name: str,
    display_path: Path,
) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "prepared-file-missing",
            f"Prepared cleanup file disappeared: {display_path}",
        ) from exc
    except PermissionError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Prepared cleanup file is unreadable: {display_path}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot remove prepared cleanup file {display_path}: {exc}",
        ) from exc


def _remove_bound_directory_cleanup_entry(
    parent_fd: int,
    name: str,
    display_path: Path,
    before: os.stat_result,
) -> None:
    fd: int | None = None
    try:
        fd = os.open(
            name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        descriptor = os.fstat(fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(descriptor.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or not _same_identity(before, descriptor)
            or not _same_identity(descriptor, current)
        ):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                f"Prepared cleanup directory identity changed: {display_path}",
            )
        _remove_bound_directory_contents(fd, display_path)
        descriptor_before_remove = os.fstat(fd)
        current_before_remove = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not _same_identity(
            descriptor, descriptor_before_remove
        ) or not _same_identity(descriptor_before_remove, current_before_remove):
            raise StoreSafetyError(
                "prepared-directory-identity-mismatch",
                "Prepared cleanup directory name no longer identifies the "
                f"bound object: {display_path}",
            )
        os.rmdir(name, dir_fd=parent_fd)
    except StoreSafetyError:
        raise
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "prepared-directory-missing",
            f"Prepared cleanup directory disappeared: {display_path}",
        ) from exc
    except PermissionError as exc:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Prepared cleanup directory is unreadable: {display_path}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-directory-revalidation-inconclusive",
            f"Cannot remove prepared cleanup directory {display_path}: {exc}",
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)


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
) -> dict[str, Any]:
    current = _verify_bound_regular_file(
        bound,
        PREPARED_FILE_CODES,
        path=path,
    )
    if current["identity"] != receipt.get("identity"):
        raise StoreSafetyError(
            "prepared-file-identity-mismatch",
            f"Prepared file identity differs from its creation receipt: "
            f"{path or bound.path}",
        )
    if current["access_policy"] != receipt.get("access_policy"):
        raise StoreSafetyError(
            "prepared-file-access-policy-mismatch",
            f"Prepared file access policy differs from its creation receipt: "
            f"{path or bound.path}",
        )
    if current["sha256"] != receipt.get("sha256") or current["size"] != receipt.get(
        "size"
    ):
        raise StoreSafetyError(
            "prepared-file-content-mismatch",
            f"Prepared file bytes differ from its creation receipt: "
            f"{path or bound.path}",
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


def _make_recovery_clone_from_bound(
    files: dict[str, _BoundRegularFile],
    destination: Path,
    codes: _FileProtectionCodes,
) -> tuple[Path, dict[str, Any]]:
    """Copy an already-bound store without reopening mutable source paths."""

    if NOTE_STORE_MAIN not in files:
        raise StoreSafetyError(
            "manifest-invalid",
            "The bound recovery file set has no main SQLite database",
        )
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    records: list[dict[str, Any]] = []
    for basename in NOTE_STORE_BASENAMES:
        bound = files.get(basename)
        if bound is None:
            continue
        source = _verify_bound_regular_file(bound, codes)
        copied = _copy_fd(bound.fd, destination / basename)
        if copied["sha256"] != bound.sha256 or copied["size"] != bound.opened.st_size:
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


def _publication_details(
    state: str,
    *,
    prepared: Path | None,
    destination: Path,
    retry_safe: bool,
) -> dict[str, Any]:
    locators: dict[str, str] = {"destination": str(destination)}
    if prepared is not None and _lexists(prepared):
        locators["prepared"] = str(prepared)
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


def _remove_bound_prepared_link(
    prepared: _BoundRegularFile,
    destination: Path,
    parent_fd: int,
    *,
    installed_link_count: int,
) -> None:
    """Remove the exact private leaf and prove its link-count transition."""

    try:
        descriptor_before = os.fstat(prepared.fd)
        prepared_before = os.stat(
            prepared.path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        destination_before = os.stat(
            destination.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "prepared-file-missing",
            f"A required publication link is missing before cleanup: "
            f"prepared={prepared.path}, destination={destination}",
        ) from exc
    except PermissionError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"A publication link is unreadable before cleanup: "
            f"prepared={prepared.path}, destination={destination}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot bind publication links before cleanup: "
            f"prepared={prepared.path}, destination={destination}: {exc}",
        ) from exc
    if (
        not stat.S_ISREG(descriptor_before.st_mode)
        or not stat.S_ISREG(prepared_before.st_mode)
        or not stat.S_ISREG(destination_before.st_mode)
        or not _same_identity(prepared.opened, descriptor_before)
        or not _same_identity(descriptor_before, prepared_before)
        or not _same_identity(descriptor_before, destination_before)
    ):
        raise StoreSafetyError(
            "prepared-file-identity-mismatch",
            "The private or destination publication leaf no longer identifies "
            f"the prepared object: prepared={prepared.path}, "
            f"destination={destination}",
        )
    baseline_access = _access_policy(prepared.opened)
    if (
        _access_policy(descriptor_before) != baseline_access
        or _access_policy(prepared_before) != baseline_access
        or _access_policy(destination_before) != baseline_access
    ):
        raise StoreSafetyError(
            "prepared-file-access-policy-mismatch",
            "The private or destination publication leaf changed access policy "
            f"before cleanup: prepared={prepared.path}, "
            f"destination={destination}",
        )
    if descriptor_before.st_nlink != installed_link_count:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            "The prepared object's link count changed before private-link "
            f"cleanup: {prepared.path}",
        )

    os.unlink(prepared.path.name, dir_fd=parent_fd)

    try:
        descriptor_after = os.fstat(prepared.fd)
        destination_after = os.stat(
            destination.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise StoreSafetyError(
            "prepared-file-missing",
            f"The committed destination disappeared during private-link cleanup: "
            f"{destination}",
        ) from exc
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot revalidate publication links after private-link cleanup: "
            f"{destination}: {exc}",
        ) from exc
    try:
        replacement = os.stat(
            prepared.path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        replacement = None
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            f"Cannot prove private-link namespace cleanup: {prepared.path}: {exc}",
        ) from exc
    if replacement is not None:
        raise StoreSafetyError(
            "prepared-file-identity-mismatch",
            "A different object occupies the private prepared leaf after "
            f"cleanup; preserving it: {prepared.path}",
        )
    if not _same_identity(descriptor_before, descriptor_after) or not _same_identity(
        descriptor_after, destination_after
    ):
        raise StoreSafetyError(
            "prepared-file-identity-mismatch",
            f"The committed object identity changed during private-link cleanup: "
            f"{destination}",
        )
    if (
        _access_policy(descriptor_after) != baseline_access
        or _access_policy(destination_after) != baseline_access
    ):
        raise StoreSafetyError(
            "prepared-file-access-policy-mismatch",
            "The committed object access policy changed during private-link "
            f"cleanup: {destination}",
        )
    if descriptor_after.st_nlink != installed_link_count - 1:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            "The private leaf is absent, but the prepared object's exact "
            f"link-count transition is not proved: {prepared.path}",
        )


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
                prepared=prepared.path,
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
                prepared=prepared.path,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc


def _publish_file_no_replace_from_parent(
    prepared: _BoundRegularFile,
    destination: Path,
    parent_fd: int,
) -> dict[str, Any]:
    before_link = os.fstat(prepared.fd)
    try:
        os.link(
            prepared.path.name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
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
        destination_is_prepared = (
            destination_state == "present"
            and destination_after is not None
            and _same_identity(prepared.opened, destination_after)
        )
        source_is_prepared = (
            source_state == "present"
            and source_after is not None
            and _same_identity(prepared.opened, source_after)
        )
        if destination_is_prepared:
            raise StoreSafetyError(
                "destination-install-uncertain",
                "The destination is linked to the prepared database, but the "
                f"publication syscall reported an error: {destination}: {exc}",
                details=_publication_details(
                    "uncertain",
                    prepared=prepared.path,
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
                    prepared=prepared.path,
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
                    prepared=prepared.path,
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
                prepared=prepared.path,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc

    try:
        _verify_bound_regular_file(
            prepared,
            PREPARED_FILE_CODES,
        )
        fingerprint = _verify_bound_regular_file(
            prepared,
            PREPARED_FILE_CODES,
            path=destination,
        )
        installed = os.fstat(prepared.fd)
        if (
            not _same_identity(before_link, installed)
            or installed.st_nlink != before_link.st_nlink + 1
        ):
            raise StoreSafetyError(
                "prepared-file-revalidation-inconclusive",
                "The destination link exists, but the prepared object's exact "
                f"link-count increment is not proved: {destination}",
            )
    except StoreSafetyError as exc:
        raise StoreSafetyError(
            "destination-install-uncertain",
            "The link syscall succeeded, but the installed object could not be "
            f"revalidated: {destination}: {exc}",
            details=_publication_details(
                "uncertain",
                prepared=prepared.path,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc

    try:
        _remove_bound_prepared_link(
            prepared,
            destination,
            parent_fd,
            installed_link_count=installed.st_nlink,
        )
    except (OSError, StoreSafetyError) as exc:
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
        committed_and_retained = (
            source_state == "present"
            and source_after is not None
            and _same_identity(prepared.opened, source_after)
            and destination_state == "present"
            and destination_after is not None
            and _same_identity(prepared.opened, destination_after)
        )
        if not committed_and_retained:
            raise StoreSafetyError(
                "destination-install-uncertain",
                "The link syscall succeeded, but cleanup failed and the current "
                "prepared/destination namespace cannot prove a retained committed "
                f"object: prepared={prepared.path}, destination={destination}: "
                f"{exc}",
                details=_publication_details(
                    "uncertain",
                    prepared=prepared.path,
                    destination=destination,
                    retry_safe=False,
                ),
            ) from exc
        raise StoreSafetyError(
            "destination-install-committed-cleanup-incomplete",
            "The recovered database is committed, but its private prepared link "
            f"could not be removed: {prepared.path}: {exc}",
            details=_publication_details(
                "committed",
                prepared=prepared.path,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc

    try:
        fingerprint = _verify_bound_regular_file(
            prepared,
            PREPARED_FILE_CODES,
            path=destination,
        )
        _fsync_directory(destination.parent)
        fingerprint = _verify_bound_regular_file(
            prepared,
            PREPARED_FILE_CODES,
            path=destination,
        )
    except (OSError, StoreSafetyError) as exc:
        raise StoreSafetyError(
            "destination-install-uncertain",
            "The recovered database was linked into place, but final durability "
            f"or fingerprint validation is unconfirmed: {destination}: {exc}",
            details=_publication_details(
                "uncertain",
                prepared=None,
                destination=destination,
                retry_safe=False,
            ),
        ) from exc
    return fingerprint


def _bound_sqlite_readonly_uri(
    source: _BoundRegularFile,
) -> str:
    descriptor_path = Path("/dev/fd") / str(source.fd)
    probe_fd: int | None = None
    try:
        descriptor = os.fstat(source.fd)
        probe_fd = os.open(
            descriptor_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor_path_stat = os.fstat(probe_fd)
        if (
            not stat.S_ISREG(descriptor.st_mode)
            or not stat.S_ISREG(descriptor_path_stat.st_mode)
            or not _same_identity(source.opened, descriptor)
            or not _same_identity(descriptor, descriptor_path_stat)
        ):
            raise StoreSafetyError(
                "prepared-file-identity-mismatch",
                "The SQLite descriptor path does not identify the validated "
                f"source object: {source.path}",
            )
    except OSError as exc:
        raise StoreSafetyError(
            "prepared-file-revalidation-inconclusive",
            "SQLite cannot bind the validated source descriptor through "
            f"{descriptor_path}: {exc}",
        ) from exc
    finally:
        if probe_fd is not None:
            os.close(probe_fd)
    return f"file:{descriptor_path}?mode=ro&immutable=1"


def _backup_sqlite_to_standalone(
    source: _BoundRegularFile,
    output: Path,
) -> dict[str, Any]:
    _verify_bound_regular_file(source, PREPARED_FILE_CODES)
    source_uri = _bound_sqlite_readonly_uri(source)
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
        try:
            path_before = os.stat(output, follow_symlinks=False)
            if not _same_identity(created, path_before):
                raise StoreSafetyError(
                    "prepared-file-identity-mismatch",
                    f"Standalone recovery output was replaced before backup: {output}",
                )
            with (
                closing(sqlite3.connect(source_uri, uri=True)) as source_conn,
                closing(sqlite3.connect(output)) as output_conn,
            ):
                source_conn.execute("PRAGMA query_only = ON")
                source_conn.backup(output_conn)
                output_conn.execute("PRAGMA journal_mode = DELETE")
                output_conn.commit()
        except sqlite3.Error as exc:
            raise StoreSafetyError(
                "sqlite-recovery-failed",
                f"SQLite backup could not create a standalone database: {exc}",
            ) from exc
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
        _verify_bound_regular_file(source, PREPARED_FILE_CODES)
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
        with _bind_regular_file(
            recovered_main,
            PREPARED_FILE_CODES,
        ) as recovered_bound:

            def revalidate_bound_source() -> None:
                _verify_bound_regular_file(
                    recovered_bound,
                    PREPARED_FILE_CODES,
                )

            return _recover_validated_clone_to_standalone(
                recovered_main,
                out,
                source_db=source_db,
                recovery_evidence=recovery_evidence,
                source_integrity=source_integrity,
                source_revalidate=revalidate_bound_source,
                source_backup=lambda output: _backup_sqlite_to_standalone(
                    recovered_bound,
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
    retain_temp = False
    try:
        if source_revalidate is not None:
            source_revalidate()
        temp_receipt = source_backup(temp_out)
        if source_revalidate is not None:
            source_revalidate()
        with _bind_regular_file(temp_out, PREPARED_FILE_CODES) as prepared:
            try:
                _assert_bound_matches_receipt(prepared, temp_receipt)
                output_integrity = _sqlite_integrity(temp_out)
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
                            prepared=temp_out,
                            destination=out,
                            retry_safe=True,
                        ),
                    ) from exc
                fingerprint = _publish_file_no_replace(prepared, out)
            except StoreSafetyError as exc:
                retain_temp = exc.details.get("publication_state") in {
                    "committed",
                    "uncertain",
                }
                raise
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
    finally:
        if not retain_temp and _lexists(temp_out):
            os.unlink(temp_out)
        for suffix in ("-wal", "-shm", "-journal"):
            temp_sidecar = temp_out.with_name(f"{temp_out.name}{suffix}")
            if not retain_temp and _lexists(temp_sidecar):
                os.unlink(temp_sidecar)


def _recover_to_standalone(src: Path, out: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apple-notes-merge-") as temp_dir:
        recovered_main, recovery_evidence = _make_recovery_clone(
            src, Path(temp_dir) / "store"
        )
        source_integrity = _sqlite_integrity(recovered_main)
        return _recover_validated_clone_to_standalone(
            recovered_main,
            out,
            source_db=src,
            recovery_evidence=recovery_evidence,
            source_integrity=source_integrity,
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
    retain_partial = False
    publication_committed = False
    partial_binding: _BoundDirectory | None = None
    try:
        with _create_bound_directory(partial) as bound_root:
            partial_binding = bound_root
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
                publication_committed = True
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
                except StoreSafetyError as exc:
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
    except StoreSafetyError as exc:
        if exc.code == "destination-install-uncertain" or exc.details.get(
            "publication_state"
        ) in {"committed", "uncertain"}:
            retain_partial = True
        raise
    finally:
        if not retain_partial and not publication_committed:
            _remove_bound_directory_if_owned(partial_binding, partial)

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
        recovered_main, recovery = _make_recovery_clone_from_bound(
            bound_files,
            Path(temp_dir) / "store",
            SNAPSHOT_FILE_CODES,
        )
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
        validated_recovery = Path(temp_dir) / "validated-recovery.sqlite"
        with _bind_regular_file(
            recovered_main,
            PREPARED_FILE_CODES,
        ) as recovered_main_bound:
            validated_recovery_receipt = _backup_sqlite_to_standalone(
                recovered_main_bound,
                validated_recovery,
            )
        validated_recovery_bound = stack.enter_context(
            _bind_regular_file(
                validated_recovery,
                PREPARED_FILE_CODES,
            )
        )
        validated_recovery_integrity = _sqlite_integrity(validated_recovery)
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
            result = _backup_sqlite_to_standalone(
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
            "sidecar_consistency": recovery["sidecars"],
            "sqlite_validation": sqlite_integrity,
            "validated_recovery_integrity": validated_recovery_integrity,
            "source_integrity": source_integrity,
        }
        yield _ValidatedSnapshotArtifact(
            public_result=public_result,
            recovered_main=validated_recovery,
            recovery_evidence=recovery,
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
    retain_partial = False
    publication_committed = False
    partial_binding: _BoundDirectory | None = None
    try:
        with _create_bound_directory(partial) as bound_root:
            partial_binding = bound_root
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
                publication_committed = True
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
                except StoreSafetyError as exc:
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
    except StoreSafetyError as exc:
        if exc.code == "destination-install-uncertain" or exc.details.get(
            "publication_state"
        ) in {"committed", "uncertain"}:
            retain_partial = True
        raise
    finally:
        if not retain_partial and not publication_committed:
            _remove_bound_directory_if_owned(partial_binding, partial)
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
            recovered_main, recovery = _make_recovery_clone_from_bound(
                {NOTE_STORE_MAIN: database_bound},
                Path(temp_dir) / "store",
                PATCH_FILE_CODES,
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
