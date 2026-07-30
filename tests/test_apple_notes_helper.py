from __future__ import annotations

import array
import builtins
import ctypes
import errno
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import unittest
from collections.abc import Iterator
from contextlib import closing, contextmanager, redirect_stdout
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".agents/skills/apple-notes-db-guardrails"
SCRIPT_PATH = SKILL_DIR / "scripts/apple_notes_db.py"
DIRECTORY_SUPERVISOR_PATH = SKILL_DIR / "scripts/apple_notes_directory_supervisor.py"
SUPERVISOR_SPEC = importlib.util.spec_from_file_location(
    "apple_notes_directory_supervisor",
    DIRECTORY_SUPERVISOR_PATH,
)
assert SUPERVISOR_SPEC is not None
assert SUPERVISOR_SPEC.loader is not None
SUPERVISOR_MODULE = importlib.util.module_from_spec(SUPERVISOR_SPEC)
sys.modules[SUPERVISOR_SPEC.name] = SUPERVISOR_MODULE
SUPERVISOR_SPEC.loader.exec_module(SUPERVISOR_MODULE)
SPEC = importlib.util.spec_from_file_location("apple_notes_db", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
WRAPPER_PATH = REPO_ROOT / "scripts/apple_notes_helper.sh"
COMPATIBILITY_SCRIPT = REPO_ROOT / "scripts/apple_notes_helper.py"
HOT_JOURNAL_FIXTURE = REPO_ROOT / "tests/create_hot_rollback_journal.py"


class _StatWithOverrides:
    def __init__(self, value: os.stat_result, **overrides: int) -> None:
        self._value = value
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._value, name)


class _StatWithFlags(_StatWithOverrides):
    def __init__(self, value: os.stat_result, flags: int) -> None:
        super().__init__(value, st_flags=flags)


@contextmanager
def _fail_if_deadline_exceeded(seconds: float) -> Iterator[None]:
    previous_handler = signal.getsignal(signal.SIGALRM)

    def raise_timeout(_signum: int, _frame: object) -> None:
        raise TimeoutError(f"operation exceeded {seconds:.3f}s deadline")

    signal.signal(signal.SIGALRM, raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)


class AppleNotesHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self._snapshot_manifest_receipts: dict[Path, dict[str, object]] = {}
        self._stage_manifest_receipts: dict[Path, dict[str, object]] = {}
        self._directory_creator_patch = mock.patch.object(
            MODULE,
            "_IDENTITY_BOUND_DIRECTORY_CREATOR",
            self._synthetic_identity_bound_directory_creator,
        )
        self._directory_creator_patch.start()
        self.addCleanup(self._directory_creator_patch.stop)

    @staticmethod
    def _supervised_worker_source(body: str) -> str:
        indented = "\n".join(f"    {line}" for line in body.splitlines())
        return (
            "DIRECTORY_CREATOR_MAX_MESSAGE_BYTES = 65536\n"
            "DIRECTORY_CREATOR_MAX_RECEIVED_FDS = 4\n"
            "def _worker_main():\n"
            f"{indented}\n"
            "if __name__ == '__main__':\n"
            "    _worker_main()\n"
        )

    @staticmethod
    def _run_supervised_test_helper(
        helper_path: Path,
        command: list[str],
    ) -> int:
        """Explicitly inject one test-only capture/module pair."""

        capture = SUPERVISOR_MODULE._capture_helper_source(helper_path)
        module_name = (
            "apple_notes_test_supervised_helper_"
            f"{capture.sha256}_{os.getpid()}_{time.monotonic_ns()}"
        )
        helper_module = SUPERVISOR_MODULE._load_helper(
            capture,
            module_name=module_name,
        )
        try:
            return SUPERVISOR_MODULE._run_supervised_capture(
                capture,
                helper_module,
                command,
                python_bin=sys.executable,
            )
        finally:
            sys.modules.pop(module_name, None)

    def _load_compatibility_module(
        self,
        compatibility_path: Path,
        module_name: str,
    ) -> ModuleType:
        spec = importlib.util.spec_from_file_location(
            module_name,
            compatibility_path,
        )
        assert spec is not None
        assert spec.loader is not None
        compatibility = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = compatibility
        try:
            spec.loader.exec_module(compatibility)
        except BaseException:
            sys.modules.pop(module_name, None)
            raise
        self.addCleanup(sys.modules.pop, module_name, None)
        self.addCleanup(
            sys.modules.pop,
            "packaged_apple_notes_directory_supervisor",
            None,
        )
        self.addCleanup(
            sys.modules.pop,
            "packaged_apple_notes_db_for_supervisor",
            None,
        )
        return compatibility

    @staticmethod
    def _write_compatibility_tree(
        root: Path,
        *,
        helper_source: bytes | None = None,
    ) -> tuple[Path, Path, Path]:
        compatibility_path = root / "scripts/apple_notes_helper.py"
        packaged_scripts = root / ".agents/skills/apple-notes-db-guardrails/scripts"
        supervisor_path = packaged_scripts / "apple_notes_directory_supervisor.py"
        helper_path = packaged_scripts / "apple_notes_db.py"
        compatibility_path.parent.mkdir(parents=True)
        packaged_scripts.mkdir(parents=True)
        compatibility_path.write_bytes(COMPATIBILITY_SCRIPT.read_bytes())
        supervisor_path.write_bytes(DIRECTORY_SUPERVISOR_PATH.read_bytes())
        helper_path.write_bytes(
            SCRIPT_PATH.read_bytes() if helper_source is None else helper_source
        )
        return compatibility_path, supervisor_path, helper_path

    @staticmethod
    def _source_tree_inventory(
        source_roots: dict[str, Path],
    ) -> dict[tuple[str, str], tuple[object, ...]]:
        inventory: dict[tuple[str, str], tuple[object, ...]] = {}
        for label, source_root in source_roots.items():
            for path in (source_root, *sorted(source_root.rglob("*"))):
                relative = (
                    "." if path == source_root else str(path.relative_to(source_root))
                )
                observed = path.lstat()
                common: tuple[object, ...] = (
                    (
                        observed.st_dev,
                        observed.st_ino,
                        stat.S_IFMT(observed.st_mode),
                    ),
                    tuple(
                        sorted(
                            MODULE._access_policy(observed).items(),
                        )
                    ),
                    observed.st_mtime_ns,
                )
                if stat.S_ISLNK(observed.st_mode):
                    value = ("symlink", *common, os.readlink(path))
                elif stat.S_ISDIR(observed.st_mode):
                    value = ("directory", *common)
                elif stat.S_ISREG(observed.st_mode):
                    payload = path.read_bytes()
                    value = (
                        "file",
                        *common,
                        len(payload),
                        hashlib.sha256(payload).hexdigest(),
                    )
                else:
                    value = ("other", *common)
                inventory[(label, relative)] = value
        return inventory

    def _synthetic_identity_bound_directory_creator(
        self,
        parent_fd: int,
        prefix: str,
    ) -> MODULE._IdentityBoundDirectoryCreation:
        """Model a trusted provider for focused in-process unit tests."""

        for _ in range(8):
            basename = f"{prefix}{MODULE.uuid.uuid4().hex}"
            try:
                os.mkdir(basename, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            fd = os.open(basename, MODULE._directory_open_flags(), dir_fd=parent_fd)
            opened = os.fstat(fd)
            parent = os.fstat(parent_fd)
            return MODULE._IdentityBoundDirectoryCreation(
                basename=basename,
                fd=fd,
                opened=opened,
                proof={
                    "schema": ("apple-notes-identity-bound-directory-creation/v1"),
                    "creation_authority": "test-only-synthetic-platform-provider",
                    "actual_created_object_descriptor_returned": True,
                    "namespace_exclusive_during_handoff": True,
                    "parent_identity": MODULE._identity(parent),
                    "parent_access_policy": MODULE._access_policy(parent),
                    "directory_identity": MODULE._identity(opened),
                    "directory_access_policy": MODULE._access_policy(opened),
                },
            )
        raise OSError(errno.EEXIST, "synthetic creator exhausted candidate names")

    @staticmethod
    def _serve_directory_creator_supervisor(
        server_fd: int,
        *,
        request_count: int,
    ) -> int:
        """Exercise the real inherited-FD transport from a separate test process.

        This transport fixture runs in a test-owned namespace with no concurrent
        mutator. It is not a production creation authority and does not make the
        stronger same-UID mkdir-then-open claim forbidden by the safety contract.
        """

        handled = 0
        with socket.socket(fileno=server_fd) as supervisor:
            supervisor.settimeout(10.0)
            for _ in range(request_count):
                payload, ancillary, flags, _ = supervisor.recvmsg(
                    MODULE.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                    socket.CMSG_SPACE(
                        array.array("i").itemsize
                        * MODULE.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                    ),
                )
                if flags & (
                    getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)
                ):
                    raise RuntimeError("test supervisor request was truncated")
                parent_descriptors = MODULE._received_rights_descriptors(ancillary)
                if len(parent_descriptors) != 1:
                    MODULE._close_descriptors(parent_descriptors)
                    raise RuntimeError(
                        "test supervisor expected exactly one parent descriptor"
                    )
                parent_fd = parent_descriptors.pop()
                directory_fd: int | None = None
                try:
                    request = json.loads(payload.decode("utf-8"))
                    if (
                        request.get("schema") != MODULE.DIRECTORY_CREATOR_REQUEST_SCHEMA
                        or request.get("operation") != "create-owner-private-directory"
                        or request.get("mode") != 0o700
                        or request.get("expected_uid") != os.geteuid()
                    ):
                        raise RuntimeError("test supervisor rejected request")
                    parent = os.fstat(parent_fd)
                    if request.get("parent_identity") != MODULE._identity(
                        parent
                    ) or request.get("parent_access_policy") != MODULE._access_policy(
                        parent
                    ):
                        raise RuntimeError("test supervisor parent proof mismatch")
                    prefix = request.get("prefix")
                    if prefix != ".apple-notes-create-":
                        raise RuntimeError("test supervisor prefix mismatch")
                    basename = f"{prefix}{MODULE.uuid.uuid4().hex}"
                    os.mkdir(basename, mode=0o700, dir_fd=parent_fd)
                    directory_fd = os.open(
                        basename,
                        MODULE._directory_open_flags(),
                        dir_fd=parent_fd,
                    )
                    opened = os.fstat(directory_fd)
                    response = json.dumps(
                        {
                            "schema": (MODULE.DIRECTORY_CREATOR_RESPONSE_SCHEMA),
                            "request_id": request["request_id"],
                            "status": "created",
                            "basename": basename,
                            "proof": {
                                "schema": (
                                    "apple-notes-identity-bound-directory-creation/v1"
                                ),
                                "creation_authority": (
                                    "test-supervisor-inherited-fd-protocol"
                                ),
                                "actual_created_object_descriptor_returned": True,
                                "namespace_exclusive_during_handoff": True,
                                "parent_identity": MODULE._identity(parent),
                                "parent_access_policy": (MODULE._access_policy(parent)),
                                "directory_identity": MODULE._identity(opened),
                                "directory_access_policy": (
                                    MODULE._access_policy(opened)
                                ),
                            },
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                    supervisor.sendmsg(
                        [response],
                        [
                            (
                                socket.SOL_SOCKET,
                                socket.SCM_RIGHTS,
                                array.array("i", [directory_fd]),
                            ),
                        ],
                    )
                    handled += 1
                finally:
                    if directory_fd is not None:
                        os.close(directory_fd)
                    os.close(parent_fd)
        return handled

    @staticmethod
    def _serve_directory_creator_failure_response(
        server_fd: int,
        *,
        details: object,
        response_overrides: dict[str, object] | None = None,
    ) -> None:
        """Create one directory and return its FD with a provider failure."""

        with socket.socket(fileno=server_fd) as supervisor:
            supervisor.settimeout(10.0)
            payload, ancillary, flags, _ = supervisor.recvmsg(
                MODULE.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                socket.CMSG_SPACE(
                    array.array("i").itemsize
                    * MODULE.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                ),
            )
            if flags & (
                getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)
            ):
                raise RuntimeError("test supervisor request was truncated")
            parent_descriptors = MODULE._received_rights_descriptors(ancillary)
            if len(parent_descriptors) != 1:
                MODULE._close_descriptors(parent_descriptors)
                raise RuntimeError(
                    "test supervisor expected exactly one parent descriptor"
                )
            parent_fd = parent_descriptors.pop()
            directory_fd: int | None = None
            try:
                request = json.loads(payload.decode("utf-8"))
                if (
                    request.get("schema") != MODULE.DIRECTORY_CREATOR_REQUEST_SCHEMA
                    or request.get("operation") != "create-owner-private-directory"
                    or request.get("prefix") != ".apple-notes-create-"
                ):
                    raise RuntimeError("test supervisor rejected request")
                parent = os.fstat(parent_fd)
                basename = ".apple-notes-create-malformed-provider-details"
                os.mkdir(basename, mode=0o700, dir_fd=parent_fd)
                directory_fd = os.open(
                    basename,
                    MODULE._directory_open_flags(),
                    dir_fd=parent_fd,
                )
                opened = os.fstat(directory_fd)
                response_payload: dict[str, object] = {
                    "schema": MODULE.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
                    "request_id": request["request_id"],
                    "status": "failed-after-create",
                    "basename": basename,
                    "proof": {
                        "schema": ("apple-notes-identity-bound-directory-creation/v1"),
                        "creation_authority": ("test-supervisor-create-then-fail"),
                        "actual_created_object_descriptor_returned": True,
                        "namespace_exclusive_during_handoff": True,
                        "parent_identity": MODULE._identity(parent),
                        "parent_access_policy": MODULE._access_policy(parent),
                        "directory_identity": MODULE._identity(opened),
                        "directory_access_policy": MODULE._access_policy(opened),
                    },
                    "details": details,
                }
                if response_overrides is not None:
                    response_payload.update(response_overrides)
                response = json.dumps(
                    response_payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                supervisor.sendmsg(
                    [response],
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            array.array("i", [directory_fd]),
                        ),
                    ],
                )
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)
                os.close(parent_fd)

    @staticmethod
    def _serve_packaged_directory_creator_once(server_fd: int) -> None:
        """Serve one request through the real packaged capability gate."""

        with socket.socket(fileno=server_fd) as supervisor:
            supervisor.settimeout(10.0)
            payload, ancillary, flags, _ = supervisor.recvmsg(
                MODULE.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                socket.CMSG_SPACE(
                    array.array("i").itemsize
                    * MODULE.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                ),
            )
            if flags & (
                getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)
            ):
                raise RuntimeError("packaged supervisor test request was truncated")
            parent_descriptors = MODULE._received_rights_descriptors(ancillary)
            SUPERVISOR_MODULE._serve_one_request(
                supervisor,
                payload,
                parent_descriptors,
                SUPERVISOR_MODULE.HELPER,
            )

    @staticmethod
    def _serve_malformed_precreation_unavailable_response(
        server_fd: int,
        *,
        malformed_kind: str,
    ) -> None:
        """Return a near-match that must not inherit the no-mutation claim."""

        with socket.socket(fileno=server_fd) as supervisor:
            supervisor.settimeout(10.0)
            payload, ancillary, flags, _ = supervisor.recvmsg(
                MODULE.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                socket.CMSG_SPACE(
                    array.array("i").itemsize
                    * MODULE.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                ),
            )
            if flags & (
                getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)
            ):
                raise RuntimeError("malformed supervisor test request was truncated")
            parent_descriptors = MODULE._received_rights_descriptors(ancillary)
            if len(parent_descriptors) != 1:
                MODULE._close_descriptors(parent_descriptors)
                raise RuntimeError("malformed supervisor expected one parent FD")
            parent_fd = parent_descriptors.pop()
            returned_fd: int | None = None
            try:
                request = json.loads(payload.decode("utf-8"))
                response: dict[str, object] = {
                    "schema": MODULE.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
                    "request_id": request["request_id"],
                    "status": MODULE.DIRECTORY_CREATOR_UNAVAILABLE_STATUS,
                    "basename": None,
                    "proof": None,
                    "details": MODULE._packaged_directory_creator_unavailable_details(),
                }
                if malformed_kind == "returned-descriptor":
                    returned_fd = os.dup(parent_fd)
                elif malformed_kind == "basename":
                    response["basename"] = ".apple-notes-create-unproved"
                elif malformed_kind == "proof":
                    response["proof"] = {
                        "actual_created_object_descriptor_returned": False,
                    }
                elif malformed_kind in {"details", "details-bool-int"}:
                    response_details = json.loads(json.dumps(response["details"]))
                    if malformed_kind == "details":
                        response_details["mutation_performed"] = True
                    else:
                        response_details["mutation_performed"] = 0
                        response_details["recovery_locators"][
                            "packaged_directory_supervisor"
                        ]["creation_boundary_entered"] = 0
                    response["details"] = response_details
                elif malformed_kind == "extra-field":
                    response["unexpected"] = True
                else:
                    raise AssertionError(
                        f"unsupported malformed kind: {malformed_kind}"
                    )
                encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
                ancillary_response = (
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            array.array("i", [returned_fd]),
                        )
                    ]
                    if returned_fd is not None
                    else []
                )
                supervisor.sendmsg([encoded], ancillary_response)
            finally:
                if returned_fd is not None:
                    os.close(returned_fd)
                os.close(parent_fd)

    def _copy_db(
        self,
        *args: object,
        **kwargs: object,
    ) -> dict[str, object]:
        result = MODULE.copy_db(*args, **kwargs)
        self._snapshot_manifest_receipts[Path(result["dest"])] = result[
            "manifest_creation_receipt"
        ]
        return result

    def _stage_patch(
        self,
        *args: object,
        **kwargs: object,
    ) -> dict[str, object]:
        result = MODULE.stage_patch(*args, **kwargs)
        self._stage_manifest_receipts[Path(result["stage_dir"])] = result[
            "manifest_creation_receipt"
        ]
        return result

    def _validate_snapshot(self, snapshot_dir: Path) -> dict[str, object]:
        return MODULE.validate_snapshot(
            snapshot_dir,
            self._snapshot_manifest_receipts[snapshot_dir],
        )

    def _validate_patch_stage(self, stage_dir: Path) -> dict[str, object]:
        return MODULE.validate_patch_stage(
            stage_dir,
            self._stage_manifest_receipts[stage_dir],
        )

    def _recover_snapshot(
        self,
        snapshot_dir: Path,
        out: Path,
    ) -> dict[str, object]:
        return MODULE.recover_snapshot(
            snapshot_dir,
            out,
            self._snapshot_manifest_receipts[snapshot_dir],
        )

    def _preflight_writeback(
        self,
        paths: MODULE.NoteStorePaths,
        *,
        backup_dir: Path,
        stage_dir: Path,
    ) -> dict[str, object]:
        return MODULE.preflight_writeback(
            paths,
            backup_dir=backup_dir,
            stage_dir=stage_dir,
            backup_manifest_creation_receipt=(
                self._snapshot_manifest_receipts[backup_dir]
            ),
            stage_manifest_creation_receipt=self._stage_manifest_receipts[stage_dir],
        )

    def _verify_writeback(
        self,
        paths: MODULE.NoteStorePaths,
        *,
        backup_dir: Path,
        stage_dir: Path,
    ) -> dict[str, object]:
        return MODULE.verify_writeback(
            paths,
            backup_dir=backup_dir,
            stage_dir=stage_dir,
            backup_manifest_creation_receipt=(
                self._snapshot_manifest_receipts[backup_dir]
            ),
            stage_manifest_creation_receipt=self._stage_manifest_receipts[stage_dir],
        )

    def _reanchor_manifest_for_test(
        self,
        artifact_dir: Path,
        *,
        artifact_kind: str,
    ) -> dict[str, object]:
        if artifact_kind == "snapshot":
            manifest_name = MODULE.SNAPSHOT_MANIFEST
            artifact_schema = MODULE.SNAPSHOT_SCHEMA
            registry = self._snapshot_manifest_receipts
        elif artifact_kind == "patch-stage":
            manifest_name = MODULE.PATCH_MANIFEST
            artifact_schema = MODULE.PATCH_SCHEMA
            registry = self._stage_manifest_receipts
        else:
            self.fail(f"Unsupported artifact kind: {artifact_kind}")
        manifest_path = artifact_dir / manifest_name
        payload = manifest_path.read_bytes()
        observed = os.stat(manifest_path, follow_symlinks=False)
        receipt = MODULE._manifest_creation_receipt_payload(
            artifact_kind=artifact_kind,
            artifact_schema=artifact_schema,
            manifest_name=manifest_name,
            manifest_receipt={
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "identity": MODULE._identity(observed),
                "access_policy": MODULE._access_policy(observed),
            },
        )
        registry[artifact_dir] = receipt
        return receipt

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

    def _create_db(self, path: Path, value: str = "ok") -> None:
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO sample(value) VALUES (?)", (value,))
            conn.commit()

    @contextmanager
    def _bind_direct_main_only_source_store(
        self,
        main_path: Path,
    ) -> Iterator[MODULE._BoundSourceStore]:
        """Bind a test store without adding a context-exit store revalidation."""

        parent_path = main_path.parent
        parent_fd = os.open(parent_path.parent, MODULE._directory_open_flags())
        directory_fd: int | None = None
        try:
            directory_fd = os.open(
                parent_path.name,
                MODULE._directory_open_flags(),
                dir_fd=parent_fd,
            )
            directory = MODULE._BoundDirectory(
                path=parent_path,
                fd=directory_fd,
                opened=os.fstat(directory_fd),
                parent_opened=os.fstat(parent_fd),
                parent_fd=parent_fd,
                namespace_basename=parent_path.name,
                canonical_path=parent_path,
            )
            with MODULE._bind_regular_file_at(
                main_path,
                directory,
                MODULE.SOURCE_FILE_CODES,
            ) as bound:
                yield MODULE._BoundSourceStore(
                    directory=directory,
                    main_name=main_path.name,
                    files={main_path.name: bound},
                    membership=(main_path.name,),
                )
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            os.close(parent_fd)

    def _create_wal_db(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(path)
        self.assertEqual(conn.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
        conn.execute("PRAGMA wal_autocheckpoint = 0")
        conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO sample(value) VALUES ('from-wal')")
        conn.commit()
        self.assertTrue(path.with_name(f"{path.name}-wal").exists())
        self.assertTrue(path.with_name(f"{path.name}-shm").exists())
        return conn

    def _create_checkpointed_then_wal_only_db(
        self,
        path: Path,
    ) -> sqlite3.Connection:
        conn = sqlite3.connect(path)
        self.assertEqual(conn.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
        conn.execute("PRAGMA wal_autocheckpoint = 0")
        conn.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        conn.execute("INSERT INTO evidence VALUES ('checkpointed')")
        conn.commit()
        checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertIsNotNone(checkpoint)
        assert checkpoint is not None
        self.assertEqual(checkpoint[0], 0)
        conn.execute("INSERT INTO evidence VALUES ('wal-only')")
        conn.commit()
        wal = path.with_name(f"{path.name}-wal")
        self.assertTrue(wal.exists())
        self.assertGreater(wal.stat().st_size, 32)
        return conn

    def _make_paths(self, root: Path) -> MODULE.NoteStorePaths:
        group = root / "group"
        app = root / "app"
        group.mkdir()
        app.mkdir()
        return MODULE.NoteStorePaths(group_container=group, app_container=app)

    def _assert_safety_code(
        self, expected: str, context: unittest.case._AssertRaisesContext
    ) -> None:
        self.assertIsInstance(context.exception, MODULE.StoreSafetyError)
        self.assertEqual(context.exception.code, expected)

    def _assert_retained_partial(self, root: Path, pattern: str) -> Path:
        retained = list(root.glob(pattern))
        self.assertEqual(len(retained), 1)
        self.assertTrue(retained[0].is_dir())
        return retained[0]

    def _assert_snapshot_and_stage_reject_extra_entry(self, entry_kind: str) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    Path(snapshot["dest"]) / "group.com.apple.notes",
                    self._validate_snapshot,
                    Path(snapshot["dest"]),
                    "snapshot-file-set-mismatch",
                ),
                (
                    stage,
                    self._validate_patch_stage,
                    stage,
                    "patch-file-set-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(entry_kind=entry_kind, target=target.name):
                    extra = target / f"unexpected-{entry_kind}"
                    if entry_kind == "directory":
                        extra.mkdir()
                    elif entry_kind == "fifo":
                        os.mkfifo(extra)
                    elif entry_kind == "broken-symlink":
                        extra.symlink_to("missing-target")
                    else:
                        self.fail(f"Unsupported test entry kind: {entry_kind}")
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        validator(argument)
                    self._assert_safety_code(expected_code, raised)

    def test_packaged_skill_is_self_contained(self) -> None:
        self.assertTrue((SKILL_DIR / "SKILL.md").is_file())
        self.assertTrue((SKILL_DIR / "agents/openai.yaml").is_file())
        self.assertTrue((SKILL_DIR / "references/safety-contract.md").is_file())
        self.assertTrue(
            (SKILL_DIR / "scripts/apple_notes_directory_supervisor.py").is_file()
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            copied_skill = Path(temp_dir) / "apple-notes-db-guardrails"
            shutil.copytree(SKILL_DIR, copied_skill)
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(copied_skill / "scripts/apple_notes_db.py"),
                    "--help",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            copy_help = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(copied_skill / "scripts/apple_notes_db.py"),
                    "copy-db",
                    "--help",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("preflight-writeback", result.stdout)
        self.assertEqual(copy_help.returncode, 0, msg=copy_help.stderr)
        self.assertIn("--result-file", copy_help.stdout)

    def test_copy_db_cli_uses_inherited_directory_creator_supervisor(
        self,
    ) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("inherited-FD supervisor integration requires POSIX")
        process_probe = subprocess.run(
            [MODULE.NOTES_PGREP_PATH, "-x", "Notes"],
            check=False,
            capture_output=True,
        )
        if process_probe.returncode not in {0, 1} or process_probe.stderr:
            self.skipTest("fixed Notes process probe is unavailable in this sandbox")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            client, server = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_DGRAM,
            )
            child_pid = os.fork()
            if child_pid == 0:
                client.close()
                try:
                    handled = self._serve_directory_creator_supervisor(
                        server.detach(),
                        request_count=2,
                    )
                except BaseException as exc:
                    os.write(
                        2,
                        f"test directory creator supervisor failed: {exc!r}\n".encode(
                            "utf-8"
                        ),
                    )
                    os._exit(71)
                os._exit(0 if handled == 2 else 72)

            server.close()
            try:
                result = subprocess.run(
                    [
                        "bash",
                        str(WRAPPER_PATH),
                        "copy-db",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--dest",
                        str(destination),
                        "--directory-creator-fd",
                        str(client.fileno()),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    pass_fds=(client.fileno(),),
                    timeout=20.0,
                    env={
                        **os.environ,
                        "PYTHON_BIN": sys.executable,
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                )
            finally:
                client.close()
                _, child_status = os.waitpid(child_pid, 0)
            manifest_exists = (destination / MODULE.SNAPSHOT_MANIFEST).is_file()
            database_exists = (
                destination / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            ).is_file()

        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertTrue(os.WIFEXITED(child_status))
        self.assertEqual(os.WEXITSTATUS(child_status), 0)
        payload = json.loads(result.stdout)
        self.assertEqual(Path(payload["dest"]), destination)
        self.assertTrue(manifest_exists)
        self.assertTrue(database_exists)

    def test_shell_wrapper_packaged_supervisor_fails_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live_source = paths.group_container / MODULE.NOTE_STORE_MAIN
            edited_source = root / "edited.sqlite"
            self._create_db(live_source)
            self._create_db(edited_source)
            snapshot = root / "snapshot"
            stage = root / "stage"
            previous_umask = os.umask(0o777)
            try:
                stage_result = subprocess.run(
                    [
                        "bash",
                        str(WRAPPER_PATH),
                        "stage-patch",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--src",
                        str(edited_source),
                        "--dest",
                        str(stage),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    env={
                        **os.environ,
                        "PYTHON_BIN": sys.executable,
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                )
            finally:
                os.umask(previous_umask)

            stage_payload = (
                json.loads(stage_result.stdout) if stage_result.stdout else {}
            )
            stage_exists = (stage / MODULE.NOTE_STORE_MAIN).is_file()
            supervisor_residue = list(root.rglob(".apple-notes-create-*"))

        self.assertEqual(
            stage_result.returncode,
            1,
            msg=stage_result.stdout + stage_result.stderr,
        )
        self.assertEqual(
            stage_payload["error_code"],
            "directory-creation-identity-inconclusive",
        )
        self.assertFalse(stage_exists)
        self.assertFalse(stage.exists())
        self.assertFalse(stage_payload["details"]["mutation_performed"])
        self.assertEqual(stage_payload["details"]["cleanup_state"], "not-needed")
        self.assertEqual(supervisor_residue, [])

        # The fixed pgrep probe is deliberately fail-closed. Exercise copy-db
        # through the same production launcher only when this test runtime can
        # obtain unambiguous process-list evidence.
        process_probe = subprocess.run(
            [MODULE.NOTES_PGREP_PATH, "-x", "Notes"],
            check=False,
            capture_output=True,
        )
        if process_probe.returncode not in {0, 1} or process_probe.stderr:
            return
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            snapshot = root / "snapshot"
            copy_result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER_PATH),
                    "copy-db",
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                    "--dest",
                    str(snapshot),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30.0,
                env={
                    **os.environ,
                    "PYTHON_BIN": sys.executable,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            copy_payload = json.loads(copy_result.stdout) if copy_result.stdout else {}
            snapshot_exists = (
                snapshot / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            ).is_file()
        self.assertEqual(
            copy_result.returncode,
            1,
            msg=copy_result.stdout + copy_result.stderr,
        )
        self.assertEqual(
            copy_payload["error_code"],
            "directory-creation-identity-inconclusive",
        )
        self.assertFalse(snapshot_exists)
        self.assertFalse(snapshot.exists())
        self.assertFalse(copy_payload["details"]["mutation_performed"])
        self.assertEqual(copy_payload["details"]["cleanup_state"], "not-needed")

    def test_packaged_directory_supervisor_bounds_signal_teardown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            worker_pid_file = root / "worker.pid"
            worker_script.write_text(
                self._supervised_worker_source(
                    "import os\n"
                    "import sys\n"
                    "import time\n"
                    "with open(sys.argv[1], 'w', encoding='ascii') as stream:\n"
                    "    stream.write(str(os.getpid()))\n"
                    "while True:\n"
                    "    time.sleep(0.1)"
                ),
                encoding="utf-8",
            )
            test_launcher = root / "test_launcher.py"
            test_launcher.write_text(
                "import importlib.util\n"
                "import pathlib\n"
                "import sys\n"
                f"supervisor_path = pathlib.Path({str(DIRECTORY_SUPERVISOR_PATH)!r})\n"
                "spec = importlib.util.spec_from_file_location(\n"
                "    'apple_notes_test_signal_launcher',\n"
                "    supervisor_path,\n"
                ")\n"
                "assert spec is not None and spec.loader is not None\n"
                "supervisor = importlib.util.module_from_spec(spec)\n"
                "sys.modules[spec.name] = supervisor\n"
                "spec.loader.exec_module(supervisor)\n"
                "capture = supervisor._capture_helper_source(pathlib.Path(sys.argv[1]))\n"
                "helper_name = 'apple_notes_test_signal_helper'\n"
                "helper = supervisor._load_helper(capture, module_name=helper_name)\n"
                "try:\n"
                "    return_code = supervisor._run_supervised_capture(\n"
                "        capture,\n"
                "        helper,\n"
                "        [sys.argv[2]],\n"
                "        python_bin=sys.executable,\n"
                "    )\n"
                "finally:\n"
                "    sys.modules.pop(helper_name, None)\n"
                "raise SystemExit(return_code)\n",
                encoding="utf-8",
            )
            launcher = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(test_launcher),
                    str(worker_script),
                    str(worker_pid_file),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = time.monotonic() + 5.0
            while not worker_pid_file.is_file() and time.monotonic() < deadline:
                if launcher.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue(worker_pid_file.is_file())
            worker_pid = int(worker_pid_file.read_text(encoding="ascii"))
            os.kill(launcher.pid, signal.SIGTERM)
            stdout, stderr = launcher.communicate(timeout=5.0)
            worker_deadline = time.monotonic() + 2.0
            while time.monotonic() < worker_deadline:
                try:
                    os.kill(worker_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                self.fail(f"supervised worker {worker_pid} survived teardown")

        self.assertEqual(launcher.returncode, -signal.SIGTERM, stderr)
        self.assertEqual(stdout, "")

    def test_supervisor_latches_launch_window_and_repeated_signals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            worker_script.write_text(
                self._supervised_worker_source(
                    "import time\nwhile True:\n    time.sleep(0.1)"
                ),
                encoding="utf-8",
            )
            spawned_pids: list[int] = []
            delivered_signals: list[int] = []
            original_spawn = SUPERVISOR_MODULE.subprocess.Popen
            original_terminate = SUPERVISOR_MODULE._terminate_worker
            original_handler = signal.getsignal(signal.SIGTERM)
            original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

            def spawn_then_signal(
                *args: object,
                **kwargs: object,
            ) -> subprocess.Popen[bytes]:
                process = original_spawn(*args, **kwargs)
                spawned_pids.append(process.pid)
                os.kill(os.getpid(), signal.SIGTERM)
                return process

            def repeat_signal_during_cleanup(
                worker: object,
                grace_seconds: float,
            ) -> None:
                os.kill(os.getpid(), signal.SIGTERM)
                original_terminate(worker, grace_seconds)

            signal.signal(
                signal.SIGTERM,
                lambda signum, _frame: delivered_signals.append(signum),
            )
            try:
                with (
                    mock.patch.object(
                        SUPERVISOR_MODULE.subprocess,
                        "Popen",
                        side_effect=spawn_then_signal,
                    ),
                    mock.patch.object(
                        SUPERVISOR_MODULE,
                        "_terminate_worker",
                        side_effect=repeat_signal_during_cleanup,
                    ),
                ):
                    return_code = self._run_supervised_test_helper(
                        worker_script,
                        ["ignored"],
                    )
            finally:
                signal.signal(signal.SIGTERM, original_handler)

            restored_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            self.assertEqual(restored_mask, original_mask)
            self.assertEqual(return_code, 128 + signal.SIGTERM)
            self.assertEqual(delivered_signals, [signal.SIGTERM])
            self.assertEqual(len(spawned_pids), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(spawned_pids[0], 0)

    def test_spawn_worker_inherits_exact_supervisor_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            observed_fd_file = root / "observed-fd"
            worker_script.write_text(
                "import os\n"
                "import sys\n"
                "if sys.argv[2] != '--directory-creator-fd':\n"
                "    raise SystemExit(2)\n"
                "descriptor = int(sys.argv[3])\n"
                "os.fstat(descriptor)\n"
                "with open(sys.argv[1], 'w', encoding='ascii') as stream:\n"
                "    stream.write(str(descriptor))\n",
                encoding="utf-8",
            )
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            worker = None
            client_fd = client.fileno()
            try:
                worker = SUPERVISOR_MODULE._spawn_worker(
                    SUPERVISOR_MODULE._capture_helper_source(worker_script),
                    [str(observed_fd_file)],
                    python_bin=sys.executable,
                    client_fd=client_fd,
                    child_signal_mask=set(
                        signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    ),
                )
                return_code = worker.wait(timeout=5.0)
            finally:
                if worker is not None and worker.poll() is None:
                    SUPERVISOR_MODULE._terminate_worker(worker, 0.5)
                client.close()
                server.close()

            self.assertEqual(return_code, 0)
            self.assertEqual(
                int(observed_fd_file.read_text(encoding="ascii")),
                client_fd,
            )

    def test_spawn_worker_closes_last_moment_inheritable_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"sentinel")
            sentinel_metadata = root / "sentinel-metadata.json"
            observed_file = root / "observed"
            worker_script.write_text(
                "import json\n"
                "import os\n"
                "import sys\n"
                "metadata = json.loads(open(sys.argv[1], encoding='ascii').read())\n"
                "inherited = False\n"
                "try:\n"
                "    opened = os.fstat(metadata['fd'])\n"
                "except OSError:\n"
                "    pass\n"
                "else:\n"
                "    inherited = [opened.st_dev, opened.st_ino] == metadata['identity']\n"
                "with open(sys.argv[2], 'w', encoding='ascii') as stream:\n"
                "    stream.write(json.dumps({'inherited': inherited}))\n",
                encoding="utf-8",
            )
            original_spawn = SUPERVISOR_MODULE.subprocess.Popen
            created_fd: int | None = None

            def open_inheritable_then_spawn(
                *args: object,
                **kwargs: object,
            ) -> subprocess.Popen[bytes]:
                nonlocal created_fd
                created_fd = os.open(sentinel, os.O_RDONLY)
                os.set_inheritable(created_fd, True)
                opened = os.fstat(created_fd)
                sentinel_metadata.write_text(
                    json.dumps(
                        {
                            "fd": created_fd,
                            "identity": [opened.st_dev, opened.st_ino],
                        }
                    ),
                    encoding="ascii",
                )
                try:
                    return original_spawn(*args, **kwargs)
                finally:
                    os.close(created_fd)

            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            worker = None
            try:
                with mock.patch.object(
                    SUPERVISOR_MODULE.subprocess,
                    "Popen",
                    side_effect=open_inheritable_then_spawn,
                ):
                    worker = SUPERVISOR_MODULE._spawn_worker(
                        SUPERVISOR_MODULE._capture_helper_source(worker_script),
                        [str(sentinel_metadata), str(observed_file)],
                        python_bin=sys.executable,
                        client_fd=client.fileno(),
                        child_signal_mask=set(
                            signal.pthread_sigmask(signal.SIG_BLOCK, set())
                        ),
                    )
                return_code = worker.wait(timeout=5.0)
            finally:
                if worker is not None and worker.poll() is None:
                    SUPERVISOR_MODULE._terminate_worker(worker, 0.5)
                client.close()
                server.close()

            self.assertIsNotNone(created_fd)
            self.assertEqual(return_code, 0)
            self.assertFalse(
                json.loads(observed_file.read_text(encoding="ascii"))["inherited"]
            )

    def test_spawn_worker_bootstrap_does_not_reopen_supervisor_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            observed_file = root / "observed"
            worker_script.write_text(
                "import pathlib\n"
                "import sys\n"
                "pathlib.Path(sys.argv[1]).write_text('started', encoding='ascii')\n",
                encoding="utf-8",
            )
            observed_argv: list[str] = []
            original_spawn = SUPERVISOR_MODULE.subprocess.Popen

            def capture_argv_then_spawn(
                argv: list[str],
                **kwargs: object,
            ) -> subprocess.Popen[bytes]:
                observed_argv.extend(argv)
                return original_spawn(argv, **kwargs)

            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            worker = None
            try:
                with mock.patch.object(
                    SUPERVISOR_MODULE.subprocess,
                    "Popen",
                    side_effect=capture_argv_then_spawn,
                ):
                    worker = SUPERVISOR_MODULE._spawn_worker(
                        SUPERVISOR_MODULE._capture_helper_source(worker_script),
                        [str(observed_file)],
                        python_bin=sys.executable,
                        client_fd=client.fileno(),
                        child_signal_mask=set(
                            signal.pthread_sigmask(signal.SIG_BLOCK, set())
                        ),
                    )
                return_code = worker.wait(timeout=5.0)
            finally:
                if worker is not None and worker.poll() is None:
                    SUPERVISOR_MODULE._terminate_worker(worker, 0.5)
                client.close()
                server.close()

            self.assertEqual(return_code, 0)
            self.assertEqual(observed_file.read_text(encoding="ascii"), "started")
            self.assertIn("-c", observed_argv)
            self.assertIn(
                SUPERVISOR_MODULE.WORKER_BOOTSTRAP_SOURCE,
                observed_argv,
            )
            self.assertNotIn(
                str(DIRECTORY_SUPERVISOR_PATH),
                observed_argv,
            )

    def test_captured_helper_bytes_survive_post_capture_mutation(self) -> None:
        def helper_source(marker: str) -> bytes:
            return (
                "import pathlib\n"
                "import sys\n"
                f"CAPTURE_MARKER = {marker!r}\n"
                "if __name__ == '__main__':\n"
                "    pathlib.Path(sys.argv[1]).write_text(\n"
                "        CAPTURE_MARKER,\n"
                "        encoding='ascii',\n"
                "    )\n"
            ).encode("ascii")

        captured_source = helper_source("captured")
        replacement_source = helper_source("replaced")
        self.assertEqual(len(captured_source), len(replacement_source))
        self.assertEqual(
            SUPERVISOR_MODULE.HELPER.__captured_source_sha256__,
            SUPERVISOR_MODULE.HELPER_CAPTURE.sha256,
        )

        for mutation in ("atomic-replace", "preheld-in-place-overwrite"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                worker_script = root / "worker.py"
                observed_file = root / "observed"
                worker_script.write_bytes(captured_source)
                held_fd = (
                    os.open(worker_script, os.O_RDWR)
                    if mutation == "preheld-in-place-overwrite"
                    else None
                )
                try:
                    capture = SUPERVISOR_MODULE._capture_helper_source(worker_script)
                    module_name = (
                        f"captured_helper_source_test_{mutation.replace('-', '_')}"
                    )
                    parent_module = SUPERVISOR_MODULE._load_helper(
                        capture,
                        module_name=module_name,
                    )
                    self.addCleanup(sys.modules.pop, module_name, None)
                    self.assertEqual(parent_module.CAPTURE_MARKER, "captured")
                    self.assertEqual(
                        parent_module.__captured_source_sha256__,
                        capture.sha256,
                    )

                    if held_fd is None:
                        replacement = root / "replacement.py"
                        replacement.write_bytes(replacement_source)
                        os.replace(replacement, worker_script)
                    else:
                        self.assertEqual(
                            os.pwrite(held_fd, replacement_source, 0),
                            len(replacement_source),
                        )

                    client, server = socket.socketpair(
                        socket.AF_UNIX,
                        socket.SOCK_DGRAM,
                    )
                    worker = None
                    try:
                        worker = SUPERVISOR_MODULE._spawn_worker(
                            capture,
                            [str(observed_file)],
                            python_bin=sys.executable,
                            client_fd=client.fileno(),
                            child_signal_mask=set(
                                signal.pthread_sigmask(signal.SIG_BLOCK, set())
                            ),
                        )
                        return_code = worker.wait(timeout=5.0)
                    finally:
                        if worker is not None and worker.poll() is None:
                            SUPERVISOR_MODULE._terminate_worker(worker, 0.5)
                        client.close()
                        server.close()
                finally:
                    if held_fd is not None:
                        os.close(held_fd)

                self.assertEqual(return_code, 0)
                self.assertEqual(
                    worker_script.read_bytes(),
                    replacement_source,
                )
                self.assertEqual(
                    observed_file.read_text(encoding="ascii"),
                    "captured",
                )

    def test_spawn_worker_closes_source_descriptor_before_helper_exec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            observed_file = root / "observed"
            worker_script.write_text(
                "import errno\n"
                "import os\n"
                "import pathlib\n"
                "import sys\n"
                "descriptor = int(os.environ['APPLE_NOTES_TEST_SOURCE_FD'])\n"
                "try:\n"
                "    os.fstat(descriptor)\n"
                "except OSError as exc:\n"
                "    closed = exc.errno == errno.EBADF\n"
                "else:\n"
                "    closed = False\n"
                "pathlib.Path(sys.argv[1]).write_text(str(closed), encoding='ascii')\n"
                "if not closed:\n"
                "    raise SystemExit(3)\n",
                encoding="utf-8",
            )
            capture = SUPERVISOR_MODULE._capture_helper_source(worker_script)
            source_descriptors: list[int] = []
            original_spawn = SUPERVISOR_MODULE.subprocess.Popen

            def expose_source_fd_then_spawn(
                argv: list[str],
                **kwargs: object,
            ) -> subprocess.Popen[bytes]:
                source_descriptors.append(int(argv[7]))
                child_env = dict(kwargs["env"])
                child_env["APPLE_NOTES_TEST_SOURCE_FD"] = argv[7]
                kwargs["env"] = child_env
                return original_spawn(argv, **kwargs)

            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            worker = None
            try:
                with mock.patch.object(
                    SUPERVISOR_MODULE.subprocess,
                    "Popen",
                    side_effect=expose_source_fd_then_spawn,
                ):
                    worker = SUPERVISOR_MODULE._spawn_worker(
                        capture,
                        [str(observed_file)],
                        python_bin=sys.executable,
                        client_fd=client.fileno(),
                        child_signal_mask=set(
                            signal.pthread_sigmask(signal.SIG_BLOCK, set())
                        ),
                    )
                return_code = worker.wait(timeout=5.0)
            finally:
                if worker is not None and worker.poll() is None:
                    SUPERVISOR_MODULE._terminate_worker(worker, 0.5)
                client.close()
                server.close()

            self.assertEqual(return_code, 0)
            self.assertEqual(observed_file.read_text(encoding="ascii"), "True")
            self.assertEqual(len(source_descriptors), 1)
            with self.assertRaises(OSError) as raised:
                os.fstat(source_descriptors[0])
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_worker_helper_source_frame_corruption_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            worker_script.write_text(
                "import pathlib\n"
                "import sys\n"
                "pathlib.Path(sys.argv[1]).write_text('executed', encoding='ascii')\n",
                encoding="utf-8",
            )
            capture = SUPERVISOR_MODULE._capture_helper_source(worker_script)
            valid_frame = SUPERVISOR_MODULE._helper_source_frame(capture)
            source_offset = (
                len(SUPERVISOR_MODULE.HELPER_SOURCE_FRAME_MAGIC)
                + 8
                + hashlib.sha256().digest_size
            )
            digest_corruption = bytearray(valid_frame)
            digest_corruption[source_offset] ^= 1
            oversized_header = b"".join(
                (
                    SUPERVISOR_MODULE.HELPER_SOURCE_FRAME_MAGIC,
                    (SUPERVISOR_MODULE.HELPER_SOURCE_MAX_BYTES + 1).to_bytes(
                        8,
                        "big",
                    ),
                    hashlib.sha256(b"oversized").digest(),
                )
            )
            corruptions = {
                "truncated": valid_frame[:-1],
                "digest": bytes(digest_corruption),
                "trailing": valid_frame + b"x",
                "oversize": oversized_header,
            }

            for label, corrupt_frame in corruptions.items():
                with self.subTest(label=label):
                    observed_file = root / f"observed-{label}"
                    client, server = socket.socketpair(
                        socket.AF_UNIX,
                        socket.SOCK_DGRAM,
                    )
                    worker = None
                    try:
                        with mock.patch.object(
                            SUPERVISOR_MODULE,
                            "_helper_source_frame",
                            return_value=corrupt_frame,
                        ):
                            worker = SUPERVISOR_MODULE._spawn_worker(
                                capture,
                                [str(observed_file)],
                                python_bin=sys.executable,
                                client_fd=client.fileno(),
                                child_signal_mask=set(
                                    signal.pthread_sigmask(signal.SIG_BLOCK, set())
                                ),
                            )
                        return_code = worker.wait(timeout=5.0)
                    finally:
                        if worker is not None and worker.poll() is None:
                            SUPERVISOR_MODULE._terminate_worker(worker, 0.5)
                        client.close()
                        server.close()

                    self.assertEqual(return_code, 1)
                    self.assertFalse(observed_file.exists())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(worker.pid, 0)

    def test_helper_source_delivery_errors_reap_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            worker_script = Path(temp_dir) / "worker.py"
            worker_script.write_text("raise SystemExit(0)\n", encoding="utf-8")
            capture = SUPERVISOR_MODULE._capture_helper_source(worker_script)

            for delivery_error in (
                TimeoutError("simulated helper source delivery timeout"),
                BrokenPipeError(errno.EPIPE, "simulated helper source reader exit"),
            ):
                with self.subTest(error=type(delivery_error).__name__):
                    spawned_pids: list[int] = []
                    original_spawn = SUPERVISOR_MODULE.subprocess.Popen

                    def record_spawn(
                        *args: object,
                        **kwargs: object,
                    ) -> subprocess.Popen[bytes]:
                        process = original_spawn(*args, **kwargs)
                        spawned_pids.append(process.pid)
                        return process

                    client, server = socket.socketpair(
                        socket.AF_UNIX,
                        socket.SOCK_DGRAM,
                    )
                    try:
                        with (
                            mock.patch.object(
                                SUPERVISOR_MODULE.subprocess,
                                "Popen",
                                side_effect=record_spawn,
                            ),
                            mock.patch.object(
                                SUPERVISOR_MODULE,
                                "_write_helper_source_frame",
                                side_effect=delivery_error,
                            ),
                        ):
                            with self.assertRaises(type(delivery_error)):
                                SUPERVISOR_MODULE._spawn_worker(
                                    capture,
                                    ["ignored"],
                                    python_bin=sys.executable,
                                    client_fd=client.fileno(),
                                    child_signal_mask=set(
                                        signal.pthread_sigmask(signal.SIG_BLOCK, set())
                                    ),
                                )
                    finally:
                        client.close()
                        server.close()

                    self.assertEqual(len(spawned_pids), 1)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(spawned_pids[0], 0)

    def test_helper_source_delivery_times_out_on_a_real_full_pipe(self) -> None:
        read_fd, write_fd = os.pipe()
        frame = b"x" * (
            len(SUPERVISOR_MODULE.HELPER_SOURCE_FRAME_MAGIC)
            + 8
            + hashlib.sha256().digest_size
            + SUPERVISOR_MODULE.HELPER_SOURCE_MAX_BYTES
        )
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                SUPERVISOR_MODULE._write_helper_source_frame(
                    write_fd,
                    frame,
                    timeout_seconds=0.05,
                )
        finally:
            os.close(write_fd)
            os.close(read_fd)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_run_supervised_uses_one_capture_for_service_and_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            helper_path = root / "helper.py"
            service_evidence = root / "service-digest"
            worker_evidence = root / "worker-digest"
            helper_path.write_text(
                self._supervised_worker_source(
                    "import pathlib\n"
                    "import sys\n"
                    "pathlib.Path(sys.argv[1]).write_text(\n"
                    "    __captured_source_sha256__,\n"
                    "    encoding='ascii',\n"
                    ")"
                ),
                encoding="utf-8",
            )
            expected_capture = SUPERVISOR_MODULE._capture_helper_source(helper_path)
            module_prefix = "apple_notes_test_supervised_helper_"
            modules_before = {
                name for name in sys.modules if name.startswith(module_prefix)
            }

            def record_service_capture(
                supervisor_fd: int,
                helper_module: object,
            ) -> int:
                try:
                    service_evidence.write_text(
                        helper_module.__captured_source_sha256__,
                        encoding="ascii",
                    )
                finally:
                    os.close(supervisor_fd)
                return 0

            with mock.patch.object(
                SUPERVISOR_MODULE,
                "_serve",
                new=record_service_capture,
            ):
                return_code = self._run_supervised_test_helper(
                    helper_path,
                    [str(worker_evidence)],
                )

            self.assertEqual(return_code, 0)
            self.assertEqual(
                service_evidence.read_text(encoding="ascii"),
                expected_capture.sha256,
            )
            self.assertEqual(
                worker_evidence.read_text(encoding="ascii"),
                expected_capture.sha256,
            )
            self.assertEqual(
                {name for name in sys.modules if name.startswith(module_prefix)},
                modules_before,
            )

    def test_production_launcher_rejects_custom_helper_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            helper_path = root / "helper.py"
            execution_evidence = root / "custom-helper-executed"
            helper_path.write_text(
                "import pathlib\n"
                f"pathlib.Path({str(execution_evidence)!r}).write_text(\n"
                "    'executed',\n"
                "    encoding='ascii',\n"
                ")\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(
                    SUPERVISOR_MODULE.os,
                    "fork",
                    side_effect=AssertionError("service must not fork"),
                ) as fork,
                mock.patch.object(
                    SUPERVISOR_MODULE.subprocess,
                    "Popen",
                    side_effect=AssertionError("worker must not spawn"),
                ) as spawn,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "custom --helper paths are unsupported",
                ):
                    SUPERVISOR_MODULE.run_supervised(
                        helper_path,
                        ["ignored"],
                        python_bin=sys.executable,
                    )

            fork.assert_not_called()
            spawn.assert_not_called()
            self.assertFalse(execution_evidence.exists())

    def test_helper_capture_failures_precede_service_or_worker_spawn(self) -> None:
        def assert_fails_before_spawn(helper_path: Path) -> None:
            with (
                mock.patch.object(
                    SUPERVISOR_MODULE.os,
                    "fork",
                    side_effect=AssertionError("service must not fork"),
                ) as fork,
                mock.patch.object(
                    SUPERVISOR_MODULE.subprocess,
                    "Popen",
                    side_effect=AssertionError("worker must not spawn"),
                ) as spawn,
            ):
                with self.assertRaises(RuntimeError):
                    SUPERVISOR_MODULE._capture_helper_source(helper_path)
            fork.assert_not_called()
            spawn.assert_not_called()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            helper = root / "helper.py"
            helper.write_text("raise SystemExit(0)\n", encoding="utf-8")
            helper_symlink = root / "helper-link.py"
            helper_symlink.symlink_to(helper)
            assert_fails_before_spawn(helper_symlink)
            assert_fails_before_spawn(root)

            original_fstat = SUPERVISOR_MODULE.os.fstat
            fstat_calls = 0

            def report_access_drift(descriptor: int) -> os.stat_result:
                nonlocal fstat_calls
                fstat_calls += 1
                opened = original_fstat(descriptor)
                if fstat_calls == 2:
                    return _StatWithOverrides(
                        opened,
                        st_mode=opened.st_mode ^ stat.S_IWGRP,
                    )
                return opened

            with mock.patch.object(
                SUPERVISOR_MODULE.os,
                "fstat",
                side_effect=report_access_drift,
            ):
                assert_fails_before_spawn(helper)

            replacement = b"raise SystemExit(1)\n"
            self.assertEqual(len(helper.read_bytes()), len(replacement))
            held_fd = os.open(helper, os.O_RDWR)
            original_read_pass = SUPERVISOR_MODULE._read_helper_source_pass
            read_passes = 0

            def overwrite_between_capture_passes(
                descriptor: int,
                expected_size: int,
            ) -> bytes:
                nonlocal read_passes
                captured = original_read_pass(descriptor, expected_size)
                read_passes += 1
                if read_passes == 1:
                    self.assertEqual(
                        os.pwrite(held_fd, replacement, 0),
                        len(replacement),
                    )
                return captured

            try:
                with mock.patch.object(
                    SUPERVISOR_MODULE,
                    "_read_helper_source_pass",
                    side_effect=overwrite_between_capture_passes,
                ):
                    assert_fails_before_spawn(helper)
            finally:
                os.close(held_fd)

            helper.write_text("raise SystemExit(0)\n", encoding="utf-8")
            original_open = SUPERVISOR_MODULE.os.open
            open_flags: list[int] = []

            def replace_regular_helper_with_fifo(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                open_flags.append(flags)
                os.unlink(helper)
                os.mkfifo(helper)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    SUPERVISOR_MODULE.os,
                    "open",
                    side_effect=replace_regular_helper_with_fifo,
                ),
                _fail_if_deadline_exceeded(1.0),
            ):
                assert_fails_before_spawn(helper)
            self.assertEqual(len(open_flags), 1)
            self.assertTrue(open_flags[0] & os.O_NONBLOCK)

    def test_spawn_worker_restores_default_signal_dispositions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            observed_file = root / "observed.json"
            worker_script.write_text(
                self._supervised_worker_source(
                    "import json\n"
                    "import pathlib\n"
                    "import signal\n"
                    "import sys\n"
                    "signals = json.loads(sys.argv[2])\n"
                    "pathlib.Path(sys.argv[1]).write_text(\n"
                    "    json.dumps(\n"
                    "        {str(value): signal.getsignal(value) for value in signals}\n"
                    "    ),\n"
                    "    encoding='ascii',\n"
                    ")"
                ),
                encoding="utf-8",
            )
            defaults = sorted(
                int(signum) for signum in SUPERVISOR_MODULE.SPAWN_DEFAULT_SIGNALS
            )
            original_handlers = {
                signum: signal.getsignal(signum) for signum in defaults
            }
            try:
                for signum in defaults:
                    signal.signal(signum, signal.SIG_IGN)
                return_code = self._run_supervised_test_helper(
                    worker_script,
                    [str(observed_file), json.dumps(defaults)],
                )
                restored_handlers = {
                    signum: signal.getsignal(signum) for signum in defaults
                }
            finally:
                for signum, handler in original_handlers.items():
                    signal.signal(signum, handler)

            self.assertEqual(return_code, 0)
            self.assertEqual(
                restored_handlers,
                {signum: signal.SIG_IGN for signum in defaults},
            )
            observed = json.loads(observed_file.read_text(encoding="ascii"))
            self.assertEqual(
                observed,
                {str(signum): signal.SIG_DFL for signum in defaults},
            )

    def test_spawn_worker_restores_exact_selected_signal_mask(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            observed_file = root / "observed.json"
            worker_script.write_text(
                self._supervised_worker_source(
                    "import json\n"
                    "import pathlib\n"
                    "import signal\n"
                    "import sys\n"
                    "current = signal.pthread_sigmask(signal.SIG_BLOCK, set())\n"
                    "pathlib.Path(sys.argv[1]).write_text(\n"
                    "    json.dumps(sorted(int(signum) for signum in current)),\n"
                    "    encoding='ascii',\n"
                    ")"
                ),
                encoding="utf-8",
            )
            original_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGUSR1},
            )
            expected_mask = set(original_mask).union({signal.SIGUSR1})
            try:
                return_code = self._run_supervised_test_helper(
                    worker_script,
                    [str(observed_file)],
                )
                retained_parent_mask = signal.pthread_sigmask(
                    signal.SIG_BLOCK,
                    set(),
                )
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

            self.assertEqual(return_code, 0)
            self.assertEqual(retained_parent_mask, expected_mask)
            self.assertEqual(
                json.loads(observed_file.read_text(encoding="ascii")),
                sorted(int(signum) for signum in expected_mask),
            )

    def test_pending_signal_drain_is_snapshot_bounded(self) -> None:
        with (
            mock.patch.object(
                SUPERVISOR_MODULE.signal,
                "sigpending",
                return_value={signal.SIGTERM},
            ) as pending,
            mock.patch.object(
                SUPERVISOR_MODULE.signal,
                "sigwait",
                return_value=signal.SIGTERM,
            ) as wait,
        ):
            first_signal = SUPERVISOR_MODULE._drain_pending_termination_signals(
                {signal.SIGTERM},
                None,
            )

        self.assertEqual(first_signal, signal.SIGTERM)
        pending.assert_called_once_with()
        wait.assert_called_once_with({signal.SIGTERM})

    def test_supervisor_normalizes_ignored_sigchld_and_restores(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            worker_script = Path(temp_dir) / "worker.py"
            worker_script.write_text(
                self._supervised_worker_source("raise SystemExit(0)"),
                encoding="utf-8",
            )
            original_sigchld_handler = signal.getsignal(signal.SIGCHLD)
            original_sigterm_handler = signal.getsignal(signal.SIGTERM)
            original_mask = signal.pthread_sigmask(
                signal.SIG_UNBLOCK,
                {signal.SIGCHLD},
            )
            expected_mask = set(original_mask).difference({signal.SIGCHLD})

            def retained_sigterm_handler(_signum: int, _frame: object) -> None:
                pass

            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, retained_sigterm_handler)
            try:
                return_code = self._run_supervised_test_helper(
                    worker_script,
                    ["ignored"],
                )
                restored_sigchld_handler = signal.getsignal(signal.SIGCHLD)
                restored_sigterm_handler = signal.getsignal(signal.SIGTERM)
                restored_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            finally:
                signal.signal(signal.SIGCHLD, original_sigchld_handler)
                signal.signal(signal.SIGTERM, original_sigterm_handler)
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

        self.assertEqual(return_code, 0)
        self.assertEqual(restored_sigchld_handler, signal.SIG_IGN)
        self.assertIs(restored_sigterm_handler, retained_sigterm_handler)
        self.assertEqual(restored_mask, expected_mask)

    def test_supervisor_echild_status_is_conservative_and_terminal(self) -> None:
        process = mock.Mock(pid=12345, returncode=None)
        worker = SUPERVISOR_MODULE._SpawnedWorker(12345, process=process)
        no_child = ChildProcessError(errno.ECHILD, "simulated external reap")
        with mock.patch.object(
            SUPERVISOR_MODULE.os,
            "waitpid",
            side_effect=no_child,
        ) as waitpid:
            self.assertEqual(
                worker.poll(),
                SUPERVISOR_MODULE.WORKER_RETURN_CODE_UNAVAILABLE,
            )
            self.assertEqual(
                worker.poll(),
                SUPERVISOR_MODULE.WORKER_RETURN_CODE_UNAVAILABLE,
            )
        waitpid.assert_called_once_with(12345, os.WNOHANG)
        self.assertEqual(process.returncode, 1)

        with mock.patch.object(
            SUPERVISOR_MODULE.os,
            "waitpid",
            side_effect=no_child,
        ):
            self.assertEqual(
                SUPERVISOR_MODULE._wait_pid(12345, time.monotonic()),
                SUPERVISOR_MODULE.WAIT_STATUS_UNAVAILABLE,
            )

    def test_packaged_supervisor_fails_before_same_uid_mkdir_open_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            client, server = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_DGRAM,
            )
            request_id = "same-uid-mkdir-open-replacement"
            parent = os.fstat(parent_fd)
            request = json.dumps(
                {
                    "schema": MODULE.DIRECTORY_CREATOR_REQUEST_SCHEMA,
                    "request_id": request_id,
                    "operation": "create-owner-private-directory",
                    "prefix": ".apple-notes-create-",
                    "mode": 0o700,
                    "expected_uid": os.geteuid(),
                    "parent_identity": MODULE._identity(parent),
                    "parent_access_policy": MODULE._access_policy(parent),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            original_mkdir = os.mkdir
            original_open = os.open

            def replace_after_mkdir(
                name: str,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> None:
                assert dir_fd is not None
                original_mkdir(name, mode=mode, dir_fd=dir_fd)
                os.rename(
                    name,
                    "attacker-parked-created-object",
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
                original_mkdir(name, mode=0o700, dir_fd=dir_fd)

            try:
                with (
                    mock.patch.object(
                        SUPERVISOR_MODULE.os,
                        "mkdir",
                        side_effect=replace_after_mkdir,
                    ) as mkdir,
                    mock.patch.object(
                        SUPERVISOR_MODULE.os,
                        "open",
                        side_effect=original_open,
                    ) as open_directory,
                ):
                    SUPERVISOR_MODULE._serve_one_request(
                        server,
                        request,
                        [os.dup(parent_fd)],
                        SUPERVISOR_MODULE.HELPER,
                    )
                payload, ancillary, flags, _ = client.recvmsg(
                    MODULE.DIRECTORY_CREATOR_MAX_MESSAGE_BYTES,
                    socket.CMSG_SPACE(
                        array.array("i").itemsize
                        * MODULE.DIRECTORY_CREATOR_MAX_RECEIVED_FDS
                    ),
                )
            finally:
                client.close()
                server.close()
                os.close(parent_fd)
            root_entries = list(root.iterdir())

        mkdir.assert_not_called()
        open_directory.assert_not_called()
        self.assertEqual(flags, 0)
        self.assertEqual(MODULE._received_rights_descriptors(ancillary), [])
        response = json.loads(payload.decode("utf-8"))
        self.assertEqual(
            response,
            {
                "schema": MODULE.DIRECTORY_CREATOR_RESPONSE_SCHEMA,
                "request_id": request_id,
                "status": MODULE.DIRECTORY_CREATOR_UNAVAILABLE_STATUS,
                "basename": None,
                "proof": None,
                "details": MODULE._packaged_directory_creator_unavailable_details(),
            },
        )
        self.assertEqual(root_entries, [])

    def test_creator_cli_safely_publishes_external_result_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            result_file = root / "snapshot-creation-result.json"
            stdout = io.StringIO()
            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                redirect_stdout(stdout),
            ):
                return_code = MODULE.main(
                    [
                        "copy-db",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--dest",
                        str(destination),
                        "--result-file",
                        str(result_file),
                    ]
                )

            self.assertEqual(return_code, 0, stdout.getvalue())
            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(result_file.read_text(encoding="utf-8"))
            result_stat = os.stat(result_file, follow_symlinks=False)

        self.assertEqual(return_code, 0)
        self.assertEqual(file_payload, stdout_payload)
        self.assertEqual(Path(file_payload["dest"]), destination)
        self.assertEqual(stat.S_IMODE(result_stat.st_mode), 0o600)
        self.assertEqual(result_stat.st_uid, os.geteuid())
        self.assertEqual(result_stat.st_gid, os.getegid())

    def test_creator_result_rejects_prebind_artifact_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            parked = root / "snapshot-original"
            result_file = root / "snapshot-creation-result.json"
            original_write = MODULE._write_creator_result_file
            attacked = False

            def replace_before_result_binding(
                result_destination: MODULE._CreatorResultDestination,
                artifact: Path,
                payload: dict[str, object],
            ) -> dict[str, object]:
                nonlocal attacked
                requested_artifact = Path(artifact)
                requested_artifact.rename(parked)
                shutil.copytree(parked, requested_artifact)
                attacked = True
                return original_write(
                    result_destination,
                    requested_artifact,
                    payload,
                )

            stdout = io.StringIO()
            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_write_creator_result_file",
                    side_effect=replace_before_result_binding,
                ),
                redirect_stdout(stdout),
            ):
                return_code = MODULE.main(
                    [
                        "copy-db",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--dest",
                        str(destination),
                        "--result-file",
                        str(result_file),
                    ]
                )

            error_payload = json.loads(stdout.getvalue())
            result_exists = result_file.exists()
            artifact_exists = destination.is_dir()
            parked_exists = parked.is_dir()

        self.assertTrue(attacked)
        self.assertEqual(return_code, 1)
        self.assertEqual(
            error_payload["error_code"],
            "result-file-publication-failed",
        )
        self.assertEqual(
            error_payload["details"]["underlying_error_code"],
            "prepared-directory-identity-mismatch",
        )
        self.assertFalse(result_exists)
        self.assertTrue(artifact_exists)
        self.assertTrue(parked_exists)

    @unittest.skipUnless(sys.platform == "darwin", "macOS root alias contract")
    def test_creator_cli_publishes_results_across_alias_and_nonalias_roots(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory(dir="/tmp") as tmp_dir,
            tempfile.TemporaryDirectory(dir=REPO_ROOT) as user_dir,
        ):
            tmp_root = Path(tmp_dir)
            user_root = Path(user_dir)
            cases = (
                ("copy-db", user_root, tmp_root),
                ("stage-patch", tmp_root, user_root),
            )
            for command, artifact_root, result_root in cases:
                with self.subTest(command=command):
                    live_root = artifact_root / f"{command}-live"
                    live_root.mkdir()
                    paths = self._make_paths(live_root)
                    destination = artifact_root / f"{command}-artifact"
                    result_file = result_root / f"{command}-result.json"
                    artifact_alias = MODULE._trusted_alias_paths(destination)[2]
                    result_alias = MODULE._trusted_alias_paths(result_file)[2]
                    self.assertNotEqual(artifact_alias, result_alias)

                    argv = [
                        command,
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                    ]
                    if command == "copy-db":
                        self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                        argv.extend(["--dest", str(destination)])
                    else:
                        edited = artifact_root / "edited.sqlite"
                        self._create_db(edited)
                        argv.extend(
                            [
                                "--src",
                                str(edited),
                                "--dest",
                                str(destination),
                            ]
                        )
                    argv.extend(["--result-file", str(result_file)])

                    stdout = io.StringIO()
                    with (
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        redirect_stdout(stdout),
                    ):
                        return_code = MODULE.main(argv)

                    self.assertEqual(return_code, 0, stdout.getvalue())
                    stdout_payload = json.loads(stdout.getvalue())
                    file_payload = json.loads(result_file.read_text(encoding="utf-8"))
                    self.assertEqual(file_payload, stdout_payload)
                    self.assertTrue(destination.is_dir())
                    self.assertEqual(
                        stat.S_IMODE(
                            os.stat(result_file, follow_symlinks=False).st_mode
                        ),
                        0o600,
                    )

    def test_creator_cli_independently_binds_distinct_trusted_aliases(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            artifact_target = root / "artifact-target"
            result_target = root / "result-target"
            artifact_target.mkdir()
            result_target.mkdir()
            artifact_alias = root / "artifact-alias"
            result_alias = root / "result-alias"
            artifact_alias.symlink_to(artifact_target, target_is_directory=True)
            result_alias.symlink_to(result_target, target_is_directory=True)
            registry = (
                (artifact_alias, artifact_target),
                (result_alias, result_target),
            )
            destination = artifact_alias / "snapshot"
            result_file = result_alias / "snapshot-creation-result.json"
            stdout = io.StringIO()

            with (
                mock.patch.object(
                    MODULE,
                    "_trusted_directory_alias_registry",
                    return_value=registry,
                ),
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                redirect_stdout(stdout),
            ):
                return_code = MODULE.main(
                    [
                        "copy-db",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--dest",
                        str(destination),
                        "--result-file",
                        str(result_file),
                    ]
                )

            self.assertEqual(return_code, 0, stdout.getvalue())
            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(result_file.read_text(encoding="utf-8"))
            result_stat = os.stat(result_file, follow_symlinks=False)
            artifact_exists = (artifact_target / "snapshot").is_dir()
            result_exists = (result_target / "snapshot-creation-result.json").is_file()

        self.assertEqual(file_payload, stdout_payload)
        self.assertEqual(Path(file_payload["dest"]), destination)
        self.assertTrue(artifact_exists)
        self.assertTrue(result_exists)
        self.assertEqual(stat.S_IMODE(result_stat.st_mode), 0o600)

    def test_creator_result_teardown_failure_retains_committed_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            result_file = root / "snapshot-creation-result.json"
            expected_result = Path(os.path.abspath(result_file))
            original_commit = MODULE._commit_live_safe_destination_parent

            @contextmanager
            def fail_result_scope_after_yield(
                preflight: MODULE._LiveDestinationPreflight,
            ) -> Iterator[MODULE._LiveDestinationScope]:
                with original_commit(preflight) as result_scope:
                    yield result_scope
                    if result_scope.destination == expected_result:
                        raise MODULE.StoreSafetyError(
                            "prepared-directory-identity-mismatch",
                            "simulated result-scope post-yield failure",
                        )

            stdout = io.StringIO()
            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_commit_live_safe_destination_parent",
                    side_effect=fail_result_scope_after_yield,
                ),
                redirect_stdout(stdout),
            ):
                return_code = MODULE.main(
                    [
                        "copy-db",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--dest",
                        str(destination),
                        "--result-file",
                        str(result_file),
                    ]
                )

            error_payload = json.loads(stdout.getvalue())
            details = error_payload["details"]
            committed_payload = json.loads(result_file.read_text(encoding="utf-8"))
            committed_bytes = result_file.read_bytes()
            artifact_exists = destination.is_dir()

        self.assertEqual(return_code, 1)
        self.assertEqual(
            error_payload["error_code"],
            "result-file-publication-failed",
        )
        self.assertTrue(artifact_exists)
        self.assertEqual(Path(committed_payload["dest"]), destination)
        self.assertTrue(details["artifact_mutation_performed"])
        self.assertEqual(
            details["result_file_publication_state"],
            "committed",
        )
        self.assertFalse(details["retry_safe"])
        self.assertEqual(
            details["underlying_error_code"],
            "prepared-directory-identity-mismatch",
        )
        self.assertEqual(
            details["result_file_receipt"]["sha256"],
            hashlib.sha256(committed_bytes).hexdigest(),
        )

    def test_creator_artifact_preflight_teardown_failure_retains_receipt(
        self,
    ) -> None:
        for command in ("copy-db", "stage-patch"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                destination = root / f"{command}-artifact"
                expected_artifact = Path(os.path.abspath(destination))
                original_raw_preflight = (
                    MODULE._preflight_live_safe_destination_parent_raw
                )
                original_post_publication_error = (
                    MODULE._post_publication_uncertain_error
                )
                teardown_error_details: list[dict[str, object]] = []

                @contextmanager
                def fail_artifact_preflight_after_yield(
                    preflight_paths: MODULE.NoteStorePaths,
                    preflight_destination: Path,
                    *,
                    trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
                ) -> Iterator[MODULE._LiveDestinationPreflight]:
                    with original_raw_preflight(
                        preflight_paths,
                        preflight_destination,
                        trusted_alias=trusted_alias,
                    ) as preflight:
                        yield preflight
                    if preflight.requested_destination == expected_artifact:
                        raise MODULE.StoreSafetyError(
                            "prepared-directory-identity-mismatch",
                            "simulated original preflight teardown failure",
                            details={"mutation_performed": False},
                        )

                def capture_post_publication_error(
                    exc: BaseException,
                    **kwargs: object,
                ) -> MODULE.StoreSafetyError:
                    if isinstance(exc, MODULE.StoreSafetyError):
                        teardown_error_details.append(dict(exc.details))
                    return original_post_publication_error(exc, **kwargs)

                argv = [
                    command,
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                if command == "copy-db":
                    argv.extend(["--dest", str(destination)])
                else:
                    argv.extend(
                        [
                            "--src",
                            str(edited),
                            "--dest",
                            str(destination),
                        ]
                    )
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_preflight_live_safe_destination_parent_raw",
                        side_effect=fail_artifact_preflight_after_yield,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_post_publication_uncertain_error",
                        side_effect=capture_post_publication_error,
                    ),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(argv)

                error_payload = json.loads(stdout.getvalue())
                details = error_payload["details"]
                recovery = details["recovery_locators"]["descriptor_bound_destination"]

                self.assertEqual(return_code, 1)
                self.assertEqual(
                    error_payload["error_code"],
                    "destination-install-uncertain",
                )
                self.assertTrue(destination.is_dir())
                self.assertTrue(details["mutation_performed"])
                self.assertTrue(details["artifact_mutation_performed"])
                self.assertEqual(len(teardown_error_details), 1)
                self.assertNotIn(
                    "mutation_performed",
                    teardown_error_details[0],
                )
                self.assertEqual(
                    details["artifact_publication_state"],
                    "committed",
                )
                self.assertEqual(details["publication_state"], "uncertain")
                self.assertFalse(details["retry_safe"])
                self.assertEqual(
                    details["post_publication_phase"],
                    "creator-destination-preflight-teardown",
                )
                self.assertEqual(
                    details["post_publication_error_code"],
                    "prepared-directory-identity-mismatch",
                )
                self.assertEqual(
                    Path(recovery["display_path"]),
                    expected_artifact,
                )

    def test_creator_committed_result_survives_artifact_preflight_teardown(
        self,
    ) -> None:
        for command in ("copy-db", "stage-patch"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                destination = root / f"{command}-artifact"
                result_file = root / f"{command}-creation-result.json"
                expected_artifact = Path(os.path.abspath(destination))
                original_raw_preflight = (
                    MODULE._preflight_live_safe_destination_parent_raw
                )

                @contextmanager
                def fail_artifact_preflight_after_yield(
                    preflight_paths: MODULE.NoteStorePaths,
                    preflight_destination: Path,
                    *,
                    trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
                ) -> Iterator[MODULE._LiveDestinationPreflight]:
                    with original_raw_preflight(
                        preflight_paths,
                        preflight_destination,
                        trusted_alias=trusted_alias,
                    ) as preflight:
                        yield preflight
                    if preflight.requested_destination == expected_artifact:
                        raise MODULE.StoreSafetyError(
                            "prepared-directory-identity-mismatch",
                            "simulated original preflight teardown failure",
                            details={"mutation_performed": False},
                        )

                argv = [
                    command,
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                if command == "copy-db":
                    argv.extend(["--dest", str(destination)])
                else:
                    argv.extend(
                        [
                            "--src",
                            str(edited),
                            "--dest",
                            str(destination),
                        ]
                    )
                argv.extend(["--result-file", str(result_file)])
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_preflight_live_safe_destination_parent_raw",
                        side_effect=fail_artifact_preflight_after_yield,
                    ),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(argv)

                error_payload = json.loads(stdout.getvalue())
                details = error_payload["details"]
                committed_payload = json.loads(result_file.read_text(encoding="utf-8"))
                committed_bytes = result_file.read_bytes()
                artifact_recovery = details["recovery_locators"][
                    "artifact_descriptor_bound_destination"
                ]
                result_recovery = details["recovery_locators"]["result_file_receipt"]
                expected_result_sha256 = hashlib.sha256(committed_bytes).hexdigest()

                self.assertEqual(return_code, 1)
                self.assertEqual(
                    error_payload["error_code"],
                    "result-file-publication-failed",
                )
                self.assertTrue(destination.is_dir())
                self.assertEqual(
                    Path(
                        committed_payload.get(
                            "dest",
                            committed_payload.get("stage_dir"),
                        )
                    ),
                    destination,
                )
                self.assertTrue(details["mutation_performed"])
                self.assertTrue(details["artifact_mutation_performed"])
                self.assertEqual(
                    details["artifact_publication_state"],
                    "committed",
                )
                self.assertEqual(
                    details["result_file_publication_state"],
                    "committed",
                )
                self.assertFalse(details["retry_safe"])
                self.assertEqual(
                    details["underlying_error_code"],
                    "prepared-directory-identity-mismatch",
                )
                self.assertEqual(
                    Path(artifact_recovery["display_path"]),
                    expected_artifact,
                )
                self.assertEqual(
                    details["result_file_receipt"]["sha256"],
                    expected_result_sha256,
                )
                self.assertEqual(
                    result_recovery["sha256"],
                    expected_result_sha256,
                )

    def test_stage_cli_safely_publishes_external_result_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            result_file = root / "stage-creation-result.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = MODULE.main(
                    [
                        "stage-patch",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--src",
                        str(edited),
                        "--dest",
                        str(destination),
                        "--result-file",
                        str(result_file),
                    ]
                )

            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(result_file.read_text(encoding="utf-8"))
            result_stat = os.stat(result_file, follow_symlinks=False)

        self.assertEqual(return_code, 0)
        self.assertEqual(file_payload, stdout_payload)
        self.assertEqual(Path(file_payload["stage_dir"]), destination)
        self.assertEqual(stat.S_IMODE(result_stat.st_mode), 0o600)
        self.assertEqual(result_stat.st_uid, os.geteuid())
        self.assertEqual(result_stat.st_gid, os.getegid())

    def test_creator_result_rejects_inplace_mutation_after_result_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            result_file = root / "stage-creation-result.json"
            original_write = MODULE._write_json_atomic
            attacked = False

            def mutate_after_result_commit(
                path: Path,
                payload: dict[str, object],
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal attacked
                receipt = original_write(
                    path,
                    payload,
                    **kwargs,
                )
                if Path(path) == result_file:
                    database = destination / MODULE.NOTE_STORE_MAIN
                    with database.open("ab") as handle:
                        handle.write(b"simulated post-publication mutation")
                        handle.flush()
                        os.fsync(handle.fileno())
                    attacked = True
                return receipt

            stdout = io.StringIO()
            with (
                mock.patch.object(
                    MODULE,
                    "_write_json_atomic",
                    side_effect=mutate_after_result_commit,
                ),
                redirect_stdout(stdout),
            ):
                return_code = MODULE.main(
                    [
                        "stage-patch",
                        "--group-container",
                        str(paths.group_container),
                        "--app-container",
                        str(paths.app_container),
                        "--src",
                        str(edited),
                        "--dest",
                        str(destination),
                        "--result-file",
                        str(result_file),
                    ]
                )

            error_payload = json.loads(stdout.getvalue())
            result_exists = result_file.exists()
            artifact_exists = destination.is_dir()
            committed_payload = json.loads(result_file.read_text(encoding="utf-8"))
            committed_bytes = result_file.read_bytes()
            mutated_sha256 = hashlib.sha256(
                (destination / MODULE.NOTE_STORE_MAIN).read_bytes()
            ).hexdigest()

        self.assertTrue(attacked)
        self.assertEqual(return_code, 1)
        self.assertEqual(
            error_payload["error_code"],
            "result-file-publication-failed",
        )
        self.assertEqual(
            error_payload["details"]["underlying_error_code"],
            "prepared-file-content-mismatch",
        )
        self.assertEqual(
            error_payload["details"]["result_file_publication_state"],
            "committed",
        )
        self.assertEqual(
            error_payload["details"]["result_file_receipt"]["sha256"],
            hashlib.sha256(committed_bytes).hexdigest(),
        )
        self.assertTrue(result_exists)
        self.assertTrue(artifact_exists)
        self.assertEqual(Path(committed_payload["stage_dir"]), destination)
        self.assertNotEqual(committed_payload["sha256"], mutated_sha256)

    def test_creator_cli_never_replaces_result_leaf_or_writes_inside_artifact(
        self,
    ) -> None:
        for attack in ("existing-file", "symlink", "inside-artifact"):
            with (
                self.subTest(attack=attack),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                destination = root / "snapshot"
                target = root / "do-not-truncate.json"
                target.write_text("preserve-me", encoding="utf-8")
                if attack == "existing-file":
                    result_file = root / "creation-result.json"
                    result_file.write_text("existing-result", encoding="utf-8")
                elif attack == "symlink":
                    result_file = root / "creation-result.json"
                    result_file.symlink_to(target)
                else:
                    result_file = destination / "creation-result.json"
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(
                        [
                            "copy-db",
                            "--group-container",
                            str(paths.group_container),
                            "--app-container",
                            str(paths.app_container),
                            "--dest",
                            str(destination),
                            "--result-file",
                            str(result_file),
                        ]
                    )

                self.assertEqual(return_code, 1)
                self.assertEqual(
                    json.loads(stdout.getvalue())["error_code"],
                    (
                        "result-file-not-external"
                        if attack == "inside-artifact"
                        else "result-file-exists"
                    ),
                )
                self.assertFalse(destination.exists())
                self.assertEqual(
                    target.read_text(encoding="utf-8"),
                    "preserve-me",
                )
                if attack == "existing-file":
                    self.assertEqual(
                        result_file.read_text(encoding="utf-8"),
                        "existing-result",
                    )

    def test_creator_cli_preflight_failures_leave_missing_result_parent_absent(
        self,
    ) -> None:
        cases = (
            ("copy-db", "artifact-exists", "destination-exists"),
            ("copy-db", "notes-running", "notes-running"),
            (
                "copy-db",
                "live-overlap",
                "snapshot-destination-inside-live-container",
            ),
            ("copy-db", "result-overlap", "result-file-not-external"),
            ("stage-patch", "artifact-exists", "destination-exists"),
            (
                "stage-patch",
                "live-overlap",
                "snapshot-destination-inside-live-container",
            ),
            ("stage-patch", "result-overlap", "result-file-not-external"),
        )
        for command, failure, expected_code in cases:
            with (
                self.subTest(command=command, failure=failure),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                destination = root / f"{command}-{failure}-artifact"
                if failure == "artifact-exists":
                    destination.mkdir()
                elif failure == "live-overlap":
                    destination = paths.group_container / "artifact"
                result_parent = root / f"{command}-{failure}-result-parent"
                result_file = result_parent / "result.json"
                if failure == "result-overlap":
                    result_parent = destination / "result-parent"
                    result_file = result_parent / "result.json"

                argv = [
                    command,
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                if command == "copy-db":
                    argv.extend(["--dest", str(destination)])
                    if failure == "notes-running":
                        argv.append("--require-notes-quit")
                else:
                    argv.extend(
                        [
                            "--src",
                            str(edited),
                            "--dest",
                            str(destination),
                        ]
                    )
                argv.extend(["--result-file", str(result_file)])

                creator = mock.Mock(
                    side_effect=AssertionError(
                        "read-only creator preflight must not invoke a creator"
                    )
                )
                commit = mock.Mock(
                    side_effect=AssertionError(
                        "read-only creator preflight must not enter commit"
                    )
                )
                bind_result = mock.Mock(
                    side_effect=AssertionError(
                        "read-only creator preflight must not bind result commit"
                    )
                )
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=(failure == "notes-running"),
                    ),
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        creator,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_commit_live_safe_destination_parent",
                        commit,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_bind_creator_result_destination",
                        bind_result,
                    ),
                    mock.patch.object(MODULE.os, "mkdir") as mkdir,
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(argv)

                payload = json.loads(stdout.getvalue())
                self.assertEqual(return_code, 1)
                self.assertEqual(payload["error_code"], expected_code)
                self.assertFalse(payload["details"]["mutation_performed"])
                creator.assert_not_called()
                commit.assert_not_called()
                bind_result.assert_not_called()
                mkdir.assert_not_called()
                self.assertFalse(result_parent.exists())
                if failure != "artifact-exists":
                    self.assertFalse(destination.exists())

    def test_creator_cli_rejects_replacement_between_destination_preflights(
        self,
    ) -> None:
        for command in ("copy-db", "stage-patch"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                artifact_parent = root / f"{command}-artifact-parent"
                artifact_parent.mkdir()
                parked_parent = root / f"{command}-artifact-parent-original"
                destination = artifact_parent / "artifact"
                result_parent = root / f"{command}-result-parent"
                result_file = result_parent / "result.json"
                original_preflight = MODULE._preflight_live_safe_destination_parent
                preflight_count = 0

                @contextmanager
                def replace_after_second_preflight(
                    bound_paths: MODULE.NoteStorePaths,
                    bound_destination: Path,
                ) -> Iterator[MODULE._LiveDestinationPreflight]:
                    nonlocal preflight_count
                    with original_preflight(
                        bound_paths,
                        bound_destination,
                    ) as preflight:
                        preflight_count += 1
                        if preflight_count == 2:
                            artifact_parent.rename(parked_parent)
                            artifact_parent.mkdir()
                        yield preflight

                argv = [
                    command,
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                if command == "copy-db":
                    argv.extend(["--dest", str(destination)])
                else:
                    argv.extend(
                        [
                            "--src",
                            str(edited),
                            "--dest",
                            str(destination),
                        ]
                    )
                argv.extend(["--result-file", str(result_file)])
                creator = mock.Mock(
                    side_effect=AssertionError(
                        "replacement must fail before creator commit"
                    )
                )
                commit = mock.Mock(
                    side_effect=AssertionError(
                        "replacement must fail before commit phase"
                    )
                )
                bind_result = mock.Mock(
                    side_effect=AssertionError(
                        "replacement must fail before result commit binding"
                    )
                )
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        creator,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_commit_live_safe_destination_parent",
                        commit,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_bind_creator_result_destination",
                        bind_result,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_preflight_live_safe_destination_parent",
                        side_effect=replace_after_second_preflight,
                    ),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(argv)

                payload = json.loads(stdout.getvalue())
                self.assertEqual(preflight_count, 2)
                self.assertEqual(return_code, 1)
                self.assertFalse(payload["details"]["mutation_performed"])
                creator.assert_not_called()
                commit.assert_not_called()
                bind_result.assert_not_called()
                self.assertFalse(destination.exists())
                self.assertFalse(result_parent.exists())

    def test_copy_db_direct_api_rechecks_destination_before_partial_creation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_preflight = MODULE._preflight_live_safe_destination_parent
            destination_created = False

            @contextmanager
            def create_destination_after_preflight(
                selected_paths: MODULE.NoteStorePaths,
                selected_destination: Path,
            ) -> Iterator[MODULE._LiveDestinationPreflight]:
                nonlocal destination_created
                with original_preflight(
                    selected_paths,
                    selected_destination,
                ) as preflight:
                    selected_destination.mkdir()
                    destination_created = True
                    yield preflight

            creator = mock.Mock(
                side_effect=AssertionError(
                    "destination appearance must fail before partial creation"
                )
            )
            with (
                mock.patch.object(
                    MODULE,
                    "_preflight_live_safe_destination_parent",
                    side_effect=create_destination_after_preflight,
                ),
                mock.patch.object(
                    MODULE,
                    "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                    creator,
                ),
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )

            self.assertTrue(destination_created)
            self._assert_safety_code("destination-exists", raised)
            self.assertFalse(raised.exception.details["mutation_performed"])
            creator.assert_not_called()
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(destination.iterdir()), [])
            self.assertEqual(list(root.glob(".snapshot.partial-*")), [])

    def test_creator_cli_accepts_artifact_created_shared_parent_prefix(
        self,
    ) -> None:
        for command in ("copy-db", "stage-patch"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                shared_parent = root / f"{command}-shared-parent"
                destination = shared_parent / "artifacts" / "artifact"
                result_parent = shared_parent / "results"
                result_file = result_parent / "result.json"
                argv = [
                    command,
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                if command == "copy-db":
                    argv.extend(["--dest", str(destination)])
                else:
                    argv.extend(
                        [
                            "--src",
                            str(edited),
                            "--dest",
                            str(destination),
                        ]
                    )
                argv.extend(["--result-file", str(result_file)])
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(argv)

                self.assertEqual(return_code, 0, stdout.getvalue())
                self.assertTrue(destination.is_dir())
                self.assertTrue(result_file.is_file())
                self.assertEqual(
                    json.loads(result_file.read_text(encoding="utf-8")),
                    json.loads(stdout.getvalue()),
                )

    def test_creator_result_commit_failure_retains_all_mutation_evidence(
        self,
    ) -> None:
        for command in ("copy-db", "stage-patch"):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                destination = root / f"{command}-artifact"
                result_parent = root / f"{command}-result-parent"
                result_file = result_parent / "result.json"
                argv = [
                    command,
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                if command == "copy-db":
                    argv.extend(["--dest", str(destination)])
                else:
                    argv.extend(
                        [
                            "--src",
                            str(edited),
                            "--dest",
                            str(destination),
                        ]
                    )
                argv.extend(["--result-file", str(result_file)])
                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_assert_creator_result_name_absent",
                        side_effect=MODULE.StoreSafetyError(
                            "simulated-result-commit-failure",
                            "simulated result commit failure",
                        ),
                    ),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(argv)

                payload = json.loads(stdout.getvalue())
                details = payload["details"]
                self.assertEqual(return_code, 1)
                self.assertEqual(
                    payload["error_code"],
                    "result-file-publication-failed",
                )
                self.assertEqual(
                    details["underlying_error_code"],
                    "simulated-result-commit-failure",
                )
                self.assertTrue(details["artifact_mutation_performed"])
                self.assertTrue(details["mutation_performed"])
                self.assertTrue(destination.is_dir())
                self.assertTrue(result_parent.is_dir())
                self.assertFalse(result_file.exists())

    def test_supervisor_malformed_provider_locators_never_leak_received_fd(
        self,
    ) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("inherited-FD supervisor integration requires POSIX")

        for force_transport_merge_failure in (False, True):
            with (
                self.subTest(
                    force_transport_merge_failure=(force_transport_merge_failure)
                ),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                created_path = root / ".apple-notes-create-malformed-provider-details"
                received_descriptors: list[int] = []
                transport_merge_primary: list[dict[str, object]] = []
                client, server = socket.socketpair(
                    socket.AF_UNIX,
                    socket.SOCK_DGRAM,
                )
                child_pid = os.fork()
                if child_pid == 0:
                    client.close()
                    try:
                        self._serve_directory_creator_failure_response(
                            server.detach(),
                            details={"recovery_locators": 7},
                        )
                    except BaseException as exc:
                        os.write(
                            2,
                            (
                                "test directory creator failure supervisor "
                                f"failed: {exc!r}\n"
                            ).encode("utf-8"),
                        )
                        os._exit(73)
                    os._exit(0)

                server.close()
                original_received_rights = MODULE._received_rights_descriptors
                original_merge = MODULE._merge_recovery_details

                def capture_received_rights(
                    ancillary: list[tuple[int, int, bytes]],
                ) -> list[int]:
                    descriptors = original_received_rights(ancillary)
                    received_descriptors.extend(descriptors)
                    return descriptors

                def merge_with_optional_transport_failure(
                    primary: dict[str, object],
                    additional: dict[str, object],
                ) -> dict[str, object]:
                    locators = additional.get("recovery_locators")
                    is_transport_merge = (
                        type(locators) is dict
                        and "directory_creator_supervisor" in locators
                    )
                    if is_transport_merge:
                        transport_merge_primary.append(dict(primary))
                        if force_transport_merge_failure:
                            raise TypeError(
                                "simulated transport evidence merge failure"
                            )
                    return original_merge(primary, additional)

                parent_fd = os.open(root, MODULE._directory_open_flags())
                try:
                    with (
                        MODULE.directory_creator_supervisor(client.fileno()),
                        mock.patch.object(
                            MODULE,
                            "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                            MODULE._supervisor_identity_bound_directory_creator,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_received_rights_descriptors",
                            side_effect=capture_received_rights,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_merge_recovery_details",
                            side_effect=merge_with_optional_transport_failure,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._create_and_install_directory_at(
                            parent_fd,
                            os.fstat(parent_fd),
                            "installed",
                            display_path=root / "installed",
                            revalidate_scope=None,
                            identity_code=("prepared-directory-identity-mismatch"),
                            access_policy_code=(
                                "prepared-directory-access-policy-mismatch"
                            ),
                            inconclusive_code=(
                                "prepared-directory-revalidation-inconclusive"
                            ),
                            collision_code=("prepared-directory-identity-mismatch"),
                        )
                finally:
                    os.close(parent_fd)
                    client.close()
                    _, child_status = os.waitpid(child_pid, 0)

                self.assertTrue(os.WIFEXITED(child_status))
                self.assertEqual(os.WEXITSTATUS(child_status), 0)
                self.assertTrue(created_path.is_dir())
                self.assertFalse((root / "installed").exists())
                self.assertEqual(len(received_descriptors), 1)
                with self.assertRaises(OSError) as closed:
                    os.fstat(received_descriptors[0])
                self.assertEqual(closed.exception.errno, errno.EBADF)

                self._assert_safety_code(
                    "directory-creation-identity-inconclusive",
                    raised,
                )
                details = raised.exception.details
                self.assertTrue(details["mutation_performed"])
                self.assertFalse(details["retry_safe"])
                self.assertEqual(details["cleanup_state"], "inconclusive")
                self.assertIn(
                    "identity_bound_directory_creation_failure",
                    details["recovery_locators"],
                )
                self.assertIn(
                    "created_directory_install",
                    details["recovery_locators"],
                )
                transport = details["recovery_locators"]["directory_creator_supervisor"]
                normalization = transport["provider_details_normalization"]
                self.assertEqual(
                    normalization["status"],
                    "normalized-with-rejections",
                )
                self.assertIn(
                    "recovery_locators:not-object",
                    normalization["rejected_fields"],
                )
                self.assertEqual(len(transport_merge_primary), 1)
                self.assertNotIn(
                    "recovery_locators",
                    transport_merge_primary[0],
                )
                if force_transport_merge_failure:
                    self.assertEqual(
                        transport["evidence_construction_status"],
                        "failed-closed",
                    )
                    self.assertEqual(
                        transport["evidence_construction_error_type"],
                        "TypeError",
                    )
                    self.assertFalse(
                        transport["descriptor_ownership_transferred"],
                    )
                    self.assertEqual(
                        transport["received_descriptor_cleanup_state"],
                        "complete",
                    )
                else:
                    self.assertEqual(
                        transport["evidence_construction_status"],
                        "complete",
                    )
                    self.assertTrue(
                        transport["descriptor_ownership_transferred"],
                    )

    def test_supervisor_surrogate_failure_is_utf8_safe_and_locally_uncertain(
        self,
    ) -> None:
        if not hasattr(os, "fork"):
            self.skipTest("inherited-FD supervisor integration requires POSIX")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            created_path = root / ".apple-notes-create-malformed-provider-details"
            received_descriptors: list[int] = []
            transport_merge_primary: list[dict[str, object]] = []
            client, server = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_DGRAM,
            )
            child_pid = os.fork()
            if child_pid == 0:
                client.close()
                try:
                    self._serve_directory_creator_failure_response(
                        server.detach(),
                        details={
                            "publication_state": "committed",
                            "creation_authority": "provider\ud800",
                            "provider_install_state": "created\ud800",
                            "provider_staging_basename": "staging\ud800",
                            "unknown\ud800": "ignored\ud800",
                            "recovery_locators": {
                                "locator\ud800": {"value": "safe"},
                                "safe-locator": {"value": "unsafe\ud800"},
                            },
                        },
                        response_overrides={
                            "schema": (
                                f"{MODULE.DIRECTORY_CREATOR_RESPONSE_SCHEMA}\ud800"
                            ),
                            "basename": ".apple-notes-create-\ud800",
                            "proof": {
                                "schema": (
                                    "apple-notes-identity-bound-directory-creation/v1"
                                ),
                                "creation_authority": "provider\ud800",
                            },
                        },
                    )
                except BaseException as exc:
                    os.write(
                        2,
                        (
                            "test surrogate directory creator supervisor "
                            f"failed: {exc!r}\n"
                        ).encode("utf-8"),
                    )
                    os._exit(73)
                os._exit(0)

            server.close()
            original_received_rights = MODULE._received_rights_descriptors
            original_merge = MODULE._merge_recovery_details

            def capture_received_rights(
                ancillary: list[tuple[int, int, bytes]],
            ) -> list[int]:
                descriptors = original_received_rights(ancillary)
                received_descriptors.extend(descriptors)
                return descriptors

            def capture_transport_merge(
                primary: dict[str, object],
                additional: dict[str, object],
            ) -> dict[str, object]:
                locators = additional.get("recovery_locators")
                if (
                    type(locators) is dict
                    and "directory_creator_supervisor" in locators
                ):
                    transport_merge_primary.append(dict(primary))
                return original_merge(primary, additional)

            parent_fd = os.open(root, MODULE._directory_open_flags())
            try:
                with (
                    MODULE.directory_creator_supervisor(client.fileno()),
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        MODULE._supervisor_identity_bound_directory_creator,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_received_rights_descriptors",
                        side_effect=capture_received_rights,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_merge_recovery_details",
                        side_effect=capture_transport_merge,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "installed",
                        display_path=root / "installed",
                        revalidate_scope=None,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)
                client.close()
                _, child_status = os.waitpid(child_pid, 0)

            self.assertTrue(os.WIFEXITED(child_status))
            self.assertEqual(os.WEXITSTATUS(child_status), 0)
            self.assertTrue(created_path.is_dir())
            self.assertFalse((root / "installed").exists())
            self.assertEqual(len(received_descriptors), 1)
            with self.assertRaises(OSError) as closed:
                os.fstat(received_descriptors[0])
            self.assertEqual(closed.exception.errno, errno.EBADF)

            self._assert_safety_code(
                "directory-creation-identity-inconclusive",
                raised,
            )
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertEqual(len(transport_merge_primary), 1)
            self.assertNotIn(
                "publication_state",
                transport_merge_primary[0],
            )
            self.assertEqual(details["cleanup_state"], "inconclusive")
            self.assertEqual(
                details["creation_authority"],
                "inherited-supervisor-channel",
            )
            self.assertEqual(
                details["provider_install_state"],
                "supervisor-request-started",
            )
            self.assertIsNone(details["provider_staging_basename"])

            transport = details["recovery_locators"]["directory_creator_supervisor"]
            self.assertIsNone(transport["provider_reported_staging_basename"])
            response_normalization = transport["provider_response_normalization"]
            self.assertEqual(
                response_normalization["status"],
                "normalized-with-rejections",
            )
            self.assertIn(
                "schema:invalid-string",
                response_normalization["rejected_fields"],
            )
            self.assertIn(
                "basename:invalid-string",
                response_normalization["rejected_fields"],
            )
            self.assertIn(
                "proof:invalid-closed-json",
                response_normalization["rejected_fields"],
            )

            provider_normalization = transport["provider_details_normalization"]
            self.assertEqual(
                provider_normalization["status"],
                "normalized-with-rejections",
            )
            self.assertIn(
                "publication_state",
                provider_normalization["accepted_evidence_fields"],
            )
            publication_evidence = provider_normalization["provider_scoped_evidence"][
                "publication_state"
            ]
            self.assertEqual(
                publication_evidence["status"],
                "accepted-unverified-claim",
            )
            self.assertEqual(publication_evidence["claim"], "committed")
            self.assertEqual(
                publication_evidence["top_level_merge"],
                "forbidden",
            )
            self.assertIn(
                "details:invalid-field-name",
                provider_normalization["rejected_fields"],
            )
            self.assertIn(
                "creation_authority:invalid-string",
                provider_normalization["rejected_fields"],
            )
            self.assertIn(
                "provider_install_state:invalid-string",
                provider_normalization["rejected_fields"],
            )
            self.assertIn(
                "provider_staging_basename:invalid-string",
                provider_normalization["rejected_fields"],
            )
            self.assertEqual(
                provider_normalization["rejected_locator_count"],
                2,
            )

            encoded_details = json.dumps(
                details,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8", errors="strict")
            self.assertEqual(json.loads(encoded_details), details)

    def test_emit_json_escapes_lone_surrogate_for_strict_utf8_stdout(self) -> None:
        output = io.BytesIO()
        stdout = io.TextIOWrapper(
            output,
            encoding="utf-8",
            errors="strict",
            write_through=True,
        )
        try:
            with mock.patch.object(MODULE.sys, "stdout", stdout):
                MODULE.emit_json({"provider_value": "\ud800"})
            encoded = output.getvalue()
        finally:
            stdout.detach()

        self.assertIn(b"\\ud800", encoded)
        self.assertEqual(
            json.loads(encoded.decode("utf-8")),
            {"provider_value": "\ud800"},
        )

    def test_notes_state_probe_ignores_malicious_path_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "shadow-invoked"
            shadow = root / "pgrep"
            shadow.write_text(
                f"#!/bin/sh\ntouch {marker}\nprintf '99999\\n'\n",
                encoding="utf-8",
            )
            shadow.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": str(root)}):
                try:
                    result = MODULE.notes_is_running()
                except MODULE.StoreSafetyError as exc:
                    self.assertEqual(exc.code, "notes-state-unknown")
                else:
                    self.assertIsInstance(result, bool)
            self.assertFalse(marker.exists())

    def test_notes_state_probe_uses_closed_result_matrix(self) -> None:
        class Probe:
            def __init__(
                self,
                returncode: int,
                stdout: bytes,
                stderr: bytes,
            ) -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr
                self.pid = 43210

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                self.timeout = timeout
                return self.stdout, self.stderr

            def poll(self) -> int:
                return self.returncode

        cases = (
            (0, b"123\n456\n", b"", True),
            (1, b"", b"", False),
            (0, b"", b"", None),
            (0, b"not-a-pid\n", b"", None),
            (1, b"123\n", b"", None),
            (2, b"", b"", None),
            (0, b"123\n", b"warning\n", None),
        )
        for returncode, stdout, stderr, expected in cases:
            with self.subTest(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
            ):
                probe = Probe(returncode, stdout, stderr)
                with mock.patch.object(
                    MODULE.subprocess,
                    "Popen",
                    return_value=probe,
                ) as popen:
                    if expected is None:
                        with self.assertRaises(MODULE.StoreSafetyError) as raised:
                            MODULE.notes_is_running()
                        self._assert_safety_code("notes-state-unknown", raised)
                    else:
                        self.assertIs(MODULE.notes_is_running(), expected)
                argv = popen.call_args.args[0]
                kwargs = popen.call_args.kwargs
                self.assertEqual(argv, ["/usr/bin/pgrep", "-x", "Notes"])
                self.assertEqual(kwargs["cwd"], "/")
                self.assertEqual(kwargs["env"]["PATH"], "/usr/bin:/bin")
                self.assertTrue(kwargs["start_new_session"])
                self.assertEqual(
                    probe.timeout,
                    MODULE.NOTES_STATE_TIMEOUT_SECONDS,
                )

    def test_notes_state_probe_exec_failure_and_timeout_fail_closed(self) -> None:
        with (
            mock.patch.object(
                MODULE.subprocess,
                "Popen",
                side_effect=OSError(errno.ENOENT, "missing fixed pgrep"),
            ),
            self.assertRaises(MODULE.StoreSafetyError) as exec_raised,
        ):
            MODULE.notes_is_running()
        self._assert_safety_code("notes-state-unknown", exec_raised)
        self.assertEqual(exec_raised.exception.details["phase"], "exec")

        class HangingProbe:
            pid = 54321
            returncode: int | None = None

            def __init__(self) -> None:
                self.wait_calls = 0

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                raise subprocess.TimeoutExpired(
                    cmd="/usr/bin/pgrep",
                    timeout=timeout,
                )

            def wait(self, *, timeout: float) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired(
                        cmd="/usr/bin/pgrep",
                        timeout=timeout,
                    )
                self.returncode = -signal.SIGKILL
                return self.returncode

            def poll(self) -> int | None:
                return self.returncode

        probe = HangingProbe()
        with (
            mock.patch.object(
                MODULE.subprocess,
                "Popen",
                return_value=probe,
            ),
            mock.patch.object(MODULE.os, "killpg") as killpg,
            self.assertRaises(MODULE.StoreSafetyError) as timeout_raised,
        ):
            MODULE.notes_is_running()
        self._assert_safety_code("notes-state-unknown", timeout_raised)
        self.assertEqual(timeout_raised.exception.details["phase"], "timeout")
        self.assertTrue(
            timeout_raised.exception.details["cleanup"]["process_group_reaped"]
        )
        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(probe.pid, signal.SIGTERM),
                mock.call(probe.pid, signal.SIGKILL),
            ],
        )

    def test_notes_state_probe_process_control_baseexceptions_cleanup_and_reraise(
        self,
    ) -> None:
        class Pipe:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        class InterruptedProbe:
            pid = 65432
            returncode: int | None = None

            def __init__(self, failure: BaseException) -> None:
                self.failure = failure
                self.stdout = Pipe()
                self.stderr = Pipe()

            def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
                raise self.failure

            def wait(self, *, timeout: float) -> int:
                self.returncode = -signal.SIGTERM
                return self.returncode

            def poll(self) -> int | None:
                return self.returncode

        failures: tuple[BaseException, ...] = (
            KeyboardInterrupt("simulated probe interrupt"),
            SystemExit(19),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                probe = InterruptedProbe(failure)
                with (
                    mock.patch.object(
                        MODULE.subprocess,
                        "Popen",
                        return_value=probe,
                    ),
                    mock.patch.object(MODULE.os, "killpg") as killpg,
                    self.assertRaises(type(failure)) as raised,
                ):
                    MODULE.notes_is_running()
                self.assertIs(raised.exception, failure)
                self.assertTrue(probe.stdout.closed)
                self.assertTrue(probe.stderr.closed)
                self.assertEqual(
                    killpg.call_args_list,
                    [mock.call(probe.pid, signal.SIGTERM)],
                )

    def test_compatibility_launcher_exports_packaged_api(self) -> None:
        compatibility = self._load_compatibility_module(
            COMPATIBILITY_SCRIPT,
            "compatibility_helper",
        )
        self.assertEqual(compatibility.HELPER_PATH, SCRIPT_PATH)
        self.assertTrue(callable(compatibility.main))
        self.assertTrue(callable(compatibility.directory_creator_supervisor))
        self.assertTrue(callable(compatibility.emit_json))
        self.assertTrue(callable(compatibility.notes_is_running))
        self.assertTrue(callable(compatibility.build_parser))
        self.assertEqual(compatibility.GROUP_CONTAINER, MODULE.GROUP_CONTAINER)
        self.assertEqual(compatibility.APP_CONTAINER, MODULE.APP_CONTAINER)
        self.assertEqual(
            compatibility.NOTE_STORE_BASENAMES,
            MODULE.NOTE_STORE_BASENAMES,
        )
        self.assertEqual(
            compatibility.NoteStorePaths().note_store_files(),
            MODULE.NoteStorePaths().note_store_files(),
        )
        self.assertIs(
            compatibility.HELPER_CAPTURE,
            compatibility._SUPERVISOR.HELPER_CAPTURE,
        )
        self.assertIs(compatibility._HELPER, compatibility._SUPERVISOR.HELPER)
        self.assertEqual(
            compatibility._HELPER.__captured_source_sha256__,
            compatibility.HELPER_CAPTURE.sha256,
        )
        self.assertEqual(
            compatibility._SUPERVISOR.__captured_source_sha256__,
            compatibility.DIRECTORY_SUPERVISOR_CAPTURE.sha256,
        )

    def test_compatibility_entry_rejects_unstable_helper_before_execution(
        self,
    ) -> None:
        internal_modules = (
            "packaged_apple_notes_directory_supervisor",
            "packaged_apple_notes_db_for_supervisor",
        )
        for mutation in ("symlink", "atomic-replacement", "in-place-mutation"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                execution_evidence = root / "helper-executed"

                def helper_source(label: str) -> bytes:
                    return (
                        "from pathlib import Path\n"
                        f"Path({str(execution_evidence)!r}).write_text("
                        f"{label!r}, encoding='ascii')\n"
                    ).encode("ascii")

                initial_source = helper_source("first")
                replacement_source = helper_source("other")
                self.assertEqual(len(initial_source), len(replacement_source))
                compatibility_path, _, helper_path = self._write_compatibility_tree(
                    root,
                    helper_source=initial_source,
                )
                for module_name in internal_modules:
                    sys.modules.pop(module_name, None)
                held_fd: int | None = None
                try:
                    if mutation == "symlink":
                        symlink_target = root / "symlink-helper.py"
                        symlink_target.write_bytes(replacement_source)
                        helper_path.unlink()
                        helper_path.symlink_to(symlink_target)
                        patcher = mock.patch.object(os, "open", wraps=os.open)
                    elif mutation == "atomic-replacement":
                        replacement = root / "replacement-helper.py"
                        replacement.write_bytes(replacement_source)
                        canonical_helper_path = helper_path.resolve()
                        original_open = os.open
                        replaced = False

                        def replace_before_helper_open(
                            path: object,
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            nonlocal replaced
                            if (
                                not replaced
                                and Path(os.path.abspath(os.fspath(path)))
                                == canonical_helper_path
                            ):
                                os.replace(replacement, helper_path)
                                replaced = True
                            return original_open(
                                path,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )

                        patcher = mock.patch.object(
                            os,
                            "open",
                            side_effect=replace_before_helper_open,
                        )
                    else:
                        held_fd = os.open(helper_path, os.O_RDWR)
                        helper_identity = helper_path.stat()
                        original_lseek = os.lseek
                        mutated = False

                        def mutate_before_second_helper_read(
                            descriptor: int,
                            offset: int,
                            whence: int,
                        ) -> int:
                            nonlocal mutated
                            opened = os.fstat(descriptor)
                            if (
                                not mutated
                                and opened.st_dev == helper_identity.st_dev
                                and opened.st_ino == helper_identity.st_ino
                            ):
                                assert held_fd is not None
                                self.assertEqual(
                                    os.pwrite(
                                        held_fd,
                                        replacement_source,
                                        0,
                                    ),
                                    len(replacement_source),
                                )
                                mutated = True
                            return original_lseek(descriptor, offset, whence)

                        patcher = mock.patch.object(
                            os,
                            "lseek",
                            side_effect=mutate_before_second_helper_read,
                        )

                    with (
                        patcher,
                        self.assertRaises(RuntimeError),
                    ):
                        self._load_compatibility_module(
                            compatibility_path,
                            f"compatibility_unstable_helper_{mutation}",
                        )
                    self.assertFalse(execution_evidence.exists())
                finally:
                    if held_fd is not None:
                        os.close(held_fd)
                    for module_name in internal_modules:
                        sys.modules.pop(module_name, None)

    def test_compatibility_entry_captures_supervisor_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            execution_evidence = root / "supervisor-executed"
            compatibility_path, supervisor_path, _ = self._write_compatibility_tree(
                root
            )
            symlink_target = root / "symlink-supervisor.py"
            symlink_target.write_text(
                "from pathlib import Path\n"
                f"Path({str(execution_evidence)!r}).write_text("
                "'executed', encoding='ascii')\n",
                encoding="ascii",
            )
            supervisor_path.unlink()
            supervisor_path.symlink_to(symlink_target)

            with self.assertRaises(RuntimeError):
                self._load_compatibility_module(
                    compatibility_path,
                    "compatibility_symlink_supervisor",
                )

            self.assertFalse(execution_evidence.exists())

        compatibility = self._load_compatibility_module(
            COMPATIBILITY_SCRIPT,
            "compatibility_supervisor_access_policy",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "supervisor.py"
            source.write_text("CAPTURED = True\n", encoding="ascii")
            original_fstat = compatibility.os.fstat
            fstat_calls = 0

            def report_access_policy_drift(
                descriptor: int,
            ) -> os.stat_result:
                nonlocal fstat_calls
                fstat_calls += 1
                opened = original_fstat(descriptor)
                if fstat_calls == 2:
                    return _StatWithOverrides(
                        opened,
                        st_mode=opened.st_mode ^ stat.S_IWGRP,
                    )
                return opened

            with (
                mock.patch.object(
                    compatibility.os,
                    "fstat",
                    side_effect=report_access_policy_drift,
                ),
                self.assertRaises(RuntimeError),
            ):
                compatibility._capture_directory_supervisor_source(source)

    def test_compatibility_entry_load_writes_no_source_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            compatibility_path, supervisor_path, _ = self._write_compatibility_tree(
                root
            )
            source_roots = {
                "compatibility": compatibility_path.parent,
                "packaged": supervisor_path.parent,
            }
            before = self._source_tree_inventory(source_roots)
            environment = dict(os.environ)
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(compatibility_path),
                    "--help",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30.0,
                env=environment,
            )
            after = self._source_tree_inventory(source_roots)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(after, before)

    def test_compatibility_entry_preserves_preexisting_source_bytecode_cache(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            compatibility_path, supervisor_path, _ = self._write_compatibility_tree(
                root
            )
            cache_tag = sys.implementation.cache_tag or "python"
            seeded_cache_files = (
                compatibility_path.parent
                / "__pycache__"
                / f"runner_preexisting.{cache_tag}.pyc",
                supervisor_path.parent
                / "__pycache__"
                / f"packaged_preexisting.{cache_tag}.pyc",
            )
            for index, cache_file in enumerate(seeded_cache_files):
                cache_file.parent.mkdir(exist_ok=True)
                cache_file.write_bytes(f"preexisting-cache-{index}".encode("ascii"))

            source_roots = {
                "compatibility": compatibility_path.parent,
                "packaged": supervisor_path.parent,
            }
            before = self._source_tree_inventory(source_roots)
            seeded_cache_keys = {
                (
                    label,
                    str(cache_file.relative_to(source_roots[label])),
                )
                for label, cache_file in zip(
                    ("compatibility", "packaged"),
                    seeded_cache_files,
                )
            }
            self.assertTrue(seeded_cache_keys.issubset(before))
            self.assertTrue(all(before[key][0] == "file" for key in seeded_cache_keys))
            environment = dict(os.environ)
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(compatibility_path),
                    "--help",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30.0,
                env=environment,
            )
            after = self._source_tree_inventory(source_roots)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(after, before)

    def test_compatibility_main_routes_writes_through_packaged_capability_gate(
        self,
    ) -> None:
        compatibility = self._load_compatibility_module(
            COMPATIBILITY_SCRIPT,
            "compatibility_helper_supervision",
        )
        with (
            mock.patch.object(
                compatibility._SUPERVISOR,
                "run_supervised",
                return_value=23,
            ) as run_supervised,
            mock.patch.object(
                compatibility._HELPER,
                "main",
                return_value=29,
            ) as helper_main,
        ):
            for command in sorted(compatibility.WRITE_PRODUCING_COMMANDS):
                with self.subTest(command=command):
                    self.assertEqual(
                        compatibility.main([command, "--synthetic"]),
                        23,
                    )
            self.assertEqual(
                compatibility.main(
                    [
                        "copy-db",
                        "--directory-creator-fd",
                        "17",
                    ]
                ),
                29,
            )
            self.assertEqual(
                compatibility.main(["probe-db-access"]),
                29,
            )

        self.assertEqual(run_supervised.call_count, 4)
        for call, command in zip(
            run_supervised.call_args_list,
            sorted(compatibility.WRITE_PRODUCING_COMMANDS),
        ):
            self.assertEqual(
                call,
                mock.call(
                    compatibility.HELPER_CAPTURE.display_path,
                    [command, "--synthetic"],
                    python_bin=sys.executable,
                ),
            )
        self.assertEqual(
            helper_main.call_args_list,
            [
                mock.call(
                    [
                        "copy-db",
                        "--directory-creator-fd",
                        "17",
                    ]
                ),
                mock.call(["probe-db-access"]),
            ],
        )

    def test_compatibility_python_api_preserves_merged_db_alias(self) -> None:
        compatibility = self._load_compatibility_module(
            COMPATIBILITY_SCRIPT,
            "compatibility_helper_merge",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            output = root / "merged.sqlite"
            self._create_db(source)
            result = compatibility.merge_db(source, output)

        self.assertEqual(Path(result["merged_db"]), output)
        self.assertEqual(Path(result["standalone_db"]), output)

    def test_compatibility_cli_json_preserves_merged_db_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            output = root / "merged.sqlite"
            self._create_db(source)
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(COMPATIBILITY_SCRIPT),
                    "merge-db",
                    "--src",
                    str(source),
                    "--out",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(Path(payload["merged_db"]), output)
        self.assertEqual(Path(payload["standalone_db"]), output)

    def test_compatibility_copy_cli_packaged_supervisor_fails_before_creation(
        self,
    ) -> None:
        process_probe = subprocess.run(
            [MODULE.NOTES_PGREP_PATH, "-x", "Notes"],
            check=False,
            capture_output=True,
        )
        if process_probe.returncode not in {0, 1} or process_probe.stderr:
            self.skipTest("fixed Notes process probe is unavailable in this sandbox")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(COMPATIBILITY_SCRIPT),
                    "copy-db",
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                    "--dest",
                    str(destination),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30.0,
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            payload = json.loads(result.stdout) if result.stdout else {}
            copied = (
                destination / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            ).is_file()

        self.assertEqual(
            result.returncode,
            1,
            msg=result.stdout + result.stderr,
        )
        self.assertEqual(
            payload["error_code"],
            "directory-creation-identity-inconclusive",
        )
        self.assertFalse(copied)
        self.assertFalse(destination.exists())
        self.assertFalse(payload["details"]["mutation_performed"])
        self.assertEqual(payload["details"]["cleanup_state"], "not-needed")

    def test_merge_default_output_is_external_to_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            source = snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            merged = MODULE.merge_db(source, None, paths=paths)
            output = Path(merged["standalone_db"])
            validation = self._validate_snapshot(snapshot_dir)

            self.assertEqual(output.parent, snapshot_dir.parent)
            self.assertNotEqual(output, source)
            self.assertFalse(output.is_relative_to(snapshot_dir))
            self.assertEqual(validation["sqlite_validation"]["result"], "ok")

    def test_merge_rejects_lexical_output_inside_snapshot_before_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            source = snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            output = snapshot_dir / "analysis.sqlite"

            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE.merge_db(source, output, paths=paths)

            self._assert_safety_code("merge-output-inside-snapshot", raised)
            self.assertFalse(output.exists())
            self.assertFalse(raised.exception.details["mutation_performed"])

    def test_merge_rejects_descriptor_alias_output_inside_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            source = snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            alias = root / "snapshot-alias"
            alias.symlink_to(snapshot_dir, target_is_directory=True)
            output = alias / "group.com.apple.notes" / "analysis.sqlite"

            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE.merge_db(source, output, paths=paths)

            self._assert_safety_code("merge-output-inside-snapshot", raised)
            self.assertFalse(
                (snapshot_dir / "group.com.apple.notes" / "analysis.sqlite").exists()
            )

    def test_capture_uses_python_39_compatible_zip_call(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(source)

            def python_39_zip(
                *iterables: object,
                **kwargs: object,
            ) -> object:
                if kwargs:
                    raise TypeError("zip() takes no keyword arguments")
                return builtins.zip(*iterables)

            with mock.patch.object(
                MODULE,
                "zip",
                side_effect=python_39_zip,
                create=True,
            ):
                records = MODULE._capture_database_files(source)
        self.assertEqual([row["basename"] for row in records], [source.name])

    def test_shell_wrapper_delegates_db_commands_to_packaged_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER_PATH),
                    "probe-db-access",
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["paths"][0]["readable"])

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
        self.assertIn(
            "Note title prefix is ambiguous in folder Daily Notes", result.stderr
        )
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
        self.assertIn(
            "Note title prefix not found in folder Daily Notes", result.stderr
        )

    def test_copy_db_copies_and_validates_complete_wal_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            db_path = paths.group_container / MODULE.NOTE_STORE_MAIN
            conn = self._create_wal_db(db_path)
            try:
                with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                    result = self._copy_db(
                        paths,
                        dest=root / "snapshot",
                        require_notes_quit=True,
                    )
            finally:
                conn.close()
            copied_names = {Path(row["dest"]).name for row in result["copied_files"]}
            self.assertEqual(copied_names, set(MODULE.NOTE_STORE_BASENAMES))
            self.assertEqual(result["classification"], "writeback-baseline")
            self.assertEqual(result["sqlite_validation"]["result"], "ok")
            self.assertEqual(
                result["sidecar_consistency"]["shm"]["status"],
                "derived-match",
            )
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], MODULE.SNAPSHOT_SCHEMA)

    def test_copy_db_rejects_live_container_destination_before_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            for live_container in (paths.group_container, paths.app_container):
                with self.subTest(live_container=live_container.name):
                    destination = live_container / "snapshot"
                    before = set(os.listdir(live_container))
                    mkdir_calls: list[tuple[object, ...]] = []
                    original_mkdir = MODULE.os.mkdir

                    def record_mkdir(*args: object, **kwargs: object) -> None:
                        mkdir_calls.append(args)
                        original_mkdir(*args, **kwargs)

                    with (
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        mock.patch.object(
                            MODULE.os,
                            "mkdir",
                            side_effect=record_mkdir,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE.copy_db(
                            paths,
                            dest=destination,
                            require_notes_quit=True,
                        )

                    self._assert_safety_code(
                        "snapshot-destination-inside-live-container",
                        raised,
                    )
                    self.assertEqual(mkdir_calls, [])
                    self.assertEqual(set(os.listdir(live_container)), before)
                    self.assertFalse(destination.exists())

    def test_copy_db_reports_inconclusive_live_scope_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "safe-parent" / "snapshot"
            original_stat = MODULE.os.stat

            def fail_app_container_stat(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if (path == paths.app_container and kwargs.get("dir_fd") is None) or (
                    path == paths.app_container.name
                    and kwargs.get("dir_fd") is not None
                ):
                    raise OSError(
                        errno.EIO,
                        "simulated live-container scope failure",
                    )
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=fail_app_container_stat,
                ),
                mock.patch.object(MODULE.os, "mkdir") as mkdir,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code(
                "snapshot-destination-scope-inconclusive",
                raised,
            )
            mkdir.assert_not_called()
            self.assertFalse(destination.parent.exists())

    def test_copy_db_rejects_symlink_alias_into_live_container_before_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            alias = root / "group-alias"
            alias.symlink_to(paths.group_container, target_is_directory=True)
            destination = alias / "snapshot"
            mkdir_calls: list[tuple[object, ...]] = []
            original_mkdir = MODULE.os.mkdir

            def record_mkdir(*args: object, **kwargs: object) -> None:
                mkdir_calls.append(args)
                original_mkdir(*args, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(MODULE.os, "mkdir", side_effect=record_mkdir),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code(
                "snapshot-destination-inside-live-container",
                raised,
            )
            self.assertEqual(mkdir_calls, [])
            self.assertFalse(destination.exists())

    def test_copy_db_rejects_intermediate_symlink_toward_absent_live_container(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            group = root / "group"
            group.mkdir()
            app = root / "initially-absent-app"
            paths = MODULE.NoteStorePaths(
                group_container=group,
                app_container=app,
            )
            self._create_db(group / MODULE.NOTE_STORE_MAIN)
            alias = root / "untrusted-intermediate"
            alias.symlink_to(app, target_is_directory=True)
            destination = alias / "nested" / "snapshot"

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(MODULE.os, "mkdir") as mkdir,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code(
                "snapshot-destination-scope-inconclusive",
                raised,
            )
            self.assertFalse(raised.exception.details["mutation_performed"])
            mkdir.assert_not_called()
            self.assertFalse(app.exists())
            self.assertFalse(destination.exists())

    def test_component_replacement_before_creation_cannot_redirect_live_namespace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            group = root / "group"
            group.mkdir()
            app = root / "initially-absent-app"
            paths = MODULE.NoteStorePaths(
                group_container=group,
                app_container=app,
            )
            self._create_db(group / MODULE.NOTE_STORE_MAIN)
            safe_root = root / "safe-root"
            safe_parent = safe_root / "parent"
            safe_parent.mkdir(parents=True)
            parked = root / "safe-root-parked"
            destination = safe_parent / "snapshot"
            original_verify = MODULE._verify_snapshot_live_container_bindings
            attacked = False

            def replace_component_before_creation(
                *args: object,
                **kwargs: object,
            ) -> object:
                nonlocal attacked
                if not attacked:
                    attacked = True
                    safe_root.rename(parked)
                    safe_root.symlink_to(app, target_is_directory=True)
                return original_verify(*args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_verify_snapshot_live_container_bindings",
                        side_effect=replace_component_before_creation,
                    ),
                    mock.patch.object(MODULE.os, "mkdir") as mkdir,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.copy_db(
                        paths,
                        dest=destination,
                        require_notes_quit=True,
                    )
                self._assert_safety_code(
                    "snapshot-destination-scope-inconclusive",
                    raised,
                )
                self.assertTrue(attacked)
                self.assertFalse(raised.exception.details["mutation_performed"])
                mkdir.assert_not_called()
                self.assertFalse(app.exists())
                self.assertFalse(destination.exists())
            finally:
                if safe_root.is_symlink():
                    safe_root.unlink()
                if parked.exists():
                    parked.rename(safe_root)

    def test_destination_component_replacement_between_install_and_target_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            destination = root / "created-parent" / "snapshot"
            parked = root / "transaction-created-parent"
            original_install = MODULE._install_created_directory_no_replace_at
            attacked = False

            def replace_after_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal attacked
                self.assertTrue(staging_name.startswith(".apple-notes-create-"))
                self.assertNotEqual(staging_name, target_name)
                original_install(parent_fd, staging_name, target_name)
                if target_name != "created-parent":
                    return
                attacked = True
                os.rename(
                    target_name,
                    parked.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_install_created_directory_no_replace_at",
                    side_effect=replace_after_install,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                with MODULE._bind_live_safe_destination_parent(
                    paths,
                    destination,
                ):
                    self.fail("replaced destination parent must not be yielded")

            self._assert_safety_code(
                "snapshot-destination-scope-inconclusive",
                raised,
            )
            self.assertTrue(attacked)
            self.assertTrue(parked.is_dir())
            self.assertTrue(destination.parent.is_dir())
            self.assertTrue(raised.exception.details["mutation_performed"])
            self.assertEqual(
                raised.exception.details["cleanup_state"],
                "preserved-no-identity-safe-directory-unlink",
            )
            recovery = raised.exception.details["recovery_locators"][
                "created_directory_install"
            ]
            self.assertEqual(
                recovery["protected_property"],
                "transaction-created-object-identity",
            )
            self.assertTrue(recovery["created_descriptor"]["matches_creation_receipt"])
            self.assertFalse(
                recovery["namespace_observations"]["target_name"][
                    "matches_created_identity"
                ]
            )

    def test_destination_component_install_accepts_metadata_only_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            destination = root / "created-parent" / "snapshot"
            original_install = MODULE._install_created_directory_no_replace_at
            touched = False

            def touch_after_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal touched
                original_install(parent_fd, staging_name, target_name)
                if target_name == "created-parent":
                    touched = True
                    os.utime(
                        target_name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )

            with mock.patch.object(
                MODULE,
                "_install_created_directory_no_replace_at",
                side_effect=touch_after_install,
            ):
                with MODULE._bind_live_safe_destination_parent(
                    paths,
                    destination,
                ) as scope:
                    receipt = scope.parent.creation_install_receipt
                    self.assertIsNotNone(receipt)
                    assert receipt is not None
                    self.assertEqual(
                        receipt["creation_protocol"],
                        "trusted-creator-returned-fd-before-no-replace-install",
                    )
            self.assertTrue(touched)
            self.assertTrue(destination.parent.is_dir())

    def test_directory_install_latches_receipt_before_scope_revalidation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent_fd = os.open(root, MODULE._directory_open_flags())
            revalidations = 0

            def fail_after_no_replace_install() -> None:
                nonlocal revalidations
                revalidations += 1
                if revalidations == 3:
                    raise MODULE.StoreSafetyError(
                        "prepared-directory-revalidation-inconclusive",
                        "simulated post-install scope failure",
                    )

            try:
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "installed",
                        display_path=root / "installed",
                        revalidate_scope=fail_after_no_replace_install,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)

            self._assert_safety_code(
                "prepared-directory-revalidation-inconclusive",
                raised,
            )
            self.assertEqual(revalidations, 3)
            installed = root / "installed"
            self.assertTrue(installed.is_dir())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            self.assertEqual(
                details["cleanup_state"],
                "preserved-no-identity-safe-directory-unlink",
            )
            exact_receipt = details["recovery_locators"]["creation_install_receipt"]
            recovery = details["recovery_locators"]["created_directory_install"]
            self.assertEqual(recovery["install_state"], "no-replace-install-returned")
            self.assertEqual(recovery["creation_install_receipt"], exact_receipt)
            self.assertEqual(
                exact_receipt["directory_identity"],
                MODULE._identity(installed.stat()),
            )
            self.assertEqual(
                exact_receipt["directory_access_policy"],
                MODULE._access_policy(installed.stat()),
            )

    def test_created_parent_failure_retains_every_component_install_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            destination = root / "created-one" / "created-two" / "snapshot"
            original_verify = MODULE._verify_held_directory_components
            failed = False

            def fail_after_second_component(
                components: object,
            ) -> dict[str, object]:
                nonlocal failed
                held = list(components)
                if len(held) == 2 and not failed:
                    failed = True
                    raise OSError(
                        MODULE.errno.EIO,
                        "simulated post-component chain revalidation failure",
                    )
                return original_verify(held)

            with (
                mock.patch.object(
                    MODULE,
                    "_verify_held_directory_components",
                    side_effect=fail_after_second_component,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                with MODULE._bind_live_safe_destination_parent(
                    paths,
                    destination,
                ):
                    self.fail("failed parent-component chain must not be yielded")

            self._assert_safety_code(
                "snapshot-destination-scope-inconclusive",
                raised,
            )
            self.assertTrue(failed)
            self.assertTrue(destination.parent.is_dir())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            recovery = details["recovery_locators"][
                "created_destination_parent_components"
            ]
            components = recovery["components"]
            self.assertEqual(len(components), 2)
            self.assertEqual(
                [Path(component["path"]).name for component in components],
                ["created-one", "created-two"],
            )
            for component in components:
                receipt = component["creation_install_receipt"]
                self.assertEqual(
                    receipt["directory_identity"],
                    component["directory_identity"],
                )
                self.assertEqual(
                    receipt["directory_access_policy"],
                    component["directory_access_policy"],
                )

    def test_created_parent_teardown_retains_component_install_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            destination = root / "created-parent" / "snapshot"
            original_verify = MODULE._verify_held_directory_components
            body_completed = False
            failed = False

            def fail_during_component_teardown(
                components: object,
            ) -> dict[str, object]:
                nonlocal failed
                held = list(components)
                if body_completed and held and not failed:
                    failed = True
                    raise PermissionError(
                        MODULE.errno.EACCES,
                        "simulated component teardown failure",
                    )
                return original_verify(held)

            with (
                mock.patch.object(
                    MODULE,
                    "_verify_held_directory_components",
                    side_effect=fail_during_component_teardown,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                with MODULE._bind_live_safe_destination_parent(
                    paths,
                    destination,
                ):
                    body_completed = True

            self._assert_safety_code(
                "snapshot-destination-scope-inconclusive",
                raised,
            )
            self.assertTrue(failed)
            self.assertTrue(destination.parent.is_dir())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            components = details["recovery_locators"][
                "created_destination_parent_components"
            ]["components"]
            self.assertEqual(len(components), 1)
            self.assertEqual(
                components[0]["creation_install_receipt"]["directory_identity"],
                MODULE._identity(destination.parent.stat()),
            )

    def test_directory_creation_without_supervisor_fails_before_mkdir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent_fd = os.open(root, MODULE._directory_open_flags())
            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        MODULE._supervisor_identity_bound_directory_creator,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_DIRECTORY_CREATOR_SUPERVISOR_FD",
                        None,
                    ),
                    mock.patch.object(MODULE.os, "mkdir") as mkdir,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "created",
                        display_path=root / "created",
                        revalidate_scope=None,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)

            self._assert_safety_code(
                "directory-creation-identity-inconclusive",
                raised,
            )
            mkdir.assert_not_called()
            self.assertFalse((root / "created").exists())
            details = raised.exception.details
            self.assertFalse(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            recovery = details["recovery_locators"]["created_directory_install"]
            self.assertEqual(
                recovery["protected_property"],
                "creation-identity-inconclusive",
            )
            self.assertIsNone(recovery["creation_proof"])

    def test_packaged_supervisor_capability_failure_is_precreation_end_to_end(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            client, server = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_DGRAM,
            )
            service_errors: list[BaseException] = []

            def serve_once() -> None:
                try:
                    self._serve_packaged_directory_creator_once(server.detach())
                except BaseException as exc:
                    service_errors.append(exc)

            service = threading.Thread(target=serve_once, daemon=True)
            service.start()
            parent_fd = os.open(root, MODULE._directory_open_flags())
            try:
                with (
                    MODULE.directory_creator_supervisor(client.fileno()),
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        MODULE._supervisor_identity_bound_directory_creator,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "installed",
                        display_path=root / "installed",
                        revalidate_scope=None,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)
                client.close()
                service.join(timeout=10.0)

            self.assertFalse(service.is_alive())
            self.assertEqual(service_errors, [])
            self._assert_safety_code(
                "directory-creation-identity-inconclusive",
                raised,
            )
            self.assertEqual(list(root.iterdir()), [])
            details = raised.exception.details
            self.assertFalse(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            self.assertEqual(details["cleanup_state"], "not-needed")
            self.assertEqual(
                details["creation_authority"],
                MODULE.PACKAGED_DIRECTORY_CREATOR_AUTHORITY,
            )
            self.assertEqual(details["provider_install_state"], "not-created")
            capability = details["recovery_locators"]["packaged_directory_supervisor"]
            self.assertEqual(
                capability["protected_property"],
                "exact-created-object-descriptor",
            )
            self.assertFalse(capability["creation_boundary_entered"])
            install = details["recovery_locators"]["created_directory_install"]
            self.assertEqual(install["install_state"], "not-created")
            self.assertFalse(install["mutation_performed"])
            self.assertIsNone(install["creation_proof"])

    def test_malformed_precreation_unavailable_response_is_conservative(
        self,
    ) -> None:
        malformed_kinds = (
            "returned-descriptor",
            "basename",
            "proof",
            "details",
            "details-bool-int",
            "extra-field",
        )
        for malformed_kind in malformed_kinds:
            with (
                self.subTest(malformed_kind=malformed_kind),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                client, server = socket.socketpair(
                    socket.AF_UNIX,
                    socket.SOCK_DGRAM,
                )
                service_errors: list[BaseException] = []
                received_descriptors: list[int] = []
                original_received_rights = MODULE._received_rights_descriptors

                def capture_received_rights(
                    ancillary: list[tuple[int, int, bytes]],
                ) -> list[int]:
                    descriptors = original_received_rights(ancillary)
                    received_descriptors.extend(descriptors)
                    return descriptors

                def serve_once() -> None:
                    try:
                        self._serve_malformed_precreation_unavailable_response(
                            server.detach(),
                            malformed_kind=malformed_kind,
                        )
                    except BaseException as exc:
                        service_errors.append(exc)

                service = threading.Thread(target=serve_once, daemon=True)
                parent_fd = os.open(root, MODULE._directory_open_flags())
                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_received_rights_descriptors",
                            side_effect=capture_received_rights,
                        ),
                        MODULE.directory_creator_supervisor(client.fileno()),
                        mock.patch.object(
                            MODULE,
                            "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                            MODULE._supervisor_identity_bound_directory_creator,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        service.start()
                        MODULE._create_and_install_directory_at(
                            parent_fd,
                            os.fstat(parent_fd),
                            "installed",
                            display_path=root / "installed",
                            revalidate_scope=None,
                            identity_code=("prepared-directory-identity-mismatch"),
                            access_policy_code=(
                                "prepared-directory-access-policy-mismatch"
                            ),
                            inconclusive_code=(
                                "prepared-directory-revalidation-inconclusive"
                            ),
                            collision_code=("prepared-directory-identity-mismatch"),
                        )
                finally:
                    os.close(parent_fd)
                    client.close()
                    if service.ident is not None:
                        service.join(timeout=10.0)

                self.assertFalse(service.is_alive())
                self.assertEqual(service_errors, [])
                self._assert_safety_code(
                    "directory-creation-identity-inconclusive",
                    raised,
                )
                self.assertEqual(list(root.iterdir()), [])
                details = raised.exception.details
                self.assertTrue(details["mutation_performed"])
                self.assertFalse(details["retry_safe"])
                self.assertEqual(details["cleanup_state"], "inconclusive")
                self.assertEqual(details["publication_state"], "uncertain")
                self.assertEqual(
                    details["creation_authority"],
                    "inherited-supervisor-channel",
                )
                self.assertEqual(
                    details["provider_install_state"],
                    "supervisor-request-started",
                )
                self.assertIn(
                    "directory_creator_supervisor",
                    details["recovery_locators"],
                )
                for descriptor in received_descriptors:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_structured_creator_create_then_fail_retains_conservative_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            created_path = root / ".apple-notes-create-structured-failure"
            transferred_fd: int | None = None

            def create_then_fail(
                parent_fd: int,
                _prefix: str,
            ) -> MODULE._IdentityBoundDirectoryCreation:
                nonlocal transferred_fd
                os.mkdir(created_path.name, mode=0o700, dir_fd=parent_fd)
                transferred_fd = os.open(
                    created_path.name,
                    MODULE._directory_open_flags(),
                    dir_fd=parent_fd,
                )
                opened = os.fstat(transferred_fd)
                parent = os.fstat(parent_fd)
                raise MODULE._IdentityBoundDirectoryCreationFailure(
                    "simulated provider failure after creation",
                    staging_basename=created_path.name,
                    fd=transferred_fd,
                    opened=opened,
                    proof={
                        "schema": ("apple-notes-identity-bound-directory-creation/v1"),
                        "creation_authority": "test-create-then-fail-provider",
                        "actual_created_object_descriptor_returned": True,
                        "namespace_exclusive_during_handoff": True,
                        "parent_identity": MODULE._identity(parent),
                        "parent_access_policy": MODULE._access_policy(parent),
                        "directory_identity": MODULE._identity(opened),
                        "directory_access_policy": MODULE._access_policy(opened),
                    },
                    details={
                        "mutation_performed": False,
                        "cleanup_state": "complete",
                        "retry_safe": True,
                    },
                )

            parent_fd = os.open(root, MODULE._directory_open_flags())
            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        create_then_fail,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "installed",
                        display_path=root / "installed",
                        revalidate_scope=None,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)

            self._assert_safety_code(
                "directory-creation-identity-inconclusive",
                raised,
            )
            self.assertTrue(created_path.is_dir())
            self.assertFalse((root / "installed").exists())
            self.assertIsNotNone(transferred_fd)
            assert transferred_fd is not None
            with self.assertRaises(OSError) as closed:
                os.fstat(transferred_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            self.assertEqual(
                details["cleanup_state"],
                "preserved-no-identity-safe-directory-unlink",
            )
            provider_recovery = details["recovery_locators"][
                "identity_bound_directory_creation_failure"
            ]
            self.assertEqual(
                provider_recovery["protected_property"],
                "creation-identity-inconclusive",
            )
            self.assertEqual(
                provider_recovery["creation_state"],
                "create-then-fail",
            )
            self.assertTrue(
                provider_recovery["created_descriptor"]["matches_creation_receipt"]
            )
            self.assertTrue(
                provider_recovery["namespace_observations"]["staging_name"][
                    "matches_created_identity"
                ]
            )
            self.assertIn(
                "created_directory_install",
                details["recovery_locators"],
            )

    def test_unstructured_creator_failure_never_claims_no_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            created_path = root / ".apple-notes-create-unstructured-failure"

            def create_then_raise_unstructured(
                parent_fd: int,
                _prefix: str,
            ) -> MODULE._IdentityBoundDirectoryCreation:
                os.mkdir(created_path.name, mode=0o700, dir_fd=parent_fd)
                raise RuntimeError("simulated unstructured provider failure")

            parent_fd = os.open(root, MODULE._directory_open_flags())
            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        create_then_raise_unstructured,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "installed",
                        display_path=root / "installed",
                        revalidate_scope=None,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)

            self._assert_safety_code(
                "directory-creation-identity-inconclusive",
                raised,
            )
            self.assertTrue(created_path.is_dir())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            self.assertEqual(details["cleanup_state"], "inconclusive")
            provider_recovery = details["recovery_locators"][
                "identity_bound_directory_creation_failure"
            ]
            self.assertEqual(
                provider_recovery["creation_state"],
                "unknown-after-creator-entry",
            )
            self.assertEqual(
                provider_recovery["evidence_status"],
                "inconclusive",
            )

    def test_creator_create_then_malformed_return_is_conservative(self) -> None:
        for malformed_kind in ("none", "missing-fields", "wrong-field-types"):
            with (
                self.subTest(malformed_kind=malformed_kind),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                created_path = root / f".apple-notes-create-{malformed_kind}"
                returned_fd: int | None = None

                def create_then_return_malformed(
                    parent_fd: int,
                    _prefix: str,
                ) -> object:
                    nonlocal returned_fd
                    os.mkdir(created_path.name, mode=0o700, dir_fd=parent_fd)
                    if malformed_kind == "none":
                        return None
                    returned_fd = os.open(
                        created_path.name,
                        MODULE._directory_open_flags(),
                        dir_fd=parent_fd,
                    )
                    if malformed_kind == "missing-fields":
                        return {
                            "basename": created_path.name,
                            "fd": returned_fd,
                        }
                    return MODULE._IdentityBoundDirectoryCreation(
                        basename=created_path.name,
                        fd=returned_fd,
                        opened="not-a-stat-result",
                        proof=["not", "a", "proof"],
                    )

                parent_fd = os.open(root, MODULE._directory_open_flags())
                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                            create_then_return_malformed,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._create_and_install_directory_at(
                            parent_fd,
                            os.fstat(parent_fd),
                            "installed",
                            display_path=root / "installed",
                            revalidate_scope=None,
                            identity_code=("prepared-directory-identity-mismatch"),
                            access_policy_code=(
                                "prepared-directory-access-policy-mismatch"
                            ),
                            inconclusive_code=(
                                "prepared-directory-revalidation-inconclusive"
                            ),
                            collision_code=("prepared-directory-identity-mismatch"),
                        )
                finally:
                    os.close(parent_fd)

                self._assert_safety_code(
                    "directory-creation-identity-inconclusive",
                    raised,
                )
                self.assertTrue(created_path.is_dir())
                self.assertFalse((root / "installed").exists())
                if returned_fd is not None:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(returned_fd)
                    self.assertEqual(closed.exception.errno, errno.EBADF)
                details = raised.exception.details
                self.assertTrue(details["mutation_performed"])
                self.assertFalse(details["retry_safe"])
                self.assertEqual(details["cleanup_state"], "inconclusive")
                self.assertEqual(
                    details["provider_install_state"],
                    "trusted-creator-malformed-result",
                )
                self.assertIn(
                    "identity_bound_directory_creation_malformed_result",
                    details["recovery_locators"],
                )
                self.assertIn(
                    "identity_bound_directory_creation_failure",
                    details["recovery_locators"],
                )
                self.assertIn(
                    "created_directory_install",
                    details["recovery_locators"],
                )
                malformed = details["recovery_locators"][
                    "identity_bound_directory_creation_malformed_result"
                ]
                self.assertEqual(
                    malformed["protected_property"],
                    "creation-identity-inconclusive",
                )
                self.assertFalse(
                    malformed["automatic_cleanup_attempted"],
                )

    def test_creator_handoff_replacement_is_retained_without_created_object_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parked = root / "provider-created-object"
            replacement = root / "provider-name-replacement"
            returned_fd: int | None = None

            def replace_before_handoff(
                parent_fd: int,
                prefix: str,
            ) -> MODULE._IdentityBoundDirectoryCreation:
                nonlocal returned_fd
                basename = f"{prefix}replacement-race"
                os.mkdir(basename, mode=0o700, dir_fd=parent_fd)
                returned_fd = os.open(
                    basename,
                    MODULE._directory_open_flags(),
                    dir_fd=parent_fd,
                )
                opened = os.fstat(returned_fd)
                parent = os.fstat(parent_fd)
                os.rename(
                    basename,
                    parked.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.mkdir(basename, mode=0o700, dir_fd=parent_fd)
                os.rename(
                    basename,
                    replacement.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.mkdir(basename, mode=0o700, dir_fd=parent_fd)
                return MODULE._IdentityBoundDirectoryCreation(
                    basename=basename,
                    fd=returned_fd,
                    opened=opened,
                    proof={
                        "schema": ("apple-notes-identity-bound-directory-creation/v1"),
                        "creation_authority": "test-provider-race",
                        "actual_created_object_descriptor_returned": True,
                        "namespace_exclusive_during_handoff": True,
                        "parent_identity": MODULE._identity(parent),
                        "parent_access_policy": MODULE._access_policy(parent),
                        "directory_identity": MODULE._identity(opened),
                        "directory_access_policy": MODULE._access_policy(opened),
                    },
                )

            parent_fd = os.open(root, MODULE._directory_open_flags())
            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        replace_before_handoff,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._create_and_install_directory_at(
                        parent_fd,
                        os.fstat(parent_fd),
                        "installed",
                        display_path=root / "installed",
                        revalidate_scope=None,
                        identity_code="prepared-directory-identity-mismatch",
                        access_policy_code=(
                            "prepared-directory-access-policy-mismatch"
                        ),
                        inconclusive_code=(
                            "prepared-directory-revalidation-inconclusive"
                        ),
                        collision_code="prepared-directory-identity-mismatch",
                    )
            finally:
                os.close(parent_fd)

            self._assert_safety_code(
                "prepared-directory-identity-mismatch",
                raised,
            )
            self.assertIsNotNone(returned_fd)
            assert returned_fd is not None
            with self.assertRaises(OSError) as closed:
                os.fstat(returned_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            self.assertTrue(parked.is_dir())
            self.assertTrue(replacement.is_dir())
            self.assertTrue((root / ".apple-notes-create-replacement-race").is_dir())
            self.assertFalse((root / "installed").exists())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertFalse(details["retry_safe"])
            recovery = details["recovery_locators"]["created_directory_install"]
            self.assertEqual(
                recovery["protected_property"],
                "creation-identity-inconclusive",
            )
            self.assertIsNone(recovery["creation_proof"])
            self.assertEqual(
                recovery["namespace_observations"]["staging_name"]["status"],
                "present",
            )
            self.assertNotIn(
                "transaction-created-object-identity",
                json.dumps(recovery, sort_keys=True),
            )

    def test_destination_component_install_rejects_access_policy_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            destination = root / "created-parent" / "snapshot"
            original_install = MODULE._install_created_directory_no_replace_at
            changed = False

            def chmod_after_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal changed
                original_install(parent_fd, staging_name, target_name)
                if target_name == "created-parent":
                    changed = True
                    os.chmod(
                        target_name,
                        0o750,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )

            with (
                mock.patch.object(
                    MODULE,
                    "_install_created_directory_no_replace_at",
                    side_effect=chmod_after_install,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                with MODULE._bind_live_safe_destination_parent(
                    paths,
                    destination,
                ):
                    self.fail("access-policy drift must not be yielded")

            self._assert_safety_code(
                "snapshot-destination-scope-inconclusive",
                raised,
            )
            self.assertTrue(changed)
            self.assertTrue(raised.exception.details["mutation_performed"])
            self.assertEqual(
                stat.S_IMODE(destination.parent.stat().st_mode),
                0o750,
            )
            recovery = raised.exception.details["recovery_locators"][
                "created_directory_install"
            ]
            self.assertFalse(
                recovery["created_descriptor"]["matches_creation_access_policy"]
            )

    def test_private_partial_replacement_between_install_and_target_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            live_root = root / "live"
            live_root.mkdir()
            paths = self._make_paths(live_root)
            source = root / "edited.sqlite"
            self._create_db(source)
            destination = root / "stage"
            parked = root / "transaction-created-partial"
            original_install = MODULE._install_created_directory_no_replace_at
            attacked = False

            def replace_partial_after_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal attacked
                self.assertTrue(staging_name.startswith(".apple-notes-create-"))
                self.assertNotEqual(staging_name, target_name)
                original_install(parent_fd, staging_name, target_name)
                if not target_name.startswith(".stage.partial-"):
                    return
                attacked = True
                os.rename(
                    target_name,
                    parked.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_install_created_directory_no_replace_at",
                    side_effect=replace_partial_after_install,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(source, destination, paths=paths)

            self._assert_safety_code(
                "prepared-directory-identity-mismatch",
                raised,
            )
            self.assertTrue(attacked)
            self.assertTrue(parked.is_dir())
            self.assertFalse(destination.exists())
            partials = list(root.glob(".stage.partial-*"))
            self.assertEqual(len(partials), 1)
            self.assertTrue(partials[0].is_dir())
            recovery = raised.exception.details["recovery_locators"][
                "created_directory_install"
            ]
            self.assertEqual(
                recovery["install_state"],
                "no-replace-install-returned",
            )
            self.assertFalse(
                recovery["namespace_observations"]["target_name"][
                    "matches_created_identity"
                ]
            )

    def test_private_partial_install_accepts_metadata_only_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            live_root = root / "live"
            live_root.mkdir()
            paths = self._make_paths(live_root)
            source = root / "edited.sqlite"
            self._create_db(source)
            destination = root / "stage"
            original_install = MODULE._install_created_directory_no_replace_at
            touched = False

            def touch_partial_after_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal touched
                original_install(parent_fd, staging_name, target_name)
                if target_name.startswith(".stage.partial-"):
                    touched = True
                    os.utime(
                        target_name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )

            with mock.patch.object(
                MODULE,
                "_install_created_directory_no_replace_at",
                side_effect=touch_partial_after_install,
            ):
                result = self._stage_patch(source, destination, paths=paths)

            self.assertTrue(touched)
            self.assertEqual(Path(result["stage_dir"]), destination)
            self.assertTrue(destination.is_dir())

    def test_private_partial_install_rejects_access_policy_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            live_root = root / "live"
            live_root.mkdir()
            paths = self._make_paths(live_root)
            source = root / "edited.sqlite"
            self._create_db(source)
            destination = root / "stage"
            original_install = MODULE._install_created_directory_no_replace_at
            changed = False

            def chmod_partial_after_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal changed
                original_install(parent_fd, staging_name, target_name)
                if target_name.startswith(".stage.partial-"):
                    changed = True
                    os.chmod(
                        target_name,
                        0o750,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )

            with (
                mock.patch.object(
                    MODULE,
                    "_install_created_directory_no_replace_at",
                    side_effect=chmod_partial_after_install,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(source, destination, paths=paths)

            self._assert_safety_code(
                "prepared-directory-access-policy-mismatch",
                raised,
            )
            self.assertTrue(changed)
            partial = self._assert_retained_partial(root, ".stage.partial-*")
            self.assertEqual(stat.S_IMODE(partial.stat().st_mode), 0o750)
            self.assertEqual(
                raised.exception.details["cleanup_state"],
                "preserved-no-identity-safe-directory-unlink",
            )
            recovery = raised.exception.details["recovery_locators"][
                "created_directory_install"
            ]
            self.assertFalse(
                recovery["created_descriptor"]["matches_creation_access_policy"]
            )

    def test_private_partial_install_collision_retains_exact_staging_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / ".stage.partial-fixed"
            original_install = MODULE._install_created_directory_no_replace_at
            collided = False

            def collide_before_install(
                parent_fd: int,
                staging_name: str,
                target_name: str,
            ) -> None:
                nonlocal collided
                collided = True
                os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)
                original_install(parent_fd, staging_name, target_name)

            with (
                mock.patch.object(
                    MODULE,
                    "_install_created_directory_no_replace_at",
                    side_effect=collide_before_install,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                with MODULE._create_bound_directory(target):
                    self.fail("no-replace collision must not yield a binding")

            self._assert_safety_code(
                "prepared-directory-revalidation-inconclusive",
                raised,
            )
            self.assertTrue(collided)
            self.assertTrue(target.is_dir())
            staged = list(root.glob(".apple-notes-create-*"))
            self.assertEqual(len(staged), 1)
            self.assertEqual(
                raised.exception.details["underlying_errno"],
                errno.EEXIST,
            )
            recovery = raised.exception.details["recovery_locators"][
                "created_directory_install"
            ]
            self.assertEqual(
                recovery["namespace_observations"]["staging_name"]["status"],
                "present",
            )
            self.assertTrue(
                recovery["namespace_observations"]["staging_name"][
                    "matches_created_identity"
                ]
            )
            self.assertFalse(
                recovery["namespace_observations"]["target_name"][
                    "matches_created_identity"
                ]
            )

    def test_copy_db_rejects_case_and_nfd_live_container_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            group = root / "Nótes"
            app = root / "App"
            group.mkdir()
            app.mkdir()
            paths = MODULE.NoteStorePaths(
                group_container=group,
                app_container=app,
            )
            self._create_db(group / MODULE.NOTE_STORE_MAIN)
            destinations = (
                root / "NÓTES" / "snapshot-case",
                root / "No\u0301tes" / "snapshot-nfd",
            )
            for destination in destinations:
                with (
                    self.subTest(destination=destination.name),
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    mock.patch.object(MODULE.os, "mkdir") as mkdir,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.copy_db(
                        paths,
                        dest=destination,
                        require_notes_quit=True,
                    )
                self._assert_safety_code(
                    "snapshot-destination-inside-live-container",
                    raised,
                )
                mkdir.assert_not_called()
                self.assertFalse(destination.exists())

    def test_copy_db_rejects_missing_reserved_sidecar_as_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            reserved = paths.group_container / f"{MODULE.NOTE_STORE_MAIN}-wal"
            self.assertFalse(reserved.exists())
            destination = reserved / "snapshot"
            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(MODULE.os, "mkdir") as mkdir,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )
            self._assert_safety_code(
                "snapshot-destination-reserved-store-path",
                raised,
            )
            mkdir.assert_not_called()
            self.assertFalse(reserved.exists())

    def test_live_scope_canonicalizes_absent_darwin_tmp_aliases_before_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app = root / "app"
            app.mkdir()
            basename = f"apple-notes-absent-live-{MODULE.uuid.uuid4().hex}"
            alias_live = Path("/tmp") / basename
            canonical_live = Path("/private/tmp") / basename
            cases = (
                (
                    alias_live,
                    canonical_live / "nested" / "snapshot",
                    "requested",
                    "canonical",
                ),
                (
                    canonical_live,
                    alias_live / "nested" / "snapshot",
                    "canonical",
                    "requested",
                ),
            )
            for (
                live_container,
                destination,
                expected_destination_form,
                expected_live_form,
            ) in cases:
                creator = mock.Mock(
                    side_effect=AssertionError(
                        "alias overlap must fail before directory creation"
                    )
                )
                with (
                    self.subTest(
                        live_container=live_container,
                        destination=destination,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_trusted_directory_alias_registry",
                        return_value=((Path("/tmp"), Path("/private/tmp")),),
                    ),
                    mock.patch.object(
                        MODULE,
                        "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                        creator,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_bind_snapshot_live_containers",
                        wraps=MODULE._bind_snapshot_live_containers,
                    ) as bind_live,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._bind_live_safe_destination_parent(
                        MODULE.NoteStorePaths(
                            group_container=live_container,
                            app_container=app,
                        ),
                        destination,
                    ):
                        self.fail("overlapping alias scope must not be yielded")

                self._assert_safety_code(
                    "snapshot-destination-inside-live-container",
                    raised,
                )
                self.assertFalse(raised.exception.details["mutation_performed"])
                self.assertEqual(
                    raised.exception.details["destination_scope_form"],
                    expected_destination_form,
                )
                self.assertEqual(
                    raised.exception.details["live_container_scope_form"],
                    expected_live_form,
                )
                bind_live.assert_not_called()
                creator.assert_not_called()
                self.assertFalse(os.path.lexists(alias_live))
                self.assertFalse(os.path.lexists(canonical_live))
                self.assertFalse(os.path.lexists(destination))

    @unittest.skipUnless(sys.platform == "darwin", "macOS root alias contract")
    def test_copy_db_supports_real_macos_tmp_alias(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            tempfile.NamedTemporaryFile(
                prefix="apple-notes-alias-name-",
                dir="/tmp",
            ) as unique_name,
        ):
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = Path(f"{unique_name.name}-snapshot")
            try:
                with mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    return_value=False,
                ):
                    result = self._copy_db(
                        paths,
                        dest=destination,
                        require_notes_quit=True,
                    )
                self.assertEqual(Path(result["dest"]), destination)
                self.assertTrue(destination.is_dir())
                self.assertEqual(
                    self._validate_snapshot(destination)["sqlite_validation"]["result"],
                    "ok",
                )
            finally:
                if destination.exists():
                    shutil.rmtree(destination)

    @unittest.skipUnless(sys.platform == "darwin", "macOS root alias contract")
    def test_real_macos_tmp_alias_spans_all_publication_boundaries(self) -> None:
        alias_root = Path(
            tempfile.mkdtemp(
                prefix="apple-notes-trusted-alias-boundaries-",
                dir="/tmp",
            )
        )
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                edited = root / "edited.sqlite"
                self._create_db(edited, value="edited")

                with mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    return_value=False,
                ):
                    snapshot = MODULE.copy_db(
                        paths,
                        dest=alias_root / "snapshot",
                        require_notes_quit=True,
                    )
                snapshot_dir = Path(snapshot["dest"])
                receipt_file = alias_root / "snapshot-receipt.json"
                receipt_file.write_text(
                    json.dumps(snapshot["manifest_creation_receipt"]),
                    encoding="utf-8",
                )

                original_receipt_parent = MODULE._bind_manifest_creation_receipt_parent
                receipt_alias_pairs: list[tuple[object, object]] = []

                @contextmanager
                def capture_receipt_parent_alias(
                    path: Path,
                    *,
                    trusted_alias: object = None,
                ) -> Iterator[MODULE._BoundDirectory]:
                    with original_receipt_parent(
                        path,
                        trusted_alias=trusted_alias,
                    ) as binding:
                        receipt_alias_pairs.append(
                            (trusted_alias, binding.trusted_alias)
                        )
                        yield binding

                with mock.patch.object(
                    MODULE,
                    "_bind_manifest_creation_receipt_parent",
                    side_effect=capture_receipt_parent_alias,
                ):
                    validation = MODULE.validate_snapshot(
                        snapshot_dir,
                        manifest_creation_receipt_file=receipt_file,
                    )

                merged = MODULE.merge_db(
                    source,
                    alias_root / "merged.sqlite",
                    paths=paths,
                )
                recovered = MODULE.recover_snapshot(
                    snapshot_dir,
                    alias_root / "recovered.sqlite",
                    manifest_creation_receipt_file=receipt_file,
                    paths=paths,
                )
                stage = MODULE.stage_patch(
                    edited,
                    alias_root / "stage",
                    paths=paths,
                )

                self.assertEqual(
                    validation["sqlite_validation"]["result"],
                    "ok",
                )
                self.assertEqual(len(receipt_alias_pairs), 1)
                carried_alias, receipt_parent_alias = receipt_alias_pairs[0]
                self.assertIsNotNone(carried_alias)
                self.assertIs(carried_alias, receipt_parent_alias)

                alias_receipts = (
                    snapshot["manifest_creation_destination_scope"]["trusted_alias"],
                    snapshot["terminal_destination_scope"]["trusted_alias"],
                    snapshot["descriptor_bound_destination"]["trusted_alias"],
                    merged["terminal_destination_scope"]["trusted_alias"],
                    merged["descriptor_bound_destination"]["trusted_alias"],
                    merged["terminal_public_path_revalidation"]["trusted_alias"],
                    recovered["recovered"]["terminal_destination_scope"][
                        "trusted_alias"
                    ],
                    recovered["recovered"]["descriptor_bound_destination"][
                        "trusted_alias"
                    ],
                    recovered["recovered"]["terminal_public_path_revalidation"][
                        "trusted_alias"
                    ],
                    stage["manifest_creation_destination_scope"]["trusted_alias"],
                    stage["terminal_destination_scope"]["trusted_alias"],
                    stage["descriptor_bound_destination"]["trusted_alias"],
                )
                for receipt in alias_receipts:
                    self.assertIsNotNone(receipt)
                    self.assertEqual(receipt["alias"], "/tmp")
                    self.assertEqual(
                        receipt["canonical_target"],
                        "/private/tmp",
                    )
                    self.assertIn("alias_parent_identity", receipt)
                    self.assertIn(
                        "canonical_target_receipt",
                        receipt,
                    )
        finally:
            shutil.rmtree(alias_root, ignore_errors=True)

    def test_carried_alias_rejects_terminal_retarget_and_replacement(
        self,
    ) -> None:
        operations = ("file-retarget", "directory-replacement")
        for operation in operations:
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir).resolve()
                live_root = root / "live"
                live_root.mkdir()
                paths = self._make_paths(live_root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                target = root / "canonical"
                alternate = root / "alternate"
                target.mkdir()
                alternate.mkdir()
                alias = root / "trusted-alias"
                parked_alias = root / "trusted-alias-original"
                alias.symlink_to(target, target_is_directory=True)
                registry = ((alias, target),)
                attacked = False

                if operation == "file-retarget":
                    original_terminal = MODULE._verify_installed_file_path

                    def attack_terminal(
                        prepared: MODULE._BoundRegularFile,
                        destination: Path,
                    ) -> object:
                        nonlocal attacked
                        self.assertIsNotNone(prepared.trusted_alias)
                        assert prepared.trusted_alias is not None
                        self.assertEqual(prepared.trusted_alias.alias, alias)
                        if not attacked:
                            attacked = True
                            alias.rename(parked_alias)
                            alias.symlink_to(
                                alternate,
                                target_is_directory=True,
                            )
                        return original_terminal(prepared, destination)

                    terminal_name = "_verify_installed_file_path"

                    def invoke_file_operation() -> object:
                        return MODULE.merge_db(
                            source,
                            alias / "merged.sqlite",
                            paths=paths,
                        )

                    invoke = invoke_file_operation
                    installed = target / "merged.sqlite"
                else:
                    original_terminal = MODULE._verify_installed_directory_path

                    def attack_terminal(
                        prepared: MODULE._BoundDirectory,
                        destination: Path,
                    ) -> object:
                        nonlocal attacked
                        self.assertIsNotNone(prepared.trusted_alias)
                        assert prepared.trusted_alias is not None
                        self.assertEqual(prepared.trusted_alias.alias, alias)
                        if not attacked:
                            attacked = True
                            alias.rename(parked_alias)
                            alias.symlink_to(
                                target,
                                target_is_directory=True,
                            )
                        return original_terminal(prepared, destination)

                    terminal_name = "_verify_installed_directory_path"

                    def invoke_directory_operation() -> object:
                        return MODULE.stage_patch(
                            source,
                            alias / "stage",
                            paths=paths,
                        )

                    invoke = invoke_directory_operation
                    installed = target / "stage"

                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_trusted_directory_alias_registry",
                            return_value=registry,
                        ),
                        mock.patch.object(
                            MODULE,
                            terminal_name,
                            side_effect=attack_terminal,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        invoke()
                    self._assert_safety_code(
                        "destination-install-uncertain",
                        raised,
                    )
                    self.assertTrue(attacked)
                    self.assertTrue(installed.exists())
                    self.assertEqual(list(alternate.iterdir()), [])
                    alias_evidence = raised.exception.details["recovery_locators"][
                        "descriptor_bound_destination"
                    ]["trusted_alias_before_terminal"]
                    self.assertEqual(
                        alias_evidence["alias"],
                        str(alias),
                    )
                    self.assertEqual(
                        alias_evidence["canonical_target"],
                        str(target),
                    )
                finally:
                    if alias.is_symlink():
                        alias.unlink()
                    if parked_alias.exists() or parked_alias.is_symlink():
                        parked_alias.rename(alias)

    def test_trusted_alias_revalidation_rejects_retarget_and_mocked_aba(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            live_root = root / "live"
            live_root.mkdir()
            paths = self._make_paths(live_root)
            target = root / "canonical"
            alternate = root / "alternate"
            target.mkdir()
            alternate.mkdir()
            alias = root / "trusted-alias"
            alias.symlink_to(target, target_is_directory=True)
            destination = alias / "output"
            registry = ((alias, target),)

            with mock.patch.object(
                MODULE,
                "_trusted_directory_alias_registry",
                return_value=registry,
            ):
                with self.assertRaises(MODULE.StoreSafetyError) as retargeted:
                    with MODULE._bind_live_safe_destination_parent(
                        paths,
                        destination,
                    ) as scope:
                        alias.unlink()
                        alias.symlink_to(alternate, target_is_directory=True)
                        scope.revalidate()
                self._assert_safety_code(
                    "snapshot-destination-scope-inconclusive",
                    retargeted,
                )

            alias.unlink()
            alias.symlink_to(target, target_is_directory=True)
            with mock.patch.object(
                MODULE,
                "_trusted_directory_alias_registry",
                return_value=registry,
            ):
                with MODULE._bind_live_safe_destination_parent(
                    paths,
                    destination,
                ) as scope:
                    real_readlink = MODULE.os.readlink
                    injected = False

                    def readlink_with_mocked_aba(
                        path: object,
                        *args: object,
                        **kwargs: object,
                    ) -> str:
                        nonlocal injected
                        if not injected and os.fspath(path) == alias.name:
                            injected = True
                            return os.path.relpath(alternate, alias.parent)
                        return real_readlink(path, *args, **kwargs)

                    with (
                        mock.patch.object(
                            MODULE.os,
                            "readlink",
                            side_effect=readlink_with_mocked_aba,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as aba,
                    ):
                        scope.revalidate()
                    self._assert_safety_code(
                        "snapshot-destination-scope-inconclusive",
                        aba,
                    )
                    self.assertTrue(injected)
            self.assertEqual(list(target.iterdir()), [])
            self.assertEqual(list(alternate.iterdir()), [])

    def test_absent_live_alias_replacement_fails_before_parent_creation(
        self,
    ) -> None:
        for attack in ("retarget", "same-target-replacement"):
            with (
                self.subTest(attack=attack),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir).resolve()
                target = root / "canonical"
                alternate = root / "alternate"
                app = root / "app"
                target.mkdir()
                alternate.mkdir()
                app.mkdir()
                alias = root / "trusted-alias"
                parked_alias = root / "trusted-alias-original"
                alias.symlink_to(target, target_is_directory=True)
                live_container = alias / "initially-absent-live"
                destination = root / "initially-absent-output-parent" / "output"
                paths = MODULE.NoteStorePaths(
                    group_container=live_container,
                    app_container=app,
                )
                registry = ((alias, target),)
                creator = mock.Mock(
                    side_effect=AssertionError(
                        "alias replacement must fail before directory creation"
                    )
                )
                original_verify = MODULE._verify_snapshot_live_container_bindings
                attacked = False

                def replace_alias_before_creation(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    nonlocal attacked
                    if not attacked:
                        attacked = True
                        alias.rename(parked_alias)
                        alias.symlink_to(
                            alternate if attack == "retarget" else target,
                            target_is_directory=True,
                        )
                    return original_verify(*args, **kwargs)

                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_trusted_directory_alias_registry",
                            return_value=registry,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_IDENTITY_BOUND_DIRECTORY_CREATOR",
                            creator,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_verify_snapshot_live_container_bindings",
                            side_effect=replace_alias_before_creation,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        with MODULE._bind_live_safe_destination_parent(
                            paths,
                            destination,
                        ):
                            self.fail("replaced live alias must not enter write scope")

                    self._assert_safety_code(
                        "snapshot-destination-scope-inconclusive",
                        raised,
                    )
                    self.assertTrue(attacked)
                    self.assertFalse(raised.exception.details["mutation_performed"])
                    creator.assert_not_called()
                    self.assertFalse(destination.parent.exists())
                    self.assertFalse((target / live_container.name).exists())
                    self.assertFalse((alternate / live_container.name).exists())
                finally:
                    if alias.is_symlink():
                        alias.unlink()
                    if parked_alias.is_symlink():
                        parked_alias.rename(alias)

    def test_untrusted_case_and_nfd_aliases_fail_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            live_root = root / "live"
            live_root.mkdir()
            paths = self._make_paths(live_root)
            target = root / "canonical"
            target.mkdir()
            registered_alias = root / "TrústAlias"
            variants = (
                root / "trústalias",
                root / unicodedata.normalize("NFD", registered_alias.name),
            )
            for index, variant in enumerate(variants):
                if variant.exists() or variant.is_symlink():
                    variant.unlink()
                variant.symlink_to(target, target_is_directory=True)
                destination = variant / f"output-{index}"
                with (
                    self.subTest(variant=variant.name),
                    mock.patch.object(
                        MODULE,
                        "_trusted_directory_alias_registry",
                        return_value=((registered_alias, target),),
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._bind_live_safe_destination_parent(
                        paths,
                        destination,
                    ):
                        self.fail("untrusted alias must not enter the write scope")
                self._assert_safety_code(
                    "snapshot-destination-scope-inconclusive",
                    raised,
                )
                self.assertEqual(list(target.iterdir()), [])
                variant.unlink()

    def test_all_write_commands_share_zero_write_live_container_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="edited")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_receipt = self._snapshot_manifest_receipts[snapshot_dir]

            operations = (
                (
                    "copy-db",
                    lambda destination: MODULE.copy_db(
                        paths,
                        dest=destination,
                        require_notes_quit=False,
                    ),
                ),
                (
                    "merge-db",
                    lambda destination: MODULE.merge_db(
                        live,
                        destination,
                        paths=paths,
                    ),
                ),
                (
                    "stage-patch",
                    lambda destination: MODULE.stage_patch(
                        edited,
                        destination,
                        paths=paths,
                    ),
                ),
                (
                    "recover-snapshot",
                    lambda destination: MODULE.recover_snapshot(
                        snapshot_dir,
                        destination,
                        snapshot_receipt,
                        paths=paths,
                    ),
                ),
            )
            for live_container in (paths.group_container, paths.app_container):
                for command, operation in operations:
                    destination = live_container / f"blocked-{command}"
                    before = sorted(os.listdir(live_container))
                    with (
                        self.subTest(
                            command=command,
                            live_container=live_container.name,
                        ),
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        operation(destination)
                    self._assert_safety_code(
                        "snapshot-destination-inside-live-container",
                        raised,
                    )
                    self.assertEqual(sorted(os.listdir(live_container)), before)
                    self.assertFalse(destination.exists())

    def test_live_scope_rejects_reserved_aliases_and_ancestor_traps_without_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            destinations = (
                root / MODULE.NOTE_STORE_MAIN / "output",
                root / MODULE.NOTE_STORE_ROLLBACK_JOURNAL.swapcase() / "output",
            )
            for destination in destinations:
                with (
                    self.subTest(destination=destination),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._bind_live_safe_destination_parent(
                        paths,
                        destination,
                    ):
                        self.fail("reserved destination must not enter write scope")
                self._assert_safety_code(
                    "snapshot-destination-reserved-store-path",
                    raised,
                )
                self.assertFalse(destination.parent.exists())
            with self.assertRaises(MODULE.StoreSafetyError) as ancestor:
                with MODULE._bind_live_safe_destination_parent(paths, root):
                    self.fail("live-container ancestor must not enter write scope")
            self._assert_safety_code(
                "snapshot-destination-inside-live-container",
                ancestor,
            )

    def test_source_revalidation_maps_hash_eio_to_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            original_hash = MODULE._hash_fd
            for fail_on_call in (1, 2, 3):
                hash_calls = 0

                def fail_selected_hash(fd: int) -> str:
                    nonlocal hash_calls
                    hash_calls += 1
                    if hash_calls == fail_on_call:
                        raise OSError(
                            MODULE.errno.EIO,
                            "simulated revalidation EIO",
                        )
                    return original_hash(fd)

                with (
                    self.subTest(fail_on_call=fail_on_call),
                    mock.patch.object(
                        MODULE,
                        "_hash_fd",
                        side_effect=fail_selected_hash,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.fingerprint_note_store(paths)

                self._assert_safety_code(
                    "source-revalidation-inconclusive",
                    raised,
                )

    def test_source_terminal_revalidation_detects_same_length_in_place_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            original_revalidate = MODULE._revalidate_open_source
            original_stat = source.stat()
            changed = False

            def mutate_after_primary_hashes(
                opened: MODULE._OpenedSource,
                second_sha256: str,
            ) -> dict[str, object]:
                nonlocal changed
                result = original_revalidate(opened, second_sha256)
                if not changed:
                    changed = True
                    with source.open("r+b") as handle:
                        handle.seek(source.stat().st_size // 2)
                        original = handle.read(1)
                        self.assertTrue(original)
                        handle.seek(-1, os.SEEK_CUR)
                        handle.write(bytes([original[0] ^ 0x01]))
                        handle.flush()
                        os.fsync(handle.fileno())
                    self.assertEqual(source.stat().st_size, original_stat.st_size)
                    os.utime(
                        source,
                        ns=(
                            original_stat.st_atime_ns,
                            original_stat.st_mtime_ns,
                        ),
                    )
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_revalidate_open_source",
                    side_effect=mutate_after_primary_hashes,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.fingerprint_note_store(paths)

        self.assertTrue(changed)
        self._assert_safety_code("source-content-mismatch", raised)

    def test_source_terminal_revalidation_allows_mtime_only_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            original_revalidate = MODULE._revalidate_open_source
            touched = False

            def touch_after_primary_hashes(
                opened: MODULE._OpenedSource,
                second_sha256: str,
            ) -> dict[str, object]:
                nonlocal touched
                result = original_revalidate(opened, second_sha256)
                if not touched:
                    touched = True
                    current = source.stat()
                    os.utime(
                        source,
                        ns=(
                            current.st_atime_ns,
                            current.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                return result

            with mock.patch.object(
                MODULE,
                "_revalidate_open_source",
                side_effect=touch_after_primary_hashes,
            ):
                result = MODULE.fingerprint_note_store(paths)

        self.assertTrue(touched)
        self.assertIn("mtime_ns", result["files"][0]["metadata_transitions"])

    def test_source_terminal_revalidation_checks_path_access_policy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            source.chmod(0o600)
            original_revalidate = MODULE._revalidate_open_source
            original_stat = MODULE.os.stat
            after_primary_revalidation = False
            attacked = False

            def mark_primary_revalidation(
                opened: MODULE._OpenedSource,
                second_sha256: str,
            ) -> dict[str, object]:
                nonlocal after_primary_revalidation
                result = original_revalidate(opened, second_sha256)
                after_primary_revalidation = True
                return result

            def chmod_before_terminal_path_stat(
                target: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal attacked
                if (
                    after_primary_revalidation
                    and not attacked
                    and Path(os.fspath(target)).name == source.name
                    and kwargs.get("dir_fd") is not None
                ):
                    attacked = True
                    source.chmod(0o640)
                return original_stat(target, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_revalidate_open_source",
                    side_effect=mark_primary_revalidation,
                ),
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=chmod_before_terminal_path_stat,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.fingerprint_note_store(paths)

        self.assertTrue(attacked)
        self._assert_safety_code("source-access-policy-mismatch", raised)

    def test_source_descriptor_revalidation_maps_estale_to_inconclusive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            fd, opened_stat = MODULE._open_regular_readonly(source)
            opened = MODULE._OpenedSource(
                path=source,
                fd=fd,
                before=opened_stat,
                first_sha256=MODULE._hash_fd(fd),
            )
            second_sha256 = MODULE._hash_fd(fd)
            try:
                with (
                    mock.patch.object(
                        MODULE.os,
                        "fstat",
                        side_effect=OSError(
                            getattr(MODULE.errno, "ESTALE", MODULE.errno.EIO),
                            "simulated stale descriptor",
                        ),
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._revalidate_open_source(
                        opened,
                        second_sha256,
                    )
            finally:
                os.close(fd)

        self._assert_safety_code(
            "source-revalidation-inconclusive",
            raised,
        )

    def test_source_path_revalidation_preserves_error_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            fd, opened_stat = MODULE._open_regular_readonly(source)
            opened = MODULE._OpenedSource(
                path=source,
                fd=fd,
                before=opened_stat,
                first_sha256=MODULE._hash_fd(fd),
            )
            second_sha256 = MODULE._hash_fd(fd)
            cases = (
                (
                    FileNotFoundError(MODULE.errno.ENOENT, "simulated missing"),
                    "source-missing-after-read",
                ),
                (
                    PermissionError(MODULE.errno.EACCES, "simulated unreadable"),
                    "source-revalidation-unreadable",
                ),
                (
                    OSError(
                        getattr(MODULE.errno, "ESTALE", MODULE.errno.EIO),
                        "simulated stale handle",
                    ),
                    "source-revalidation-inconclusive",
                ),
            )
            try:
                for fault, expected_code in cases:
                    with (
                        self.subTest(expected_code=expected_code),
                        mock.patch.object(
                            MODULE.os,
                            "stat",
                            side_effect=fault,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._revalidate_open_source(
                            opened,
                            second_sha256,
                        )
                    self._assert_safety_code(expected_code, raised)
            finally:
                os.close(fd)

    def test_probe_access_preserves_post_open_source_error_classes(self) -> None:
        cases = (
            (
                FileNotFoundError(MODULE.errno.ENOENT, "simulated disappearance"),
                "source-missing-after-read",
            ),
            (
                PermissionError(MODULE.errno.EACCES, "simulated unreadable source"),
                "source-revalidation-unreadable",
            ),
            (
                OSError(MODULE.errno.EIO, "simulated source revalidation EIO"),
                "source-revalidation-inconclusive",
            ),
        )
        for fault, expected_code in cases:
            with (
                self.subTest(expected_code=expected_code),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                original_stat = MODULE.os.stat
                target_stats = 0

                def fail_post_open_source_stat(
                    target: object,
                    *args: object,
                    **kwargs: object,
                ) -> os.stat_result:
                    nonlocal target_stats
                    if (
                        kwargs.get("dir_fd") is not None
                        and os.fspath(target) == source.name
                    ):
                        target_stats += 1
                        if target_stats == 2:
                            raise fault
                    return original_stat(target, *args, **kwargs)

                with mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=fail_post_open_source_stat,
                ):
                    result = MODULE.probe_db_access(paths)

                self.assertGreaterEqual(target_stats, 2)
                source_record = next(
                    record
                    for record in result["note_store_files"]
                    if Path(record["path"]) == source
                )
                self.assertTrue(source_record["exists"])
                self.assertFalse(source_record["readable"])
                self.assertEqual(source_record["error_code"], expected_code)

    def test_probe_initial_group_failure_propagates_dependency_classification(
        self,
    ) -> None:
        cases = (
            (
                PermissionError(
                    MODULE.errno.EACCES,
                    "simulated initial group unreadable",
                ),
                "container-unreadable",
            ),
            (
                OSError(
                    MODULE.errno.EIO,
                    "simulated initial group EIO",
                ),
                "container-revalidation-inconclusive",
            ),
            (
                MODULE.StoreSafetyError(
                    "prepared-directory-missing",
                    "simulated initial group absence",
                ),
                None,
            ),
        )
        original_bind = MODULE._bind_existing_directory_with_trusted_alias
        for fault, expected_code in cases:
            with (
                self.subTest(expected_code=expected_code),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)

                def fail_initial_group_bind(
                    path: Path,
                    *,
                    trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
                ) -> object:
                    if path == paths.group_container:
                        raise fault
                    return original_bind(
                        path,
                        trusted_alias=trusted_alias,
                    )

                with mock.patch.object(
                    MODULE,
                    "_bind_existing_directory_with_trusted_alias",
                    side_effect=fail_initial_group_bind,
                ):
                    result = MODULE.probe_db_access(paths)

                group_record = next(
                    record
                    for record in result["paths"]
                    if Path(record["path"]) == paths.group_container
                )
                app_record = next(
                    record
                    for record in result["paths"]
                    if Path(record["path"]) == paths.app_container
                )
                self.assertFalse(group_record["readable"])
                self.assertTrue(app_record["readable"])
                for file_record in result["note_store_files"]:
                    self.assertFalse(file_record["exists"])
                    self.assertFalse(file_record["readable"])
                    self.assertNotIn("size", file_record)
                    self.assertNotIn("identity", file_record)
                    self.assertNotIn("access_policy", file_record)
                    if expected_code is None:
                        self.assertNotIn("error_code", group_record)
                        self.assertNotIn("error_code", file_record)
                        self.assertNotIn("error", file_record)
                    else:
                        self.assertEqual(
                            group_record["error_code"],
                            expected_code,
                        )
                        self.assertEqual(
                            file_record["error_code"],
                            expected_code,
                        )
                        self.assertIn("error", file_record)

    def test_probe_initial_app_failure_does_not_taint_group_file_rows(
        self,
    ) -> None:
        cases = (
            (
                PermissionError(
                    MODULE.errno.EACCES,
                    "simulated initial app unreadable",
                ),
                "container-unreadable",
            ),
            (
                OSError(
                    MODULE.errno.EIO,
                    "simulated initial app EIO",
                ),
                "container-revalidation-inconclusive",
            ),
        )
        original_bind = MODULE._bind_existing_directory_with_trusted_alias
        for fault, expected_code in cases:
            with (
                self.subTest(expected_code=expected_code),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)

                def fail_initial_app_bind(
                    path: Path,
                    *,
                    trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
                ) -> object:
                    if path == paths.app_container:
                        raise fault
                    return original_bind(
                        path,
                        trusted_alias=trusted_alias,
                    )

                with mock.patch.object(
                    MODULE,
                    "_bind_existing_directory_with_trusted_alias",
                    side_effect=fail_initial_app_bind,
                ):
                    result = MODULE.probe_db_access(paths)

                app_record = next(
                    record
                    for record in result["paths"]
                    if Path(record["path"]) == paths.app_container
                )
                self.assertFalse(app_record["readable"])
                self.assertEqual(app_record["error_code"], expected_code)
                source_record = next(
                    record
                    for record in result["note_store_files"]
                    if Path(record["path"]) == source
                )
                self.assertTrue(source_record["exists"])
                self.assertTrue(source_record["readable"])
                self.assertIn("size", source_record)
                self.assertIn("identity", source_record)
                self.assertIn("access_policy", source_record)
                for file_record in result["note_store_files"]:
                    self.assertNotEqual(
                        file_record.get("error_code"),
                        expected_code,
                    )

    def test_probe_contains_each_container_context_exit_failure(self) -> None:
        fault_profiles = (
            (
                lambda: FileNotFoundError(
                    MODULE.errno.ENOENT,
                    "simulated container exit disappearance",
                ),
                "source-missing-after-read",
            ),
            (
                lambda: PermissionError(
                    MODULE.errno.EACCES,
                    "simulated container exit unreadable",
                ),
                "source-revalidation-unreadable",
            ),
            (
                lambda: OSError(
                    MODULE.errno.EIO,
                    "simulated container exit revalidation failure",
                ),
                "source-revalidation-inconclusive",
            ),
            (
                lambda: MODULE.StoreSafetyError(
                    "prepared-directory-identity-mismatch",
                    "simulated container exit replacement",
                ),
                "source-identity-mismatch",
            ),
            (
                lambda: MODULE.StoreSafetyError(
                    "prepared-directory-access-policy-mismatch",
                    "simulated container exit access-policy change",
                ),
                "source-access-policy-mismatch",
            ),
        )
        original_bind = MODULE._bind_existing_directory_with_trusted_alias
        for container_name in ("group_container", "app_container"):
            for fault_factory, expected_code in fault_profiles:
                with (
                    self.subTest(
                        container=container_name,
                        expected_code=expected_code,
                    ),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    source = paths.group_container / MODULE.NOTE_STORE_MAIN
                    self._create_db(source)
                    target = getattr(paths, container_name)

                    @contextmanager
                    def fail_selected_context_exit(
                        path: Path,
                        *,
                        trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
                    ) -> Iterator[MODULE._BoundDirectory]:
                        with original_bind(
                            path,
                            trusted_alias=trusted_alias,
                        ) as binding:
                            yield binding
                        if path == target:
                            raise fault_factory()

                    with mock.patch.object(
                        MODULE,
                        "_bind_existing_directory_with_trusted_alias",
                        side_effect=fail_selected_context_exit,
                    ):
                        result = MODULE.probe_db_access(paths)

                    target_record = next(
                        record
                        for record in result["paths"]
                        if Path(record["path"]) == target
                    )
                    self.assertTrue(target_record["exists"])
                    self.assertFalse(target_record["readable"])
                    self.assertEqual(target_record["error_code"], expected_code)
                    self.assertFalse(
                        target_record["error_code"].startswith("prepared-directory-")
                    )
                    source_record = next(
                        record
                        for record in result["note_store_files"]
                        if Path(record["path"]) == source
                    )
                    if container_name == "group_container":
                        for file_record in result["note_store_files"]:
                            self.assertFalse(file_record["readable"])
                            self.assertEqual(
                                file_record["error_code"],
                                expected_code,
                            )
                            self.assertNotIn("size", file_record)
                            self.assertNotIn("identity", file_record)
                            self.assertNotIn("access_policy", file_record)
                        self.assertTrue(source_record["exists"])
                    else:
                        self.assertTrue(source_record["exists"])
                        self.assertTrue(source_record["readable"])
                        self.assertIn("size", source_record)
                        self.assertIn("identity", source_record)
                        self.assertIn("access_policy", source_record)

    def test_probe_explicit_terminal_check_uses_source_taxonomy(self) -> None:
        fault_profiles = (
            (
                lambda: FileNotFoundError(
                    MODULE.errno.ENOENT,
                    "simulated explicit terminal disappearance",
                ),
                "source-missing-after-read",
            ),
            (
                lambda: PermissionError(
                    MODULE.errno.EACCES,
                    "simulated explicit terminal unreadable",
                ),
                "source-revalidation-unreadable",
            ),
            (
                lambda: OSError(
                    MODULE.errno.EIO,
                    "simulated explicit terminal EIO",
                ),
                "source-revalidation-inconclusive",
            ),
            (
                lambda: MODULE.StoreSafetyError(
                    "prepared-directory-identity-mismatch",
                    "simulated explicit terminal replacement",
                ),
                "source-identity-mismatch",
            ),
            (
                lambda: MODULE.StoreSafetyError(
                    "prepared-directory-access-policy-mismatch",
                    "simulated explicit terminal access-policy change",
                ),
                "source-access-policy-mismatch",
            ),
        )
        original_sample = MODULE._bounded_probe_directory_sample
        original_verify = MODULE._verify_bound_directory_namespace
        for container_name in ("group_container", "app_container"):
            for fault_factory, expected_code in fault_profiles:
                with (
                    self.subTest(
                        container=container_name,
                        expected_code=expected_code,
                    ),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    source = paths.group_container / MODULE.NOTE_STORE_MAIN
                    self._create_db(source)
                    target = getattr(paths, container_name)
                    target_sample_index = (
                        1 if container_name == "group_container" else 2
                    )
                    sample_count = 0
                    fail_next_target_verify = False

                    def arm_after_selected_sample(directory_fd: int) -> list[str]:
                        nonlocal sample_count, fail_next_target_verify
                        sampled = original_sample(directory_fd)
                        sample_count += 1
                        if sample_count == target_sample_index:
                            fail_next_target_verify = True
                        return sampled

                    def fail_selected_explicit_terminal_check(
                        binding: MODULE._BoundDirectory,
                    ) -> dict[str, object]:
                        nonlocal fail_next_target_verify
                        if fail_next_target_verify and binding.path == target:
                            fail_next_target_verify = False
                            raise fault_factory()
                        return original_verify(binding)

                    with (
                        mock.patch.object(
                            MODULE,
                            "_bounded_probe_directory_sample",
                            side_effect=arm_after_selected_sample,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_verify_bound_directory_namespace",
                            side_effect=fail_selected_explicit_terminal_check,
                        ),
                    ):
                        result = MODULE.probe_db_access(paths)

                    self.assertFalse(fail_next_target_verify)
                    target_record = next(
                        record
                        for record in result["paths"]
                        if Path(record["path"]) == target
                    )
                    self.assertTrue(target_record["exists"])
                    self.assertFalse(target_record["readable"])
                    self.assertEqual(target_record["error_code"], expected_code)
                    self.assertFalse(
                        target_record["error_code"].startswith("prepared-directory-")
                    )
                    self.assertIn("sample_children", target_record)
                    source_record = next(
                        record
                        for record in result["note_store_files"]
                        if Path(record["path"]) == source
                    )
                    if container_name == "group_container":
                        for file_record in result["note_store_files"]:
                            self.assertFalse(file_record["readable"])
                            self.assertEqual(
                                file_record["error_code"],
                                expected_code,
                            )
                            self.assertIn("error", file_record)
                            self.assertNotIn("size", file_record)
                            self.assertNotIn("identity", file_record)
                            self.assertNotIn("access_policy", file_record)
                        self.assertFalse(source_record["exists"])
                    else:
                        self.assertTrue(source_record["exists"])
                        self.assertTrue(source_record["readable"])
                        self.assertIn("size", source_record)
                        self.assertIn("identity", source_record)
                        self.assertIn("access_policy", source_record)
                        self.assertNotIn("error_code", source_record)

    def test_probe_same_container_path_closes_each_role_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            shared = Path(temp_dir) / "shared"
            shared.mkdir()
            source = shared / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            paths = MODULE.NoteStorePaths(
                group_container=shared,
                app_container=shared,
            )
            original_bind = MODULE._bind_existing_directory_with_trusted_alias
            contexts: list[object] = []

            class TrackingContext:
                def __init__(
                    self,
                    path: Path,
                    trusted_alias: MODULE._TrustedDirectoryAlias | None,
                ) -> None:
                    self.inner = original_bind(
                        path,
                        trusted_alias=trusted_alias,
                    )
                    self.entered = False
                    self.exited = False
                    self.binding_fd: int | None = None

                def __enter__(self) -> MODULE._BoundDirectory:
                    binding = self.inner.__enter__()
                    self.entered = True
                    self.binding_fd = binding.fd
                    return binding

                def __exit__(
                    self,
                    exc_type: object,
                    exc: object,
                    traceback: object,
                ) -> object:
                    self.exited = True
                    return self.inner.__exit__(exc_type, exc, traceback)

            def tracked_bind(
                path: Path,
                *,
                trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
            ) -> TrackingContext:
                context = TrackingContext(path, trusted_alias)
                contexts.append(context)
                return context

            try:
                with mock.patch.object(
                    MODULE,
                    "_bind_existing_directory_with_trusted_alias",
                    side_effect=tracked_bind,
                ):
                    result = MODULE.probe_db_access(paths)

                self.assertEqual(len(contexts), 2)
                self.assertTrue(all(context.entered for context in contexts))
                self.assertTrue(all(context.exited for context in contexts))
                for context in contexts:
                    self.assertIsNotNone(context.binding_fd)
                    with self.assertRaises(OSError) as raised:
                        os.fstat(context.binding_fd)
                    self.assertEqual(raised.exception.errno, errno.EBADF)
            finally:
                for context in reversed(contexts):
                    if context.entered and not context.exited:
                        context.__exit__(None, None, None)

            self.assertEqual(len(result["paths"]), 2)
            self.assertTrue(all(record["readable"] for record in result["paths"]))
            source_record = next(
                record
                for record in result["note_store_files"]
                if Path(record["path"]) == source
            )
            self.assertTrue(source_record["exists"])
            self.assertTrue(source_record["readable"])

    def test_probe_sample_stops_at_entry_and_raw_name_byte_caps(self) -> None:
        class FakeEntry:
            def __init__(self, name: str) -> None:
                self.name = name

        class CountingScandir:
            def __init__(self, names: Iterator[str]) -> None:
                self._names = names
                self.next_calls = 0

            def __enter__(self) -> CountingScandir:
                return self

            def __exit__(
                self,
                exc_type: object,
                exc: object,
                traceback: object,
            ) -> None:
                return None

            def __iter__(self) -> CountingScandir:
                return self

            def __next__(self) -> FakeEntry:
                self.next_calls += 1
                return FakeEntry(next(self._names))

        entry_scan = CountingScandir(
            iter(
                f"entry-{index}"
                for index in range(MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES + 100)
            )
        )
        with (
            mock.patch.object(MODULE.os, "scandir", return_value=entry_scan),
            self.assertRaises(MODULE.StoreSafetyError) as entry_raised,
        ):
            MODULE._bounded_probe_directory_sample(123)
        self._assert_safety_code(
            "container-revalidation-inconclusive",
            entry_raised,
        )
        self.assertEqual(
            entry_scan.next_calls,
            MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES + 1,
        )
        self.assertEqual(
            entry_raised.exception.details["entry_limit"],
            MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES,
        )

        long_name = "é" * 128
        encoded_name_bytes = len(os.fsencode(long_name))
        name_scan = CountingScandir(iter(long_name for _ in range(100)))
        with (
            mock.patch.object(MODULE.os, "scandir", return_value=name_scan),
            self.assertRaises(MODULE.StoreSafetyError) as name_raised,
        ):
            MODULE._bounded_probe_directory_sample(123)
        self._assert_safety_code(
            "container-revalidation-inconclusive",
            name_raised,
        )
        expected_calls = (
            MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES // encoded_name_bytes + 1
        )
        self.assertEqual(name_scan.next_calls, expected_calls)
        self.assertEqual(
            name_raised.exception.details["raw_name_bytes_limit"],
            MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES,
        )

    def test_probe_reports_oversized_container_sample_as_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(Path(temp_dir))
            for index in range(MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES + 1):
                (paths.group_container / f"entry-{index}").write_bytes(b"")

            result = MODULE.probe_db_access(paths)

        group_record = next(
            record
            for record in result["paths"]
            if Path(record["path"]) == paths.group_container
        )
        self.assertTrue(group_record["exists"])
        self.assertFalse(group_record["readable"])
        self.assertEqual(
            group_record["error_code"],
            "container-revalidation-inconclusive",
        )

    def test_descriptor_relative_open_maps_post_open_fstat_and_parent_errors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)

            with MODULE._bind_existing_directory_with_trusted_alias(root) as parent:
                original_open = MODULE.os.open
                original_fstat = MODULE.os.fstat
                opened_source_fd: int | None = None

                def record_source_open(
                    target: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal opened_source_fd
                    fd = original_open(target, flags, mode, dir_fd=dir_fd)
                    if dir_fd == parent.fd and os.fspath(target) == source.name:
                        opened_source_fd = fd
                    return fd

                def fail_source_fstat(fd: int) -> os.stat_result:
                    if fd == opened_source_fd:
                        raise OSError(MODULE.errno.EIO, "simulated fstat EIO")
                    return original_fstat(fd)

                with (
                    mock.patch.object(
                        MODULE.os,
                        "open",
                        side_effect=record_source_open,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "fstat",
                        side_effect=fail_source_fstat,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._open_regular_readonly_at(
                        parent,
                        source.name,
                        display_path=source,
                    )

                self._assert_safety_code(
                    "source-revalidation-inconclusive",
                    raised,
                )

                original_verify = MODULE._verify_bound_directory_namespace
                source_revalidations = 0

                def fail_post_open_parent_revalidation(
                    directory: MODULE._BoundDirectory,
                ) -> dict[str, object]:
                    nonlocal source_revalidations
                    if directory.path == root:
                        source_revalidations += 1
                        if source_revalidations == 2:
                            raise PermissionError(
                                MODULE.errno.EACCES,
                                "simulated parent access failure",
                            )
                    return original_verify(directory)

                with (
                    mock.patch.object(
                        MODULE,
                        "_verify_bound_directory_namespace",
                        side_effect=fail_post_open_parent_revalidation,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._open_regular_readonly_at(
                        parent,
                        source.name,
                        display_path=source,
                    )

                self._assert_safety_code(
                    "source-revalidation-unreadable",
                    raised,
                )

    def test_bound_source_file_post_open_errors_close_fd_and_preserve_errno(
        self,
    ) -> None:
        cases = (
            (
                FileNotFoundError,
                MODULE.errno.ENOENT,
                "source-missing-after-read",
            ),
            (
                PermissionError,
                MODULE.errno.EACCES,
                "source-revalidation-unreadable",
            ),
            (
                OSError,
                MODULE.errno.EIO,
                "source-revalidation-inconclusive",
            ),
        )
        for operation in ("fstat", "path-stat"):
            for error_type, error_number, expected_code in cases:
                with (
                    self.subTest(operation=operation, expected_code=expected_code),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    source = root / MODULE.NOTE_STORE_MAIN
                    self._create_db(source)
                    fault = error_type(error_number, "simulated post-open failure")

                    with MODULE._bind_existing_directory_with_trusted_alias(
                        root
                    ) as parent:
                        original_open = MODULE.os.open
                        original_fstat = MODULE.os.fstat
                        original_stat = MODULE.os.stat
                        opened_source_fd: int | None = None
                        source_path_stats = 0

                        def record_source_open(
                            target: object,
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            nonlocal opened_source_fd
                            fd = original_open(target, flags, mode, dir_fd=dir_fd)
                            if dir_fd == parent.fd and os.fspath(target) == source.name:
                                opened_source_fd = fd
                            return fd

                        def fail_source_fstat(fd: int) -> os.stat_result:
                            if operation == "fstat" and fd == opened_source_fd:
                                raise fault
                            return original_fstat(fd)

                        def fail_source_path_stat(
                            target: object,
                            *args: object,
                            **kwargs: object,
                        ) -> os.stat_result:
                            nonlocal source_path_stats
                            if (
                                kwargs.get("dir_fd") == parent.fd
                                and os.fspath(target) == source.name
                            ):
                                source_path_stats += 1
                                if operation == "path-stat" and source_path_stats == 2:
                                    raise fault
                            return original_stat(target, *args, **kwargs)

                        with (
                            mock.patch.object(
                                MODULE.os,
                                "open",
                                side_effect=record_source_open,
                            ),
                            mock.patch.object(
                                MODULE.os,
                                "fstat",
                                side_effect=fail_source_fstat,
                            ),
                            mock.patch.object(
                                MODULE.os,
                                "stat",
                                side_effect=fail_source_path_stat,
                            ),
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            with MODULE._bind_regular_file_at(
                                source,
                                parent,
                                MODULE.SOURCE_FILE_CODES,
                            ):
                                self.fail("post-open source failure was accepted")

                        self._assert_safety_code(expected_code, raised)
                        self.assertIsNotNone(opened_source_fd)
                        assert opened_source_fd is not None
                        with self.assertRaises(OSError) as closed:
                            os.fstat(opened_source_fd)
                        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_bound_source_file_initial_stat_and_open_errors_preserve_taxonomy(
        self,
    ) -> None:
        cases = (
            (
                FileNotFoundError,
                MODULE.errno.ENOENT,
                "source-missing-after-read",
            ),
            (
                PermissionError,
                MODULE.errno.EACCES,
                "source-revalidation-unreadable",
            ),
            (
                PermissionError,
                MODULE.errno.EPERM,
                "source-revalidation-unreadable",
            ),
            (
                OSError,
                MODULE.errno.EIO,
                "source-revalidation-inconclusive",
            ),
        )
        for operation in ("initial-stat", "open"):
            for error_type, error_number, expected_code in cases:
                with (
                    self.subTest(
                        operation=operation,
                        error_number=error_number,
                        expected_code=expected_code,
                    ),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    source = root / MODULE.NOTE_STORE_MAIN
                    self._create_db(source)
                    fault = error_type(
                        error_number,
                        f"simulated source {operation} failure",
                    )
                    source_stat_calls = 0
                    source_open_attempts = 0

                    with MODULE._bind_existing_directory_with_trusted_alias(
                        root
                    ) as parent:
                        original_stat = MODULE.os.stat
                        original_open = MODULE.os.open

                        def fail_source_initial_stat(
                            target: object,
                            *args: object,
                            **kwargs: object,
                        ) -> os.stat_result:
                            nonlocal source_stat_calls
                            if (
                                kwargs.get("dir_fd") == parent.fd
                                and os.fspath(target) == source.name
                            ):
                                source_stat_calls += 1
                                if operation == "initial-stat":
                                    raise fault
                            return original_stat(target, *args, **kwargs)

                        def fail_source_open(
                            target: object,
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            nonlocal source_open_attempts
                            if dir_fd == parent.fd and os.fspath(target) == source.name:
                                source_open_attempts += 1
                                if operation == "open":
                                    raise fault
                            if dir_fd is None:
                                return original_open(target, flags, mode)
                            return original_open(
                                target,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )

                        with (
                            mock.patch.object(
                                MODULE.os,
                                "stat",
                                side_effect=fail_source_initial_stat,
                            ),
                            mock.patch.object(
                                MODULE.os,
                                "open",
                                side_effect=fail_source_open,
                            ),
                            mock.patch.object(MODULE, "_hash_fd") as hash_fd,
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            with MODULE._bind_regular_file_at(
                                source,
                                parent,
                                MODULE.SOURCE_FILE_CODES,
                            ):
                                self.fail("initial source binding failure was accepted")

                        self._assert_safety_code(expected_code, raised)
                        self.assertEqual(source_stat_calls, 1)
                        self.assertEqual(
                            source_open_attempts,
                            0 if operation == "initial-stat" else 1,
                        )
                        hash_fd.assert_not_called()

    def test_non_source_initial_permission_errors_remain_domain_inconclusive(
        self,
    ) -> None:
        for operation in ("initial-stat", "open"):
            for error_number in (MODULE.errno.EACCES, MODULE.errno.EPERM):
                with (
                    self.subTest(
                        operation=operation,
                        error_number=error_number,
                    ),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    snapshot = root / MODULE.NOTE_STORE_MAIN
                    self._create_db(snapshot)
                    fault = PermissionError(
                        error_number,
                        f"simulated snapshot {operation} failure",
                    )

                    with MODULE._bind_existing_directory_with_trusted_alias(
                        root
                    ) as parent:
                        original_stat = MODULE.os.stat
                        original_open = MODULE.os.open

                        def fail_snapshot_initial_stat(
                            target: object,
                            *args: object,
                            **kwargs: object,
                        ) -> os.stat_result:
                            if (
                                operation == "initial-stat"
                                and kwargs.get("dir_fd") == parent.fd
                                and os.fspath(target) == snapshot.name
                            ):
                                raise fault
                            return original_stat(target, *args, **kwargs)

                        def fail_snapshot_open(
                            target: object,
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            if (
                                operation == "open"
                                and dir_fd == parent.fd
                                and os.fspath(target) == snapshot.name
                            ):
                                raise fault
                            if dir_fd is None:
                                return original_open(target, flags, mode)
                            return original_open(
                                target,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )

                        with (
                            mock.patch.object(
                                MODULE.os,
                                "stat",
                                side_effect=fail_snapshot_initial_stat,
                            ),
                            mock.patch.object(
                                MODULE.os,
                                "open",
                                side_effect=fail_snapshot_open,
                            ),
                            mock.patch.object(MODULE, "_hash_fd") as hash_fd,
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            with MODULE._bind_regular_file_at(
                                snapshot,
                                parent,
                                MODULE.SNAPSHOT_FILE_CODES,
                            ):
                                self.fail(
                                    "initial snapshot binding failure was accepted"
                                )

                        self._assert_safety_code(
                            MODULE.SNAPSHOT_FILE_CODES.inconclusive,
                            raised,
                        )
                        hash_fd.assert_not_called()

    def test_bound_source_file_rejects_mode_drift_across_open_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            source.chmod(0o600)

            with MODULE._bind_existing_directory_with_trusted_alias(root) as parent:
                original_open = MODULE.os.open
                opened_source_fd: int | None = None

                def mutate_mode_during_source_open(
                    target: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal opened_source_fd
                    fd = original_open(target, flags, mode, dir_fd=dir_fd)
                    if dir_fd == parent.fd and os.fspath(target) == source.name:
                        opened_source_fd = fd
                        os.fchmod(fd, 0o640)
                    return fd

                with (
                    mock.patch.object(
                        MODULE.os,
                        "open",
                        side_effect=mutate_mode_during_source_open,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._bind_regular_file_at(
                        source,
                        parent,
                        MODULE.SOURCE_FILE_CODES,
                    ):
                        self.fail("source mode drift across open was accepted")

            self._assert_safety_code("source-access-policy-mismatch", raised)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o640)
            self.assertIsNotNone(opened_source_fd)
            assert opened_source_fd is not None
            with self.assertRaises(OSError) as closed:
                os.fstat(opened_source_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_bound_source_file_rejects_ownership_drift_across_open_boundary(
        self,
    ) -> None:
        for attribute in ("st_uid", "st_gid"):
            with (
                self.subTest(attribute=attribute),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                source = root / MODULE.NOTE_STORE_MAIN
                self._create_db(source)

                with MODULE._bind_existing_directory_with_trusted_alias(root) as parent:
                    original_open = MODULE.os.open
                    original_fstat = MODULE.os.fstat
                    original_stat = MODULE.os.stat
                    opened_source_fd: int | None = None

                    def observe_source_open(
                        target: object,
                        flags: int,
                        mode: int = 0o777,
                        *,
                        dir_fd: int | None = None,
                    ) -> int:
                        nonlocal opened_source_fd
                        fd = original_open(target, flags, mode, dir_fd=dir_fd)
                        if dir_fd == parent.fd and os.fspath(target) == source.name:
                            opened_source_fd = fd
                        return fd

                    def source_fstat_with_drift(fd: int) -> os.stat_result:
                        observed = original_fstat(fd)
                        if fd == opened_source_fd:
                            return _StatWithOverrides(
                                observed,
                                **{attribute: getattr(observed, attribute) + 1},
                            )
                        return observed

                    def source_stat_with_drift(
                        target: object,
                        *args: object,
                        **kwargs: object,
                    ) -> os.stat_result:
                        observed = original_stat(target, *args, **kwargs)
                        if (
                            opened_source_fd is not None
                            and kwargs.get("dir_fd") == parent.fd
                            and os.fspath(target) == source.name
                        ):
                            return _StatWithOverrides(
                                observed,
                                **{attribute: getattr(observed, attribute) + 1},
                            )
                        return observed

                    with (
                        mock.patch.object(
                            MODULE.os,
                            "open",
                            side_effect=observe_source_open,
                        ),
                        mock.patch.object(
                            MODULE.os,
                            "fstat",
                            side_effect=source_fstat_with_drift,
                        ),
                        mock.patch.object(
                            MODULE.os,
                            "stat",
                            side_effect=source_stat_with_drift,
                        ),
                        mock.patch.object(MODULE, "_hash_fd") as hash_fd,
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        with MODULE._bind_regular_file_at(
                            source,
                            parent,
                            MODULE.SOURCE_FILE_CODES,
                        ):
                            self.fail("source ownership drift across open was accepted")

                self._assert_safety_code(
                    "source-access-policy-mismatch",
                    raised,
                )
                hash_fd.assert_not_called()
                self.assertIsNotNone(opened_source_fd)
                assert opened_source_fd is not None
                with self.assertRaises(OSError) as closed:
                    os.fstat(opened_source_fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_bound_source_file_rejects_path_policy_drift_after_opened_fstat(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            source.chmod(0o600)

            with MODULE._bind_existing_directory_with_trusted_alias(root) as parent:
                original_open = MODULE.os.open
                original_fstat = MODULE.os.fstat
                opened_source_fd: int | None = None
                mutated = False

                def observe_source_open(
                    target: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal opened_source_fd
                    fd = original_open(target, flags, mode, dir_fd=dir_fd)
                    if dir_fd == parent.fd and os.fspath(target) == source.name:
                        opened_source_fd = fd
                    return fd

                def mutate_after_opened_fstat(fd: int) -> os.stat_result:
                    nonlocal mutated
                    observed = original_fstat(fd)
                    if fd == opened_source_fd and not mutated:
                        os.fchmod(fd, 0o640)
                        mutated = True
                    return observed

                with (
                    mock.patch.object(
                        MODULE.os,
                        "open",
                        side_effect=observe_source_open,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "fstat",
                        side_effect=mutate_after_opened_fstat,
                    ),
                    mock.patch.object(MODULE, "_hash_fd") as hash_fd,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._bind_regular_file_at(
                        source,
                        parent,
                        MODULE.SOURCE_FILE_CODES,
                    ):
                        self.fail(
                            "source path policy drift after opened fstat was accepted"
                        )

            self._assert_safety_code("source-access-policy-mismatch", raised)
            self.assertTrue(mutated)
            hash_fd.assert_not_called()
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o640)
            self.assertIsNotNone(opened_source_fd)
            assert opened_source_fd is not None
            with self.assertRaises(OSError) as closed:
                os.fstat(opened_source_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_bound_source_file_rejects_protected_flag_drift_across_open_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            protected_flag = MODULE._DARWIN_ACCESS_POLICY_FLAG_BITS["UF_IMMUTABLE"]

            with MODULE._bind_existing_directory_with_trusted_alias(root) as parent:
                original_open = MODULE.os.open
                original_fstat = MODULE.os.fstat
                original_stat = MODULE.os.stat
                opened_source_fd: int | None = None

                def mutate_flags_during_source_open(
                    target: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal opened_source_fd
                    fd = original_open(target, flags, mode, dir_fd=dir_fd)
                    if dir_fd == parent.fd and os.fspath(target) == source.name:
                        opened_source_fd = fd
                    return fd

                def source_fstat_with_drift(fd: int) -> os.stat_result:
                    observed = original_fstat(fd)
                    if fd == opened_source_fd:
                        return _StatWithFlags(observed, protected_flag)
                    return observed

                def source_stat_with_drift(
                    target: object,
                    *args: object,
                    **kwargs: object,
                ) -> os.stat_result:
                    observed = original_stat(target, *args, **kwargs)
                    if (
                        opened_source_fd is not None
                        and kwargs.get("dir_fd") == parent.fd
                        and os.fspath(target) == source.name
                    ):
                        return _StatWithFlags(observed, protected_flag)
                    return observed

                with (
                    mock.patch.object(
                        MODULE.os,
                        "open",
                        side_effect=mutate_flags_during_source_open,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "fstat",
                        side_effect=source_fstat_with_drift,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "stat",
                        side_effect=source_stat_with_drift,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._bind_regular_file_at(
                        source,
                        parent,
                        MODULE.SOURCE_FILE_CODES,
                    ):
                        self.fail(
                            "source protected-flag drift across open was accepted"
                        )

            self._assert_safety_code("source-access-policy-mismatch", raised)
            self.assertIsNotNone(opened_source_fd)
            assert opened_source_fd is not None
            with self.assertRaises(OSError) as closed:
                os.fstat(opened_source_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_source_directory_revalidation_uses_wrapped_os_error_causes(
        self,
    ) -> None:
        cases = (
            (
                FileNotFoundError(MODULE.errno.ENOENT, "simulated parent missing"),
                "prepared-directory-identity-mismatch",
                "source-missing-after-read",
            ),
            (
                PermissionError(
                    MODULE.errno.EACCES,
                    "simulated parent unreadable",
                ),
                "prepared-directory-revalidation-inconclusive",
                "source-revalidation-unreadable",
            ),
            (
                OSError(MODULE.errno.EIO, "simulated parent revalidation EIO"),
                "prepared-directory-revalidation-inconclusive",
                "source-revalidation-inconclusive",
            ),
        )
        for fault, wrapped_code, expected_code in cases:
            with (
                self.subTest(expected_code=expected_code),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                fd = os.open(root, MODULE._directory_open_flags())
                try:
                    opened = os.fstat(fd)
                    binding = MODULE._BoundDirectory(
                        path=root,
                        fd=fd,
                        opened=opened,
                        parent_opened=opened,
                    )
                    with (
                        mock.patch.object(MODULE.os, "stat", side_effect=fault),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._verify_bound_source_directory(binding)
                finally:
                    os.close(fd)

                self._assert_safety_code(expected_code, raised)
                wrapped = raised.exception.__cause__
                self.assertIsInstance(wrapped, MODULE.StoreSafetyError)
                assert isinstance(wrapped, MODULE.StoreSafetyError)
                self.assertEqual(wrapped.code, wrapped_code)
                self.assertIs(wrapped.__cause__, fault)

    def test_source_directory_identity_mismatch_requires_stat_comparison(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            replacement = root / "replacement"
            replacement.mkdir()
            fd = os.open(root, MODULE._directory_open_flags())
            try:
                opened = os.fstat(fd)
                binding = MODULE._BoundDirectory(
                    path=root,
                    fd=fd,
                    opened=opened,
                    parent_opened=opened,
                )
                replacement_stat = replacement.stat()
                with (
                    mock.patch.object(
                        MODULE.os,
                        "stat",
                        return_value=replacement_stat,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._verify_bound_source_directory(binding)
            finally:
                os.close(fd)

        self._assert_safety_code("source-identity-mismatch", raised)
        wrapped = raised.exception.__cause__
        self.assertIsInstance(wrapped, MODULE.StoreSafetyError)
        assert isinstance(wrapped, MODULE.StoreSafetyError)
        self.assertEqual(wrapped.code, "prepared-directory-identity-mismatch")
        self.assertIsNone(wrapped.__cause__)

    def test_probe_records_post_close_parent_revalidation_per_file(self) -> None:
        cases = (
            (
                FileNotFoundError(MODULE.errno.ENOENT, "simulated parent missing"),
                "source-missing-after-read",
            ),
            (
                PermissionError(
                    MODULE.errno.EACCES,
                    "simulated parent unreadable",
                ),
                "source-revalidation-unreadable",
            ),
            (
                OSError(MODULE.errno.EIO, "simulated parent revalidation EIO"),
                "source-revalidation-inconclusive",
            ),
        )
        for fault, expected_code in cases:
            with (
                self.subTest(expected_code=expected_code),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                original_open_source = MODULE._open_regular_readonly_at
                original_verify_source = MODULE._verify_bound_source_directory
                opened_source_fd: int | None = None
                source_revalidations = 0

                def capture_opened_source(
                    parent: MODULE._BoundDirectory,
                    basename: str,
                    *,
                    display_path: Path,
                ) -> tuple[int, os.stat_result]:
                    nonlocal opened_source_fd
                    fd, opened = original_open_source(
                        parent,
                        basename,
                        display_path=display_path,
                    )
                    if display_path == source:
                        opened_source_fd = fd
                    return fd, opened

                def fail_terminal_parent_revalidation(
                    directory: MODULE._BoundDirectory,
                ) -> dict[str, object]:
                    nonlocal source_revalidations
                    if directory.path == paths.group_container:
                        source_revalidations += 1
                        if source_revalidations == 3:
                            self.assertIsNotNone(opened_source_fd)
                            assert opened_source_fd is not None
                            with self.assertRaises(OSError) as closed:
                                os.fstat(opened_source_fd)
                            self.assertEqual(closed.exception.errno, errno.EBADF)
                            with mock.patch.object(
                                MODULE.os,
                                "stat",
                                side_effect=fault,
                            ):
                                return original_verify_source(directory)
                    return original_verify_source(directory)

                with (
                    mock.patch.object(
                        MODULE,
                        "_open_regular_readonly_at",
                        side_effect=capture_opened_source,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_verify_bound_source_directory",
                        side_effect=fail_terminal_parent_revalidation,
                    ),
                ):
                    result = MODULE.probe_db_access(paths)

                self.assertGreaterEqual(source_revalidations, 3)
                source_record = next(
                    record
                    for record in result["note_store_files"]
                    if Path(record["path"]) == source
                )
                self.assertTrue(source_record["exists"])
                self.assertFalse(source_record["readable"])
                self.assertEqual(source_record["error_code"], expected_code)
                self.assertNotIn("size", source_record)
                self.assertFalse(
                    source_record["error_code"].startswith("prepared-directory-")
                )

    def test_source_final_revalidation_maps_generic_os_errors(self) -> None:
        for syscall in ("fstat", "stat"):
            with (
                self.subTest(syscall=syscall),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                original_revalidate = MODULE._revalidate_open_source
                original_syscall = getattr(MODULE.os, syscall)
                after_primary_revalidation = False

                def mark_primary_revalidation(
                    opened: MODULE._OpenedSource,
                    second_sha256: str,
                ) -> dict[str, object]:
                    nonlocal after_primary_revalidation
                    result = original_revalidate(opened, second_sha256)
                    after_primary_revalidation = True
                    return result

                def fail_final_revalidation(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    if after_primary_revalidation:
                        if syscall == "fstat" or (
                            Path(os.fspath(args[0])).name == source.name
                            and kwargs.get("dir_fd") is not None
                        ):
                            raise OSError(
                                MODULE.errno.EIO,
                                "simulated final revalidation EIO",
                            )
                    return original_syscall(*args, **kwargs)

                with (
                    mock.patch.object(
                        MODULE,
                        "_revalidate_open_source",
                        side_effect=mark_primary_revalidation,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        syscall,
                        side_effect=fail_final_revalidation,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.fingerprint_note_store(paths)

                self._assert_safety_code(
                    "source-revalidation-inconclusive",
                    raised,
                )

    def test_source_binding_permission_errors_propagate_across_commands(
        self,
    ) -> None:
        for operation in ("fingerprint", "copy", "merge"):
            for binding_stage in (
                "post-discovery-stat",
                "pre-open-stat",
                "open",
            ):
                for error_number in (MODULE.errno.EACCES, MODULE.errno.EPERM):
                    with (
                        self.subTest(
                            operation=operation,
                            binding_stage=binding_stage,
                            error_number=error_number,
                        ),
                        tempfile.TemporaryDirectory() as temp_dir,
                    ):
                        root = Path(temp_dir)
                        paths = self._make_paths(root)
                        source = paths.group_container / MODULE.NOTE_STORE_MAIN
                        self._create_db(source)
                        destination = root / (
                            "snapshot" if operation == "copy" else "merged.sqlite"
                        )
                        fault = PermissionError(
                            error_number,
                            f"simulated {binding_stage} permission failure",
                        )
                        original_discovery = MODULE._discover_database_files_at
                        original_bind_regular = MODULE._bind_regular_file_at
                        original_stat = MODULE.os.stat
                        original_open = MODULE.os.open
                        initial_discovery_complete = False
                        fault_injected = False

                        def mark_initial_discovery(
                            main_path: Path,
                            parent: MODULE._BoundDirectory,
                        ) -> list[Path]:
                            nonlocal initial_discovery_complete
                            result = original_discovery(main_path, parent)
                            if MODULE._absolute_path(main_path) == source:
                                initial_discovery_complete = True
                            return result

                        def fail_post_discovery_stat(
                            target: object,
                            *args: object,
                            **kwargs: object,
                        ) -> os.stat_result:
                            nonlocal fault_injected
                            if (
                                binding_stage == "post-discovery-stat"
                                and initial_discovery_complete
                                and not fault_injected
                                and kwargs.get("dir_fd") is not None
                                and os.fspath(target) == source.name
                            ):
                                fault_injected = True
                                raise fault
                            return original_stat(target, *args, **kwargs)

                        @contextmanager
                        def inject_bound_source_failure(
                            path: Path,
                            parent: MODULE._BoundDirectory,
                            codes: MODULE._FileProtectionCodes,
                        ) -> Iterator[MODULE._BoundRegularFile]:
                            nonlocal fault_injected
                            if (
                                MODULE._absolute_path(path) != source
                                or codes is not MODULE.SOURCE_FILE_CODES
                            ):
                                with original_bind_regular(
                                    path,
                                    parent,
                                    codes,
                                ) as bound:
                                    yield bound
                                return

                            def fail_bound_stat(
                                target: object,
                                *args: object,
                                **kwargs: object,
                            ) -> os.stat_result:
                                nonlocal fault_injected
                                if (
                                    binding_stage == "pre-open-stat"
                                    and not fault_injected
                                    and kwargs.get("dir_fd") == parent.fd
                                    and os.fspath(target) == path.name
                                ):
                                    fault_injected = True
                                    raise fault
                                return original_stat(target, *args, **kwargs)

                            def fail_bound_open(
                                target: object,
                                flags: int,
                                mode: int = 0o777,
                                *,
                                dir_fd: int | None = None,
                            ) -> int:
                                nonlocal fault_injected
                                if (
                                    binding_stage == "open"
                                    and not fault_injected
                                    and dir_fd == parent.fd
                                    and os.fspath(target) == path.name
                                ):
                                    fault_injected = True
                                    raise fault
                                if dir_fd is None:
                                    return original_open(target, flags, mode)
                                return original_open(
                                    target,
                                    flags,
                                    mode,
                                    dir_fd=dir_fd,
                                )

                            with (
                                mock.patch.object(
                                    MODULE.os,
                                    "stat",
                                    side_effect=fail_bound_stat,
                                ),
                                mock.patch.object(
                                    MODULE.os,
                                    "open",
                                    side_effect=fail_bound_open,
                                ),
                            ):
                                with original_bind_regular(
                                    path,
                                    parent,
                                    codes,
                                ) as bound:
                                    yield bound

                        with (
                            mock.patch.object(
                                MODULE,
                                "_discover_database_files_at",
                                side_effect=mark_initial_discovery,
                            ),
                            mock.patch.object(
                                MODULE.os,
                                "stat",
                                side_effect=fail_post_discovery_stat,
                            ),
                            mock.patch.object(
                                MODULE,
                                "_bind_regular_file_at",
                                inject_bound_source_failure,
                            ),
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            if operation == "fingerprint":
                                MODULE.fingerprint_note_store(paths)
                            elif operation == "copy":
                                MODULE.copy_db(
                                    paths,
                                    dest=destination,
                                    require_notes_quit=False,
                                    _notes_running=False,
                                )
                            else:
                                MODULE.merge_db(
                                    source,
                                    destination,
                                    paths=paths,
                                )

                        self.assertTrue(fault_injected)
                        self._assert_safety_code(
                            "source-revalidation-unreadable",
                            raised,
                        )
                        if operation != "fingerprint":
                            self.assertFalse(destination.exists())

    def test_source_directory_final_window_uses_source_taxonomy_across_commands(
        self,
    ) -> None:
        fault_profiles = (
            (
                "missing",
                "prepared-directory-identity-mismatch",
                FileNotFoundError(
                    MODULE.errno.ENOENT,
                    "simulated final-window missing directory",
                ),
                "source-missing-after-read",
            ),
            (
                "unreadable",
                "prepared-directory-revalidation-inconclusive",
                PermissionError(
                    MODULE.errno.EACCES,
                    "simulated final-window unreadable directory",
                ),
                "source-revalidation-unreadable",
            ),
            (
                "stat-inconclusive",
                "prepared-directory-revalidation-inconclusive",
                OSError(
                    MODULE.errno.EIO,
                    "simulated final-window directory stat failure",
                ),
                "source-revalidation-inconclusive",
            ),
            (
                "replacement",
                "prepared-directory-identity-mismatch",
                None,
                "source-identity-mismatch",
            ),
            (
                "access-policy",
                "prepared-directory-access-policy-mismatch",
                None,
                "source-access-policy-mismatch",
            ),
        )
        for operation in ("fingerprint", "copy", "merge"):
            for (
                fault_name,
                generic_code,
                causal_error,
                expected_code,
            ) in fault_profiles:
                with (
                    self.subTest(operation=operation, fault=fault_name),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    live_root = root / "live"
                    live_root.mkdir()
                    paths = self._make_paths(live_root)
                    source = paths.group_container / MODULE.NOTE_STORE_MAIN
                    self._create_db(source, value=f"{operation}-{fault_name}")
                    original_source_store = MODULE._bind_source_store
                    original_directory_bind = (
                        MODULE._bind_existing_directory_with_trusted_alias
                    )
                    source_transaction_active = False
                    fault_injected = False

                    @contextmanager
                    def mark_source_transaction(
                        main_path: Path,
                    ) -> Iterator[MODULE._BoundSourceStore]:
                        nonlocal source_transaction_active
                        source_transaction_active = True
                        try:
                            with original_source_store(main_path) as store:
                                yield store
                        finally:
                            source_transaction_active = False

                    @contextmanager
                    def fail_generic_final_window(
                        path: Path,
                        *,
                        trusted_alias: MODULE._TrustedDirectoryAlias | None = None,
                    ) -> Iterator[MODULE._BoundDirectory]:
                        nonlocal fault_injected
                        with original_directory_bind(
                            path,
                            trusted_alias=trusted_alias,
                        ) as binding:
                            yield binding
                            if (
                                source_transaction_active
                                and not fault_injected
                                and MODULE._absolute_path(path) == source.parent
                            ):
                                fault_injected = True
                                if causal_error is None:
                                    raise MODULE.StoreSafetyError(
                                        generic_code,
                                        "simulated generic source-directory "
                                        "context teardown mismatch",
                                    )
                                try:
                                    raise causal_error
                                except OSError as cause:
                                    raise MODULE.StoreSafetyError(
                                        generic_code,
                                        "simulated generic source-directory "
                                        "context teardown syscall failure",
                                    ) from cause

                    destination = root / (
                        "snapshot" if operation == "copy" else "merged.sqlite"
                    )
                    with (
                        mock.patch.object(
                            MODULE,
                            "_bind_source_store",
                            side_effect=mark_source_transaction,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_bind_existing_directory_with_trusted_alias",
                            side_effect=fail_generic_final_window,
                        ),
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        if operation == "fingerprint":
                            MODULE.fingerprint_note_store(paths)
                        elif operation == "copy":
                            MODULE.copy_db(
                                paths,
                                dest=destination,
                                require_notes_quit=True,
                            )
                        else:
                            MODULE.merge_db(
                                source,
                                destination,
                                paths=paths,
                            )

                    self.assertTrue(fault_injected)
                    if operation == "merge":
                        self._assert_safety_code(
                            "destination-install-uncertain",
                            raised,
                        )
                        self.assertEqual(
                            raised.exception.details["post_publication_error_code"],
                            expected_code,
                        )
                        self.assertTrue(destination.is_file())
                    else:
                        self._assert_safety_code(expected_code, raised)
                        self.assertFalse(destination.exists())
                    cause = raised.exception
                    while (
                        isinstance(cause, MODULE.StoreSafetyError)
                        and cause.code != expected_code
                        and cause.__cause__ is not None
                    ):
                        cause = cause.__cause__
                    self.assertIsInstance(cause, MODULE.StoreSafetyError)
                    assert isinstance(cause, MODULE.StoreSafetyError)
                    self.assertEqual(cause.code, expected_code)
                    self.assertFalse(cause.code.startswith("prepared-directory-"))

    def test_source_store_terminal_scan_rejects_sidecars_from_final_hash(
        self,
    ) -> None:
        cases = (
            (f"{MODULE.NOTE_STORE_MAIN}-wal", "store-file-set-mismatch"),
            (MODULE.NOTE_STORE_ROLLBACK_JOURNAL, "rollback-journal-present"),
        )
        for sidecar_name, expected_code in cases:
            with (
                self.subTest(sidecar_name=sidecar_name),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                sidecar = paths.group_container / sidecar_name
                self._create_db(source)
                original_hash = MODULE._hash_fd
                hash_calls = 0
                injected = False

                def inject_sidecar_after_final_hash(fd: int) -> str:
                    nonlocal hash_calls, injected
                    digest = original_hash(fd)
                    hash_calls += 1
                    if hash_calls == 2:
                        sidecar.write_bytes(b"persistent late sidecar")
                        injected = True
                    return digest

                with self._bind_direct_main_only_source_store(source) as store:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_hash_fd",
                            side_effect=inject_sidecar_after_final_hash,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._verify_bound_source_store(store)

                self.assertTrue(injected)
                self.assertEqual(hash_calls, 2)
                self.assertTrue(sidecar.exists())
                self._assert_safety_code(expected_code, raised)

    def test_source_store_terminal_scan_rejects_parent_replaced_during_final_hash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="bound")
            parked = root / "group-bound"
            replacement = root / "group-replacement"
            replacement.mkdir(mode=0o700)
            self._create_db(
                replacement / MODULE.NOTE_STORE_MAIN,
                value="replacement",
            )
            original_hash = MODULE._hash_fd
            hash_calls = 0
            replaced = False

            def replace_parent_after_final_hash(fd: int) -> str:
                nonlocal hash_calls, replaced
                digest = original_hash(fd)
                hash_calls += 1
                if hash_calls == 2:
                    paths.group_container.rename(parked)
                    replacement.rename(paths.group_container)
                    replaced = True
                return digest

            try:
                with self._bind_direct_main_only_source_store(source) as store:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_hash_fd",
                            side_effect=replace_parent_after_final_hash,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._verify_bound_source_store(store)
                self.assertTrue(replaced)
                self.assertEqual(hash_calls, 2)
                self._assert_safety_code("source-identity-mismatch", raised)
            finally:
                if parked.exists():
                    if paths.group_container.exists():
                        paths.group_container.rename(replacement)
                    parked.rename(paths.group_container)

    def test_source_store_terminal_scan_allows_unrelated_transient_churn(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            transient = paths.group_container / "unrelated-transient-entry"
            self._create_db(source)
            original_hash = MODULE._hash_fd
            hash_calls = 0
            churned = False

            def churn_unrelated_entry_after_final_hash(fd: int) -> str:
                nonlocal hash_calls, churned
                digest = original_hash(fd)
                hash_calls += 1
                if hash_calls == 2:
                    transient.write_bytes(b"transient")
                    transient.unlink()
                    churned = True
                return digest

            with self._bind_direct_main_only_source_store(source) as store:
                with mock.patch.object(
                    MODULE,
                    "_hash_fd",
                    side_effect=churn_unrelated_entry_after_final_hash,
                ):
                    receipt = MODULE._verify_bound_source_store(store)

            self.assertTrue(churned)
            self.assertEqual(hash_calls, 2)
            self.assertFalse(transient.exists())
            self.assertEqual(receipt["membership"], [MODULE.NOTE_STORE_MAIN])

    def test_artifact_scan_preserves_caller_directory_error_taxonomy(
        self,
    ) -> None:
        profiles = (
            (
                "snapshot",
                "snapshot-missing",
                "snapshot-directory-identity-mismatch",
                "snapshot-directory-access-policy-mismatch",
                MODULE.SNAPSHOT_FILE_CODES.inconclusive,
                "snapshot-file-set-mismatch",
            ),
            (
                "patch-stage",
                "stage-missing",
                "stage-directory-identity-mismatch",
                "stage-directory-access-policy-mismatch",
                MODULE.PATCH_FILE_CODES.inconclusive,
                "patch-file-set-mismatch",
            ),
        )
        for (
            profile,
            missing_code,
            identity_code,
            access_policy_code,
            inconclusive_code,
            mismatch_code,
        ) in profiles:
            for fault in ("identity", "access-policy", "io"):
                with (
                    self.subTest(profile=profile, fault=fault),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    artifact = root / "artifact"
                    artifact.mkdir(mode=0o700)
                    (artifact / "member").write_bytes(b"member")
                    replacement = root / "replacement"
                    replacement.mkdir(mode=0o700)
                    parent_fd = os.open(root, MODULE._directory_open_flags())
                    artifact_fd = os.open(
                        artifact.name,
                        MODULE._directory_open_flags(),
                        dir_fd=parent_fd,
                    )
                    original_mode = stat.S_IMODE(os.fstat(artifact_fd).st_mode)
                    changed_mode = 0o750 if original_mode != 0o750 else 0o700
                    binding = MODULE._BoundDirectory(
                        path=artifact,
                        fd=artifact_fd,
                        opened=os.fstat(artifact_fd),
                        parent_opened=os.fstat(parent_fd),
                        parent_fd=parent_fd,
                        namespace_basename=artifact.name,
                        canonical_path=artifact,
                    )
                    original_fstat = MODULE.os.fstat
                    original_scandir = MODULE.os.scandir
                    scan_fault_triggered = False

                    def fail_scan_fstat(fd: int) -> os.stat_result:
                        nonlocal scan_fault_triggered
                        if fd not in {parent_fd, artifact_fd}:
                            if fault == "identity":
                                scan_fault_triggered = True
                                return replacement.stat()
                            if fault == "access-policy":
                                os.fchmod(fd, changed_mode)
                                scan_fault_triggered = True
                        return original_fstat(fd)

                    def fail_scan_read(
                        target: object,
                    ) -> os.ScandirIterator[str]:
                        nonlocal scan_fault_triggered
                        if (
                            fault == "io"
                            and isinstance(target, int)
                            and target not in {parent_fd, artifact_fd}
                        ):
                            scan_fault_triggered = True
                            raise OSError(
                                MODULE.errno.EIO,
                                "simulated artifact scan EIO",
                            )
                        return original_scandir(target)

                    expected_code = {
                        "identity": identity_code,
                        "access-policy": access_policy_code,
                        "io": inconclusive_code,
                    }[fault]
                    try:
                        with (
                            mock.patch.object(
                                MODULE.os,
                                "fstat",
                                side_effect=fail_scan_fstat,
                            ),
                            mock.patch.object(
                                MODULE.os,
                                "scandir",
                                side_effect=fail_scan_read,
                            ),
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            MODULE._scan_exact_bound_directory_entries(
                                binding,
                                {"member": stat.S_IFREG},
                                missing_code=missing_code,
                                identity_code=identity_code,
                                access_policy_code=access_policy_code,
                                inconclusive_code=inconclusive_code,
                                mismatch_code=mismatch_code,
                            )
                        self.assertTrue(scan_fault_triggered)
                        self._assert_safety_code(expected_code, raised)
                    finally:
                        os.fchmod(artifact_fd, original_mode)
                        os.close(artifact_fd)
                        os.close(parent_fd)

    def test_bound_directory_scan_rejects_large_extra_sets_before_stat(
        self,
    ) -> None:
        class UnexpectedEntry:
            def __init__(self, name: str, owner: ManyUnexpectedEntries) -> None:
                self.name = name
                self._owner = owner

            def stat(self, *, follow_symlinks: bool) -> os.stat_result:
                self._owner.stat_calls += 1
                raise AssertionError("unexpected entries must be rejected before stat")

        class ManyUnexpectedEntries:
            def __init__(self, total: int) -> None:
                self.total = total
                self.yielded = 0
                self.stat_calls = 0

            def __enter__(self) -> ManyUnexpectedEntries:
                return self

            def __exit__(
                self,
                exc_type: object,
                exc: object,
                traceback: object,
            ) -> None:
                return None

            def __iter__(self) -> ManyUnexpectedEntries:
                return self

            def __next__(self) -> UnexpectedEntry:
                if self.yielded >= self.total:
                    raise StopIteration
                name = f"unexpected-{self.yielded:08d}"
                self.yielded += 1
                return UnexpectedEntry(name, self)

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            simulated = ManyUnexpectedEntries(
                MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES * 1024
            )
            with (
                MODULE._bind_existing_directory_with_trusted_alias(
                    directory
                ) as binding,
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    return_value=simulated,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._scan_bound_directory_entry_types(
                    binding,
                    {"expected-member"},
                )

        self._assert_safety_code("prepared-file-set-mismatch", raised)
        self.assertEqual(simulated.yielded, 1)
        self.assertEqual(simulated.stat_calls, 0)

    def test_bound_directory_scan_caps_entries_and_raw_name_bytes(self) -> None:
        too_many_names = {
            f"entry-{index}"
            for index in range(MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES + 1)
        }
        long_names = {f"{index:02d}-{'é' * 100}" for index in range(24)}
        self.assertLess(
            sum(len(name) for name in long_names),
            MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES,
        )
        self.assertGreater(
            sum(len(os.fsencode(name)) for name in long_names),
            MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES,
        )

        for label, names, detail_key in (
            ("entry-count", too_many_names, "entry_limit"),
            ("raw-name-bytes", long_names, "raw_name_bytes_limit"),
        ):
            with (
                self.subTest(limit=label),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                directory = Path(temp_dir)
                with (
                    MODULE._bind_existing_directory_with_trusted_alias(
                        directory
                    ) as binding,
                    mock.patch.object(
                        MODULE.os,
                        "scandir",
                        side_effect=AssertionError(
                            "oversized expected sets must fail before scanning"
                        ),
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._scan_bound_directory_entry_types(binding, names)
                self._assert_safety_code(
                    "prepared-file-set-mismatch",
                    raised,
                )
                self.assertIn(detail_key, raised.exception.details)

    def test_bound_directory_scan_preserves_raw_names_and_rejects_collisions(
        self,
    ) -> None:
        class RawEntry:
            def __init__(
                self,
                name: bytes,
                observed: os.stat_result,
            ) -> None:
                self.name = name
                self._observed = observed
                self.stat_calls = 0

            def stat(self, *, follow_symlinks: bool) -> os.stat_result:
                self.stat_calls += 1
                if follow_symlinks:
                    raise AssertionError("raw entry stat followed a symlink")
                return self._observed

        class RawScandir:
            def __init__(self, entries: list[RawEntry]) -> None:
                self._entries = entries

            def __enter__(self) -> Iterator[RawEntry]:
                return iter(self._entries)

            def __exit__(
                self,
                exc_type: object,
                exc: object,
                traceback: object,
            ) -> None:
                return None

        raw_name = b"\xff-member"
        decoded_name = os.fsdecode(raw_name)
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            member = directory / "stat-source"
            member.write_bytes(b"member")
            observed = member.stat()
            scans = [
                RawScandir([RawEntry(raw_name, observed)]),
                RawScandir([RawEntry(raw_name, observed)]),
            ]
            with (
                MODULE._bind_existing_directory_with_trusted_alias(
                    directory
                ) as binding,
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    side_effect=scans,
                ),
            ):
                entries = MODULE._scan_bound_directory_entry_types(
                    binding,
                    {decoded_name},
                )
            self.assertEqual(entries, {decoded_name: stat.S_IFREG})

            duplicate_entries = [
                RawEntry(raw_name, observed),
                RawEntry(raw_name, observed),
            ]
            with (
                MODULE._bind_existing_directory_with_trusted_alias(
                    directory
                ) as binding,
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    return_value=RawScandir(duplicate_entries),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._scan_bound_directory_entry_types(
                    binding,
                    {decoded_name},
                )
            self._assert_safety_code("prepared-file-set-mismatch", raised)
            self.assertEqual(duplicate_entries[0].stat_calls, 1)
            self.assertEqual(duplicate_entries[1].stat_calls, 0)

    def test_copy_db_does_not_use_path_reopening_validation_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_inspect_sidecars",
                    side_effect=AssertionError("path sidecar helper used"),
                ),
                mock.patch.object(
                    MODULE,
                    "validate_database_recovery",
                    side_effect=AssertionError("path recovery helper used"),
                ),
                mock.patch.object(
                    MODULE,
                    "_discover_database_files",
                    side_effect=AssertionError("path discovery helper used"),
                ),
                mock.patch.object(
                    MODULE,
                    "_open_regular_readonly",
                    side_effect=AssertionError("path source opener used"),
                ),
            ):
                result = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )

        self.assertEqual(result["sqlite_validation"]["result"], "ok")

    def test_fingerprint_binds_group_chain_once_and_opens_store_via_parent_fd(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            original_bind = MODULE._bind_existing_directory_with_trusted_alias
            original_open = MODULE.os.open
            group_binds = 0
            source_opens = 0

            @contextmanager
            def count_group_binding(path: Path) -> Iterator[MODULE._BoundDirectory]:
                nonlocal group_binds
                if MODULE._absolute_path(path) == paths.group_container:
                    group_binds += 1
                with original_bind(path) as binding:
                    yield binding

            def require_descriptor_relative_source_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal source_opens
                if os.fspath(path) in MODULE.NOTE_STORE_DISCOVERY_BASENAMES:
                    source_opens += 1
                    self.assertIsNotNone(dir_fd)
                    self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
                    self.assertTrue(flags & getattr(os, "O_NONBLOCK", 0))
                if dir_fd is None:
                    return original_open(path, flags, mode)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_bind_existing_directory_with_trusted_alias",
                    side_effect=count_group_binding,
                ),
                mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=require_descriptor_relative_source_open,
                ),
                mock.patch.object(
                    MODULE,
                    "_discover_database_files",
                    side_effect=AssertionError("path discovery helper used"),
                ),
                mock.patch.object(
                    MODULE,
                    "_open_regular_readonly",
                    side_effect=AssertionError("path source opener used"),
                ),
            ):
                result = MODULE.fingerprint_note_store(paths)

        self.assertEqual(group_binds, 1)
        self.assertEqual(source_opens, 1)
        self.assertEqual(result["files"][0]["basename"], MODULE.NOTE_STORE_MAIN)

    def test_untrusted_regular_openers_reject_fifo_swaps_before_deadline(
        self,
    ) -> None:
        for opener in ("path", "descriptor-relative", "bound-file"):
            with (
                self.subTest(opener=opener),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                leaf = root / MODULE.NOTE_STORE_MAIN
                leaf.write_bytes(b"regular-before-race")
                original_stat = MODULE.os.stat
                swapped = False

                with MODULE._bind_existing_directory_with_trusted_alias(root) as parent:

                    def swap_regular_for_fifo(
                        selected: object,
                        *args: object,
                        **kwargs: object,
                    ) -> os.stat_result:
                        nonlocal swapped
                        result = original_stat(selected, *args, **kwargs)
                        selected_path = os.fspath(selected)
                        is_target = (
                            opener == "path"
                            and kwargs.get("dir_fd") is None
                            and selected_path == os.fspath(leaf)
                        ) or (
                            opener != "path"
                            and kwargs.get("dir_fd") == parent.fd
                            and selected_path == leaf.name
                        )
                        if is_target and not swapped:
                            leaf.unlink()
                            os.mkfifo(leaf, mode=0o600)
                            swapped = True
                        return result

                    with (
                        mock.patch.object(
                            MODULE.os,
                            "stat",
                            side_effect=swap_regular_for_fifo,
                        ),
                        _fail_if_deadline_exceeded(1.0),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        if opener == "path":
                            MODULE._open_regular_readonly(leaf)
                        elif opener == "descriptor-relative":
                            MODULE._open_regular_readonly_at(
                                parent,
                                leaf.name,
                                display_path=leaf,
                            )
                        else:
                            with MODULE._bind_regular_file_at(
                                leaf,
                                parent,
                                MODULE.SOURCE_FILE_CODES,
                            ):
                                self.fail("FIFO replacement was accepted")

                self.assertTrue(swapped)
                self.assertIn(
                    raised.exception.code,
                    {"source-not-regular", "source-identity-mismatch"},
                )

    def test_untrusted_device_race_uses_nonblocking_open_before_deadline(
        self,
    ) -> None:
        device = Path("/dev/null")
        if not device.exists():
            self.skipTest("/dev/null is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            regular = Path(temp_dir) / "regular"
            regular.write_bytes(b"regular-before-device-race")
            regular_stat = regular.stat()
            original_stat = MODULE.os.stat
            original_open = MODULE.os.open
            substituted = False
            opened_device = False

            def substitute_regular_preopen_stat(
                selected: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal substituted
                if (
                    not substituted
                    and kwargs.get("dir_fd") is None
                    and os.fspath(selected) == os.fspath(device)
                ):
                    substituted = True
                    return regular_stat
                return original_stat(selected, *args, **kwargs)

            def require_nonblocking_device_open(
                selected: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal opened_device
                if dir_fd is None and os.fspath(selected) == os.fspath(device):
                    opened_device = True
                    self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
                    self.assertTrue(flags & getattr(os, "O_NONBLOCK", 0))
                if dir_fd is None:
                    return original_open(selected, flags, mode)
                return original_open(selected, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=substitute_regular_preopen_stat,
                ),
                mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=require_nonblocking_device_open,
                ),
                _fail_if_deadline_exceeded(1.0),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._open_regular_readonly(device)

        self.assertTrue(substituted)
        self.assertTrue(opened_device)
        self._assert_safety_code("source-not-regular", raised)

    def test_fingerprint_rejects_complete_source_chain_component_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source-root"
            source_root.mkdir()
            paths = self._make_paths(source_root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            parked = root / "source-root-parked"
            replacement = root / "source-root-replacement"
            replacement.mkdir()
            replacement_paths = self._make_paths(replacement)
            self._create_db(
                replacement_paths.group_container / MODULE.NOTE_STORE_MAIN,
                value="replacement",
            )
            original_capture = MODULE._capture_bound_source_store
            attacked = False

            def replace_ancestor_after_binding(
                store: MODULE._BoundSourceStore,
                *args: object,
                **kwargs: object,
            ) -> list[dict[str, object]]:
                nonlocal attacked
                if not attacked:
                    attacked = True
                    source_root.rename(parked)
                    replacement.rename(source_root)
                return original_capture(store, *args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_capture_bound_source_store",
                        side_effect=replace_ancestor_after_binding,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.fingerprint_note_store(paths)
                self.assertTrue(attacked)
                self._assert_safety_code("source-identity-mismatch", raised)
            finally:
                if parked.exists():
                    if source_root.exists():
                        source_root.rename(replacement)
                    parked.rename(source_root)

    def test_copy_db_creates_copy_through_bound_parent_during_swap_restore(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            original_copy = MODULE._copy_fd
            real_open = MODULE.os.open
            attacked = False
            replacement_entries: list[str] = []

            def copy_with_create_swap(
                fd: int,
                destination: Path,
                *,
                destination_binding: MODULE._BoundDirectory,
            ) -> dict[str, object]:
                def open_with_swap(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal attacked
                    if (
                        not attacked
                        and os.fspath(path) == destination.name
                        and dir_fd == destination_binding.fd
                        and flags & os.O_CREAT
                    ):
                        attacked = True
                        parent = destination_binding.path
                        parked = parent.with_name(f"{parent.name}.parked")
                        parent.rename(parked)
                        parent.mkdir(mode=0o700)
                        try:
                            opened_fd = real_open(
                                path,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )
                            replacement_entries.extend(
                                child.name for child in parent.iterdir()
                            )
                            return opened_fd
                        finally:
                            shutil.rmtree(parent)
                            parked.rename(parent)
                    return real_open(
                        path,
                        flags,
                        mode,
                        dir_fd=dir_fd,
                    )

                with mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=open_with_swap,
                ):
                    return original_copy(
                        fd,
                        destination,
                        destination_binding=destination_binding,
                    )

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_copy_fd",
                    side_effect=copy_with_create_swap,
                ),
            ):
                result = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )

            self.assertTrue(attacked)
            self.assertEqual(replacement_entries, [])
            self.assertEqual(
                self._validate_snapshot(Path(result["dest"]))["sqlite_validation"][
                    "result"
                ],
                "ok",
            )

    def test_failed_copy_never_unlinks_name_after_stale_identity_observation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.sqlite"
            source.write_bytes(b"source-payload")
            destination_dir = root / "destination"
            destination = destination_dir / MODULE.NOTE_STORE_MAIN
            retained_name = "retained-created.sqlite"
            replacement_name = "replacement.sqlite"
            replacement_payload = b"non-transaction-replacement"
            real_stat = MODULE.os.stat
            swapped_after_stat = False
            unlink_called = False

            with MODULE._create_bound_directory(destination_dir) as binding:
                (destination_dir / replacement_name).write_bytes(replacement_payload)
                source_fd = os.open(source, os.O_RDONLY)

                def stat_then_replace(
                    path: object,
                    *args: object,
                    **kwargs: object,
                ) -> os.stat_result:
                    nonlocal swapped_after_stat
                    result = real_stat(path, *args, **kwargs)
                    if (
                        not swapped_after_stat
                        and os.fspath(path) == destination.name
                        and kwargs.get("dir_fd") == binding.fd
                    ):
                        swapped_after_stat = True
                        os.rename(
                            destination.name,
                            retained_name,
                            src_dir_fd=binding.fd,
                            dst_dir_fd=binding.fd,
                        )
                        os.rename(
                            replacement_name,
                            destination.name,
                            src_dir_fd=binding.fd,
                            dst_dir_fd=binding.fd,
                        )
                    return result

                def reject_unlink(*args: object, **kwargs: object) -> None:
                    nonlocal unlink_called
                    unlink_called = True
                    raise AssertionError(
                        "failure retention must never unlink a separately "
                        "observed namespace leaf"
                    )

                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_write_all",
                            side_effect=OSError(
                                MODULE.errno.EIO,
                                "simulated copy failure",
                            ),
                        ),
                        mock.patch.object(
                            MODULE.os,
                            "stat",
                            side_effect=stat_then_replace,
                        ),
                        mock.patch.object(
                            MODULE.os,
                            "unlink",
                            side_effect=reject_unlink,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._copy_fd(
                            source_fd,
                            destination,
                            destination_binding=binding,
                        )
                finally:
                    os.close(source_fd)

                self.assertTrue(swapped_after_stat)
                self.assertFalse(unlink_called)
                self.assertEqual(destination.read_bytes(), replacement_payload)
                retained = destination_dir / retained_name
                self.assertTrue(retained.is_file())
                self._assert_safety_code(
                    "prepared-file-revalidation-inconclusive",
                    raised,
                )
                self.assertEqual(
                    raised.exception.details["cleanup_state"],
                    "retained",
                )
                self.assertEqual(
                    raised.exception.details["cleanup_policy"],
                    "retain-never-stat-then-unlink",
                )
                locator = raised.exception.details["recovery_locators"][
                    "descriptor_bound_prepared_file"
                ]
                self.assertEqual(
                    locator["namespace_authority"],
                    "point-in-time-observation-only",
                )
                self.assertEqual(
                    locator["created_identity"],
                    MODULE._identity(retained.stat()),
                )
                self.assertNotEqual(
                    locator["created_identity"],
                    MODULE._identity(destination.stat()),
                )

    def test_failed_manifest_and_standalone_writers_retain_descriptor_receipts(
        self,
    ) -> None:
        for writer in ("manifest", "standalone"):
            with self.subTest(writer=writer):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    unlink_called = False

                    def reject_unlink(*args: object, **kwargs: object) -> None:
                        nonlocal unlink_called
                        unlink_called = True
                        raise AssertionError(
                            "failed writers must retain descriptor-bound files"
                        )

                    with (
                        mock.patch.object(
                            MODULE.os,
                            "unlink",
                            side_effect=reject_unlink,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        if writer == "standalone":
                            with mock.patch.object(
                                MODULE,
                                "_write_all",
                                side_effect=OSError(
                                    MODULE.errno.EIO,
                                    "simulated standalone write failure",
                                ),
                            ):
                                MODULE._write_standalone_backup_payload(
                                    b"standalone-payload",
                                    root / "output.sqlite",
                                )
                        else:
                            with MODULE._bind_existing_directory(root) as binding:
                                MODULE._write_json_atomic(
                                    root / "manifest.json",
                                    {"unsupported": object()},
                                    parent_binding=binding,
                                )

                    self.assertFalse(unlink_called)
                    self._assert_safety_code(
                        "prepared-file-revalidation-inconclusive",
                        raised,
                    )
                    self.assertEqual(
                        raised.exception.details["cleanup_state"],
                        "retained",
                    )
                    self.assertFalse(raised.exception.details["retry_safe"])
                    locator = raised.exception.details["recovery_locators"][
                        "descriptor_bound_prepared_file"
                    ]
                    self.assertTrue(
                        locator["parent_descriptor"]["matches_creation_receipt"]
                    )
                    self.assertTrue(
                        locator["file_descriptor"]["matches_created_identity"]
                    )
                    self.assertEqual(
                        locator["namespace_authority"],
                        "point-in-time-observation-only",
                    )
                    self.assertEqual(
                        locator["content_evidence"]["status"],
                        "inconclusive",
                    )
                    retained_names = [
                        basename
                        for basename, observation in locator[
                            "namespace_observations"
                        ].items()
                        if observation["status"] == "present"
                    ]
                    self.assertEqual(len(retained_names), 1)
                    self.assertTrue((root / retained_names[0]).is_file())

    def test_copy_rejects_chmod_during_write_against_creation_policy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.sqlite"
            source.write_bytes(b"creation-bound-copy")
            destination_dir = root / "destination"
            destination = destination_dir / MODULE.NOTE_STORE_MAIN
            original_write = MODULE._write_all
            attacked = False

            def write_then_chmod(fd: int, payload: bytes) -> None:
                nonlocal attacked
                original_write(fd, payload)
                if not attacked:
                    attacked = True
                    os.fchmod(fd, 0o640)

            with MODULE._create_bound_directory(destination_dir) as binding:
                source_fd = os.open(source, os.O_RDONLY)
                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "_write_all",
                            side_effect=write_then_chmod,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._copy_fd(
                            source_fd,
                            destination,
                            destination_binding=binding,
                        )
                finally:
                    os.close(source_fd)

            self.assertTrue(attacked)
            self._assert_safety_code(
                "prepared-file-access-policy-mismatch",
                raised,
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)

    def test_writers_reject_chmod_during_creation_access_binding(self) -> None:
        for writer in ("copy", "json", "standalone"):
            with (
                self.subTest(writer=writer),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                output_dir = root / "output"
                real_fchmod = MODULE.os.fchmod
                attacked = False

                def fchmod_then_attack(fd: int, mode: int) -> None:
                    nonlocal attacked
                    real_fchmod(fd, mode)
                    if not attacked and mode == 0o600:
                        attacked = True
                        real_fchmod(fd, 0o640)

                with MODULE._create_bound_directory(output_dir) as binding:
                    if writer == "copy":
                        source = root / "source.sqlite"
                        source.write_bytes(b"creation-race")
                        source_fd = os.open(source, os.O_RDONLY)
                    else:
                        source_fd = None
                    try:
                        with (
                            mock.patch.object(
                                MODULE.os,
                                "fchmod",
                                side_effect=fchmod_then_attack,
                            ),
                            mock.patch.object(MODULE, "_write_all") as write_mock,
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            if writer == "copy":
                                assert source_fd is not None
                                MODULE._copy_fd(
                                    source_fd,
                                    output_dir / MODULE.NOTE_STORE_MAIN,
                                    destination_binding=binding,
                                )
                            elif writer == "json":
                                MODULE._write_json_atomic(
                                    output_dir / "manifest.json",
                                    {"schema": "test/v1"},
                                    parent_binding=binding,
                                )
                            else:
                                MODULE._write_standalone_backup_payload(
                                    b"standalone-creation-race",
                                    output_dir / "standalone.sqlite",
                                    destination_binding=binding,
                                )
                    finally:
                        if source_fd is not None:
                            os.close(source_fd)

                self.assertTrue(attacked)
                write_mock.assert_not_called()
                self._assert_safety_code(
                    "prepared-file-access-policy-mismatch",
                    raised,
                )

    def test_standalone_writer_corrects_inherited_group_before_first_write(
        self,
    ) -> None:
        inherited_groups = [group for group in os.getgroups() if group != os.getegid()]
        if not inherited_groups:
            self.skipTest("different supplementary group is unavailable")
        inherited_group = inherited_groups[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "standalone.sqlite"
            real_open = MODULE.os.open
            real_fstat = MODULE.os.fstat
            real_fchown = MODULE.os.fchown
            real_write_all = MODULE._write_all
            output_fd: int | None = None
            inherited_group_applied = False
            corrected_group = False

            with MODULE._bind_existing_directory(root) as binding:

                def track_output_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal inherited_group_applied, output_fd
                    fd = real_open(path, flags, mode, dir_fd=dir_fd)
                    if os.fspath(path) == output.name and dir_fd == binding.fd:
                        output_fd = fd
                        real_fchown(fd, -1, inherited_group)
                        inherited_group_applied = True
                    return fd

                def record_group_correction(
                    fd: int,
                    uid: int,
                    gid: int,
                ) -> None:
                    nonlocal corrected_group
                    if fd == output_fd:
                        self.assertEqual(uid, -1)
                        self.assertEqual(gid, os.getegid())
                        corrected_group = True
                    real_fchown(fd, uid, gid)

                def verify_policy_then_write(fd: int, payload: bytes) -> None:
                    self.assertTrue(corrected_group)
                    observed = real_fstat(fd)
                    self.assertEqual(observed.st_gid, os.getegid())
                    self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
                    real_write_all(fd, payload)

                with (
                    mock.patch.object(
                        MODULE.os,
                        "open",
                        side_effect=track_output_open,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "fchown",
                        side_effect=record_group_correction,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_write_all",
                        side_effect=verify_policy_then_write,
                    ),
                ):
                    result = MODULE._write_standalone_backup_payload(
                        b"standalone-group-policy",
                        output,
                        destination_binding=binding,
                    )

            self.assertTrue(inherited_group_applied)
            self.assertTrue(corrected_group)
            self.assertEqual(result["access_policy"]["gid"], os.getegid())
            self.assertEqual(result["access_policy"]["mode"], 0o600)

    def test_standalone_writer_rejects_chmod_during_write_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "standalone.sqlite"
            original_write = MODULE._write_all
            attacked = False

            def write_then_chmod(fd: int, payload: bytes) -> None:
                nonlocal attacked
                original_write(fd, payload)
                if not attacked:
                    attacked = True
                    os.fchmod(fd, 0o640)

            with (
                mock.patch.object(
                    MODULE,
                    "_write_all",
                    side_effect=write_then_chmod,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._write_standalone_backup_payload(
                    b"standalone-write-race",
                    output,
                )

            self.assertTrue(attacked)
            self._assert_safety_code(
                "prepared-file-access-policy-mismatch",
                raised,
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    def test_json_writer_rejects_chmod_during_write_against_creation_policy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "manifest.json"
            original_write = MODULE._write_all
            attacked = False

            def write_then_chmod(fd: int, payload: bytes) -> None:
                nonlocal attacked
                original_write(fd, payload)
                if not attacked:
                    attacked = True
                    os.fchmod(fd, 0o640)

            with (
                MODULE._bind_existing_directory(root) as binding,
                mock.patch.object(
                    MODULE,
                    "_write_all",
                    side_effect=write_then_chmod,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._write_json_atomic(
                    output,
                    {"schema": "test/v1"},
                    parent_binding=binding,
                )

            self.assertTrue(attacked)
            self._assert_safety_code(
                "prepared-file-access-policy-mismatch",
                raised,
            )
            retained = list(root.glob(".manifest.json.tmp-*"))
            self.assertEqual(len(retained), 1)
            self.assertEqual(stat.S_IMODE(retained[0].stat().st_mode), 0o640)
            self.assertFalse(output.exists())

    def test_json_writer_enforces_0600_independent_of_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "result.json"
            previous_umask = os.umask(0o777)
            try:
                with MODULE._bind_existing_directory(root) as binding:
                    receipt = MODULE._write_json_atomic(
                        output,
                        {"schema": "test/v1"},
                        parent_binding=binding,
                        ensure_ascii=True,
                    )
            finally:
                os.umask(previous_umask)

            observed = os.stat(output, follow_symlinks=False)
            self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
            self.assertEqual(observed.st_uid, os.geteuid())
            self.assertEqual(observed.st_gid, os.getegid())
            self.assertEqual(receipt["access_policy"]["mode"], 0o600)

    def test_standalone_writer_rejects_same_length_valid_sqlite_race(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            expected = root / "expected.sqlite"
            competing = root / "competing.sqlite"
            output = root / "output.sqlite"
            self._create_db(expected, value="expected")
            self._create_db(competing, value="attacker")
            expected_payload = expected.read_bytes()
            competing_payload = competing.read_bytes()
            self.assertEqual(len(expected_payload), len(competing_payload))
            self.assertNotEqual(expected_payload, competing_payload)
            with closing(sqlite3.connect(competing)) as connection:
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone(),
                    ("ok",),
                )

            original_hash = MODULE._hash_fd
            attacked = False

            def replace_bytes_before_first_readback(fd: int) -> str:
                nonlocal attacked
                if not attacked:
                    attacked = True
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.ftruncate(fd, 0)
                    MODULE._write_all(fd, competing_payload)
                    os.fsync(fd)
                return original_hash(fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_hash_fd",
                    side_effect=replace_bytes_before_first_readback,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._write_standalone_backup_payload(
                    expected_payload,
                    output,
                )

            self.assertTrue(attacked)
            self._assert_safety_code("prepared-file-content-mismatch", raised)
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_size, len(expected_payload))
            with closing(sqlite3.connect(output)) as connection:
                value = connection.execute("SELECT value FROM sample").fetchone()
            self.assertEqual(value, ("attacker",))

    def test_standalone_writer_rejects_access_race_after_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.sqlite"
            output = root / "output.sqlite"
            self._create_db(source)
            payload = source.read_bytes()
            original_hash = MODULE._hash_fd
            attacked = False

            def chmod_after_hash(fd: int) -> str:
                nonlocal attacked
                digest = original_hash(fd)
                if not attacked:
                    attacked = True
                    os.fchmod(fd, 0o640)
                return digest

            with (
                mock.patch.object(
                    MODULE,
                    "_hash_fd",
                    side_effect=chmod_after_hash,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._write_standalone_backup_payload(payload, output)

            self.assertTrue(attacked)
            self._assert_safety_code(
                "prepared-file-access-policy-mismatch",
                raised,
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    def test_writeback_copy_rechecks_notes_at_end_of_before_rename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"

            with (
                mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    side_effect=[False, False, True],
                ) as notes_probe,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code("notes-started-during-capture", raised)
            self.assertEqual(notes_probe.call_count, 3)
            self.assertEqual(
                raised.exception.details["capture_phase"],
                "before-publication-rename",
            )
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertFalse(destination.exists())
            partial = self._assert_retained_partial(root, ".snapshot.partial-*")
            retained_database = (
                partial / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            )
            self.assertTrue(retained_database.is_file())
            self.assertIn(
                str(Path("group.com.apple.notes") / MODULE.NOTE_STORE_MAIN),
                {
                    row["relative_path"]
                    for row in details["sensitive_partial_inventory"]
                },
            )

    def test_writeback_copy_quarantines_snapshot_when_notes_start_after_publish(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"

            with (
                mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    side_effect=[False, False, False, True],
                ) as notes_probe,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code("notes-started-during-capture", raised)
            self.assertEqual(notes_probe.call_count, 4)
            self.assertFalse(destination.exists())
            quarantines = list(root.glob(".snapshot.notes-started-quarantine-*"))
            self.assertEqual(len(quarantines), 1)
            self.assertTrue(
                (
                    quarantines[0] / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
                ).is_file()
            )
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["publication_state"], "committed")
            self.assertEqual(
                details["artifact_publication_state"],
                "quarantined",
            )
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertFalse(details["writeback_grade"])
            self.assertFalse(details["successful_creation_receipt_emitted"])
            quarantine_receipt = details["recovery_locators"]["snapshot_quarantine"]
            self.assertEqual(
                Path(quarantine_receipt["quarantine_path"]),
                quarantines[0],
            )
            self.assertEqual(
                quarantine_receipt["artifact_publication_state"],
                "quarantined",
            )
            self.assertEqual(
                quarantine_receipt["quarantine_namespace_state"],
                "moved-verified",
            )
            self.assertEqual(
                quarantine_receipt["quarantine_verification"],
                "verified",
            )

    def test_writeback_copy_does_not_overclaim_incomplete_quarantine_proofs(
        self,
    ) -> None:
        cases = (
            (
                "directory-policy",
                "post-rename-directory-revalidation",
                True,
                "notes-started-during-capture",
            ),
            (
                "parent-durability",
                "post-rename-parent-durability",
                True,
                "notes-started-during-capture",
            ),
            (
                "tree-receipt",
                "post-rename-tree-receipt",
                True,
                "notes-started-during-capture",
            ),
            (
                "public-alias",
                "post-rename-public-alias",
                True,
                "notes-started-during-capture",
            ),
            (
                "parent-durability-conflicting-probe-details",
                "post-rename-parent-durability",
                MODULE.StoreSafetyError(
                    "notes-state-unknown",
                    "simulated final Notes process-state failure",
                    details={
                        "artifact_publication_state": "quarantined",
                        "cleanup_state": "retained",
                        "probe_phase": "simulated-conflict",
                    },
                ),
                "notes-state-unknown",
            ),
        )
        for failure, expected_phase, final_probe, expected_code in cases:
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                destination = root / "snapshot"
                quarantine_rename_returned = False
                original_rename = MODULE._rename_directory_no_replace_at
                original_verify_directory = MODULE._verify_bound_directory_at
                original_fsync_parent = MODULE._fsync_bound_parent_descriptor
                original_tree_receipt = MODULE._descriptor_bound_prepared_tree_receipt
                original_verify_alias = MODULE._verify_installed_directory_path

                def observe_quarantine_rename(
                    parent_fd: int,
                    source_name: str,
                    destination_name: str,
                ) -> None:
                    nonlocal quarantine_rename_returned
                    original_rename(parent_fd, source_name, destination_name)
                    if destination_name.startswith(
                        ".snapshot.notes-started-quarantine-"
                    ):
                        quarantine_rename_returned = True

                def fail_quarantine_directory_policy(
                    binding: MODULE._BoundDirectory,
                    *,
                    parent_fd: int,
                    basename: str,
                    display_path: Path,
                ) -> dict[str, object]:
                    if failure == "directory-policy" and basename.startswith(
                        ".snapshot.notes-started-quarantine-"
                    ):
                        raise MODULE.StoreSafetyError(
                            "prepared-directory-access-policy-mismatch",
                            "simulated quarantine directory policy drift",
                        )
                    return original_verify_directory(
                        binding,
                        parent_fd=parent_fd,
                        basename=basename,
                        display_path=display_path,
                    )

                def fail_quarantine_parent_durability(
                    parent_fd: int,
                    opened: os.stat_result,
                    *,
                    display_path: Path,
                    identity_code: str,
                    access_policy_code: str,
                    inconclusive_code: str,
                ) -> None:
                    if (
                        failure.startswith("parent-durability")
                        and quarantine_rename_returned
                    ):
                        raise MODULE.StoreSafetyError(
                            inconclusive_code,
                            "simulated quarantine parent fsync failure",
                        )
                    original_fsync_parent(
                        parent_fd,
                        opened,
                        display_path=display_path,
                        identity_code=identity_code,
                        access_policy_code=access_policy_code,
                        inconclusive_code=inconclusive_code,
                    )

                def fail_quarantine_tree_receipt(
                    *args: object,
                    **kwargs: object,
                ) -> dict[str, object]:
                    published_basename = str(kwargs["published_basename"])
                    if failure == "tree-receipt" and published_basename.startswith(
                        ".snapshot.notes-started-quarantine-"
                    ):
                        raise MODULE.StoreSafetyError(
                            "prepared-file-revalidation-inconclusive",
                            "simulated quarantine tree receipt failure",
                        )
                    return original_tree_receipt(*args, **kwargs)

                def fail_quarantine_public_alias(
                    binding: MODULE._BoundDirectory,
                    installed_path: Path,
                ) -> dict[str, object] | None:
                    if failure == "public-alias" and installed_path.name.startswith(
                        ".snapshot.notes-started-quarantine-"
                    ):
                        raise MODULE.StoreSafetyError(
                            "prepared-directory-revalidation-inconclusive",
                            "simulated quarantine public alias failure",
                        )
                    return original_verify_alias(binding, installed_path)

                with (
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        side_effect=[False, False, False, final_probe],
                    ),
                    mock.patch.object(
                        MODULE,
                        "_rename_directory_no_replace_at",
                        side_effect=observe_quarantine_rename,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_verify_bound_directory_at",
                        side_effect=fail_quarantine_directory_policy,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_fsync_bound_parent_descriptor",
                        side_effect=fail_quarantine_parent_durability,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_descriptor_bound_prepared_tree_receipt",
                        side_effect=fail_quarantine_tree_receipt,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_verify_installed_directory_path",
                        side_effect=fail_quarantine_public_alias,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    self._copy_db(
                        paths,
                        dest=destination,
                        require_notes_quit=True,
                    )

                self._assert_safety_code(expected_code, raised)
                self.assertTrue(quarantine_rename_returned)
                self.assertFalse(destination.exists())
                quarantines = list(root.glob(".snapshot.notes-started-quarantine-*"))
                self.assertEqual(len(quarantines), 1)
                details = raised.exception.details
                self.assertEqual(details["publication_state"], "committed")
                self.assertEqual(
                    details["artifact_publication_state"],
                    "namespace-moved-unverified",
                )
                self.assertEqual(details["cleanup_state"], "inconclusive")
                self.assertFalse(details["writeback_grade"])
                self.assertFalse(details["successful_creation_receipt_emitted"])
                locator = details["recovery_locators"]["snapshot_quarantine"]
                self.assertEqual(
                    locator["artifact_publication_state"],
                    "namespace-moved-unverified",
                )
                self.assertEqual(
                    locator["quarantine_namespace_state"],
                    "moved-unverified",
                )
                self.assertEqual(
                    locator["quarantine_verification"],
                    "inconclusive",
                )
                self.assertEqual(
                    locator["quarantine_failure_phase"],
                    expected_phase,
                )

    def test_writeback_copy_quarantines_snapshot_when_final_notes_probe_is_unknown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            probe_error = MODULE.StoreSafetyError(
                "notes-state-unknown",
                "simulated final Notes process-state failure",
                details={"probe_phase": "simulated"},
            )

            with (
                mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    side_effect=[False, False, False, probe_error],
                ) as notes_probe,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self.assertIs(raised.exception.__cause__, None)
            self._assert_safety_code("notes-state-unknown", raised)
            self.assertEqual(notes_probe.call_count, 4)
            self.assertFalse(destination.exists())
            quarantines = list(root.glob(".snapshot.notes-started-quarantine-*"))
            self.assertEqual(len(quarantines), 1)
            details = raised.exception.details
            self.assertEqual(details["notes_state"], "unknown")
            self.assertEqual(
                details["notes_probe_error_code"],
                "notes-state-unknown",
            )
            self.assertEqual(details["probe_phase"], "simulated")
            self.assertEqual(
                details["artifact_publication_state"],
                "quarantined",
            )
            self.assertFalse(details["writeback_grade"])
            self.assertFalse(details["successful_creation_receipt_emitted"])

    def test_copy_failure_merges_file_and_partial_tree_recovery_locators(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_write_all",
                    side_effect=OSError(
                        MODULE.errno.EIO,
                        "simulated snapshot copy failure",
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code(
                "prepared-file-revalidation-inconclusive",
                raised,
            )
            locators = raised.exception.details["recovery_locators"]
            self.assertIn("descriptor_bound_prepared_file", locators)
            self.assertIn("prepared_namespace", locators)
            partial = Path(locators["prepared_namespace"])
            self.assertTrue(partial.is_dir())
            self.assertTrue(
                (partial / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN).is_file()
            )
            self.assertFalse(destination.exists())

    def test_copy_db_blocks_copied_main_swap_during_bound_validation(self) -> None:
        for hook_name in ("_inspect_bound_sidecars", "_bound_recovery_integrity"):
            with self.subTest(hook=hook_name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                    destination = root / "snapshot"
                    replacement = root / f"{hook_name}-replacement.sqlite"
                    self._create_db(replacement, value="replacement")
                    original_hook = getattr(MODULE, hook_name)
                    attacked = False

                    def swap_around_bound_validation(
                        store: MODULE._BoundRecoveryStore,
                    ) -> dict[str, object]:
                        nonlocal attacked
                        attacked = True
                        copied = store.directory.path / store.main_name
                        parked = copied.with_name(f"{copied.name}.captured")
                        os.replace(copied, parked)
                        os.replace(replacement, copied)
                        try:
                            return original_hook(store)
                        finally:
                            os.replace(copied, replacement)
                            os.replace(parked, copied)

                    with (
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        mock.patch.object(
                            MODULE,
                            hook_name,
                            side_effect=swap_around_bound_validation,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        self._copy_db(
                            paths,
                            dest=destination,
                            require_notes_quit=True,
                        )

                    self.assertTrue(attacked)
                    self._assert_safety_code(
                        "prepared-file-identity-mismatch",
                        raised,
                    )
                    self.assertFalse(destination.exists())
                    self._assert_retained_partial(root, ".snapshot.partial-*")

    def test_snapshot_fsyncs_nested_store_then_root_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            events: list[str] = []
            original_fsync = MODULE._fsync_bound_directory_descriptor
            original_rename = MODULE._rename_directory_no_replace_at

            def record_fsync(binding: object, **kwargs: object) -> None:
                events.append(f"fsync:{Path(binding.path).name}")
                original_fsync(binding, **kwargs)

            def record_rename(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                events.append("publish")
                original_rename(parent_fd, source_name, target_name)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_directory_descriptor",
                    side_effect=record_fsync,
                ),
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=record_rename,
                ),
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

        self.assertEqual(len(events), 4)
        self.assertTrue(events[0].startswith("fsync:.snapshot.partial-"))
        self.assertEqual(events[1], "fsync:group.com.apple.notes")
        self.assertTrue(events[2].startswith("fsync:.snapshot.partial-"))
        self.assertEqual(events[3], "publish")

    def test_snapshot_nested_store_fsync_failure_retains_unpublished_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_fsync = MODULE._fsync_bound_directory_descriptor

            def fail_store_fsync(binding: object, **kwargs: object) -> None:
                if Path(binding.path).name == "group.com.apple.notes":
                    raise MODULE.StoreSafetyError(
                        "prepared-directory-revalidation-inconclusive",
                        "simulated nested store fsync failure",
                    )
                original_fsync(binding, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_directory_descriptor",
                    side_effect=fail_store_fsync,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self._assert_safety_code(
                "prepared-directory-revalidation-inconclusive",
                raised,
            )
            self.assertFalse(destination.exists())
            retained = self._assert_retained_partial(root, ".snapshot.partial-*")
            self.assertTrue(
                (retained / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN).is_file()
            )

    def test_snapshot_revalidates_store_after_root_fsync(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_fsync = MODULE._fsync_bound_directory_descriptor
            attacked = False

            def mutate_after_root_fsync(binding: object, **kwargs: object) -> None:
                nonlocal attacked
                original_fsync(binding, **kwargs)
                if not attacked and Path(binding.path).name.startswith(
                    ".snapshot.partial-"
                ):
                    attacked = True
                    copied = (
                        Path(binding.path)
                        / "group.com.apple.notes"
                        / MODULE.NOTE_STORE_MAIN
                    )
                    with copied.open("ab") as handle:
                        handle.write(b"tampered-after-root-fsync")
                        handle.flush()
                        os.fsync(handle.fileno())

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_directory_descriptor",
                    side_effect=mutate_after_root_fsync,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=True,
                )

            self.assertTrue(attacked)
            self._assert_safety_code("prepared-file-content-mismatch", raised)
            self.assertFalse(destination.exists())
            self._assert_retained_partial(root, ".snapshot.partial-*")

    def test_copy_db_rejects_open_notes_for_writeback_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=True):
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._copy_db(
                        paths, dest=root / "snapshot", require_notes_quit=True
                    )
        self._assert_safety_code("notes-running", raised)

    def test_hot_delete_and_persist_journals_fail_closed_before_capture(
        self,
    ) -> None:
        for journal_mode in ("DELETE", "PERSIST"):
            with self.subTest(journal_mode=journal_mode):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    database = root / MODULE.NOTE_STORE_MAIN
                    with closing(sqlite3.connect(database)) as connection:
                        connection.execute("PRAGMA page_size = 1024")
                        connection.execute(
                            """
                            CREATE TABLE evidence(
                                id INTEGER PRIMARY KEY,
                                state TEXT NOT NULL,
                                payload TEXT NOT NULL
                            )
                            """
                        )
                        connection.executemany(
                            """
                            INSERT INTO evidence(state, payload)
                            VALUES ('committed', ?)
                            """,
                            [
                                (f"committed-{index:06d}-" + "x" * 880,)
                                for index in range(400)
                            ],
                        )
                        connection.commit()

                    crashed_writer = subprocess.run(
                        [
                            sys.executable,
                            "-B",
                            str(HOT_JOURNAL_FIXTURE),
                            str(database),
                            journal_mode,
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        crashed_writer.returncode,
                        0,
                        msg=crashed_writer.stderr,
                    )
                    journal = database.with_name(f"{database.name}-journal")
                    self.assertTrue(journal.is_file())
                    self.assertGreater(journal.stat().st_size, 512)
                    self.assertNotEqual(journal.read_bytes()[:8], b"\0" * 8)

                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        MODULE._capture_database_files(database)
                    self._assert_safety_code("rollback-journal-present", raised)
                    self.assertEqual(
                        raised.exception.details["binding_status"],
                        "stable",
                    )
                    self.assertEqual(
                        Path(raised.exception.details["journal"]),
                        journal,
                    )

                    main_without_journal = root / "main-without-journal.sqlite"
                    shutil.copy2(database, main_without_journal)
                    exposed_uncommitted_or_partial = False
                    try:
                        with closing(
                            sqlite3.connect(main_without_journal)
                        ) as ignored_connection:
                            integrity = ignored_connection.execute(
                                "PRAGMA integrity_check"
                            ).fetchone()
                            uncommitted = ignored_connection.execute(
                                """
                                SELECT count(*)
                                FROM evidence
                                WHERE state = 'uncommitted'
                                """
                            ).fetchone()
                        exposed_uncommitted_or_partial = (
                            integrity is None
                            or integrity[0] != "ok"
                            or uncommitted is None
                            or uncommitted[0] > 0
                        )
                    except sqlite3.DatabaseError:
                        exposed_uncommitted_or_partial = True
                    self.assertTrue(exposed_uncommitted_or_partial)

                    with closing(sqlite3.connect(database)) as recovered:
                        states = recovered.execute(
                            """
                            SELECT state, count(*)
                            FROM evidence
                            GROUP BY state
                            """
                        ).fetchall()
                        integrity = recovered.execute(
                            "PRAGMA integrity_check"
                        ).fetchone()
                    self.assertEqual(states, [("committed", 400)])
                    self.assertEqual(integrity, ("ok",))

    def test_rollback_journal_symlink_is_detected_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            target = root / "attacker-controlled-journal"
            target.write_bytes(b"not a journal")
            journal = database.with_name(f"{database.name}-journal")
            journal.symlink_to(target.name)
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE._capture_database_files(database)
        self._assert_safety_code("rollback-journal-present", raised)
        self.assertEqual(raised.exception.details["binding_status"], "inconclusive")
        self.assertEqual(
            raised.exception.details["reason_code"],
            "source-not-regular",
        )

    def test_rollback_journal_appearing_during_binding_has_stable_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            journal = database.with_name(f"{database.name}-journal")
            original_discovery = MODULE._discover_database_files_at
            discovery_count = 0

            def journal_appears(
                main_path: Path,
                parent: MODULE._BoundDirectory,
            ) -> list[Path]:
                nonlocal discovery_count
                discovery_count += 1
                if discovery_count == 2:
                    journal.write_bytes(b"appeared-during-binding")
                return original_discovery(main_path, parent)

            with (
                mock.patch.object(
                    MODULE,
                    "_discover_database_files_at",
                    side_effect=journal_appears,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._capture_database_files(database)
        self._assert_safety_code("rollback-journal-present", raised)
        self.assertEqual(raised.exception.details["binding_status"], "inconclusive")
        self.assertEqual(
            raised.exception.details["reason_code"],
            "journal-membership-changed",
        )
        self.assertEqual(raised.exception.details["phase"], "after-open")

    def test_rollback_journal_binding_permission_errors_keep_source_reason(
        self,
    ) -> None:
        for error_number in (MODULE.errno.EACCES, MODULE.errno.EPERM):
            with (
                self.subTest(error_number=error_number),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                database = root / MODULE.NOTE_STORE_MAIN
                journal = database.with_name(f"{database.name}-journal")
                self._create_db(database)
                journal.write_bytes(b"simulated rollback journal")
                original_discovery = MODULE._discover_database_files_at
                original_stat = MODULE.os.stat
                initial_discovery_complete = False
                fault_injected = False
                fault = PermissionError(
                    error_number,
                    "simulated journal revalidation permission failure",
                )

                def mark_initial_discovery(
                    main_path: Path,
                    parent: MODULE._BoundDirectory,
                ) -> list[Path]:
                    nonlocal initial_discovery_complete
                    result = original_discovery(main_path, parent)
                    initial_discovery_complete = True
                    return result

                def fail_journal_revalidation(
                    target: object,
                    *args: object,
                    **kwargs: object,
                ) -> os.stat_result:
                    nonlocal fault_injected
                    if (
                        initial_discovery_complete
                        and not fault_injected
                        and kwargs.get("dir_fd") is not None
                        and os.fspath(target) == journal.name
                    ):
                        fault_injected = True
                        raise fault
                    return original_stat(target, *args, **kwargs)

                with (
                    mock.patch.object(
                        MODULE,
                        "_discover_database_files_at",
                        side_effect=mark_initial_discovery,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "stat",
                        side_effect=fail_journal_revalidation,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._capture_database_files(database)

            self.assertTrue(fault_injected)
            self._assert_safety_code("rollback-journal-present", raised)
            self.assertEqual(
                raised.exception.details["binding_status"],
                "inconclusive",
            )
            self.assertEqual(
                raised.exception.details["reason_code"],
                "source-revalidation-unreadable",
            )

    def test_outputs_never_overwrite_existing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live)
            snapshot_dest = root / "snapshot"
            snapshot_dest.mkdir()
            sentinel = snapshot_dest / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                with self.assertRaises(MODULE.StoreSafetyError) as copy_raised:
                    self._copy_db(
                        paths,
                        dest=snapshot_dest,
                        require_notes_quit=False,
                    )
            self._assert_safety_code("destination-exists", copy_raised)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

            recovered = root / "recovered.sqlite"
            recovered.write_text("keep", encoding="utf-8")
            with self.assertRaises(MODULE.StoreSafetyError) as recover_raised:
                MODULE.merge_db(live, recovered)
            self._assert_safety_code("destination-exists", recover_raised)
            self.assertEqual(recovered.read_text(encoding="utf-8"), "keep")

    def test_snapshot_publication_does_not_replace_directory_appearing_after_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_rename = MODULE._rename_directory_no_replace_at

            def destination_appears(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                os.mkdir(target_name, dir_fd=parent_fd)
                original_rename(parent_fd, source_name, target_name)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=destination_appears,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self._assert_safety_code("destination-exists", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertEqual(list(destination.iterdir()), [])
            partial = self._assert_retained_partial(root, ".snapshot.partial-*")
            self.assertEqual(raised.exception.details["cleanup_state"], "retained")
            locators = raised.exception.details["recovery_locators"]
            self.assertEqual(Path(locators["prepared_namespace"]), partial)
            self.assertEqual(
                locators["namespace_verification"],
                "creation-receipt-matched",
            )
            inventory = {
                row["relative_path"]
                for row in raised.exception.details["sensitive_partial_inventory"]
            }
            self.assertIn("snapshot-manifest.json", inventory)
            self.assertIn("group.com.apple.notes/NoteStore.sqlite", inventory)

    def test_patch_publication_does_not_replace_directory_appearing_after_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_rename = MODULE._rename_directory_no_replace_at

            def destination_appears(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                os.mkdir(target_name, dir_fd=parent_fd)
                original_rename(parent_fd, source_name, target_name)

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=destination_appears,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("destination-exists", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertEqual(list(destination.iterdir()), [])
            partial = self._assert_retained_partial(root, ".stage.partial-*")
            self.assertEqual(raised.exception.details["cleanup_state"], "retained")
            locators = raised.exception.details["recovery_locators"]
            self.assertEqual(Path(locators["prepared_namespace"]), partial)
            inventory = {
                row["relative_path"]
                for row in raised.exception.details["sensitive_partial_inventory"]
            }
            self.assertEqual(
                inventory,
                {MODULE.NOTE_STORE_MAIN, MODULE.PATCH_MANIFEST},
            )

    def test_patch_directory_rename_failure_is_retry_safe_only_after_full_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"

            def fail_rename(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                del parent_fd, source_name, target_name
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=fail_rename,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)

            self._assert_safety_code("destination-install-failed", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertTrue(raised.exception.details["retry_safe"])
            self.assertEqual(raised.exception.details["cleanup_state"], "retained")
            locators = raised.exception.details["recovery_locators"]
            retry_receipt = locators["descriptor_bound_prepared_root"]
            self.assertEqual(
                retry_receipt["verification"],
                "bound-parent-root-tree-content-and-access-match-creation-receipts",
            )
            self.assertEqual(
                retry_receipt["tree_receipt"]["schema"],
                "apple-notes-prepared-tree-receipt/v1",
            )
            self.assertEqual(retry_receipt["target"]["state"], "absent")
            self.assertEqual(
                retry_receipt["target"]["verification"],
                "terminal-descriptor-relative-no-follow-observation",
            )
            self.assertTrue(Path(locators["prepared_namespace"]).is_dir())
            self.assertFalse(destination.exists())

    def test_patch_directory_rename_failure_rejects_tree_content_and_access_drift(
        self,
    ) -> None:
        for drift in ("content", "access"):
            with (
                self.subTest(drift=drift),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                destination = root / "stage"

                def drift_then_fail(
                    parent_fd: int,
                    source_name: str,
                    target_name: str,
                ) -> None:
                    del parent_fd, target_name
                    prepared = root / source_name / MODULE.NOTE_STORE_MAIN
                    if drift == "content":
                        with prepared.open("ab") as handle:
                            handle.write(b"tampered")
                            handle.flush()
                            os.fsync(handle.fileno())
                    else:
                        prepared.chmod(0o640)
                    raise OSError(
                        MODULE.errno.EIO,
                        f"simulated {drift} drift and rename failure",
                    )

                with (
                    mock.patch.object(
                        MODULE,
                        "_rename_directory_no_replace_at",
                        side_effect=drift_then_fail,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    self._stage_patch(edited, destination)

                self._assert_safety_code("destination-install-failed", raised)
                self.assertEqual(
                    raised.exception.details["publication_state"],
                    "uncommitted",
                )
                self.assertFalse(raised.exception.details["retry_safe"])
                self.assertEqual(
                    raised.exception.details["retry_revalidation"]["error_code"],
                    (
                        "prepared-file-content-mismatch"
                        if drift == "content"
                        else "prepared-file-access-policy-mismatch"
                    ),
                )
                self.assertEqual(
                    raised.exception.details["cleanup_state"],
                    "retained",
                )
                self.assertFalse(destination.exists())

    def test_patch_directory_rename_failure_rechecks_terminal_target_absence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_tree_receipt = MODULE._descriptor_bound_prepared_tree_receipt
            rename_failed = False
            injected = False

            def fail_rename(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                nonlocal rename_failed
                del parent_fd, source_name, target_name
                rename_failed = True
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            def build_receipt_then_inject_target(
                *args: object,
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal injected
                receipt = original_tree_receipt(*args, **kwargs)
                if rename_failed and not injected:
                    destination.mkdir()
                    injected = True
                return receipt

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=fail_rename,
                ),
                mock.patch.object(
                    MODULE,
                    "_descriptor_bound_prepared_tree_receipt",
                    side_effect=build_receipt_then_inject_target,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)

            self.assertTrue(injected)
            self._assert_safety_code("destination-exists", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            retry_receipt = raised.exception.details["recovery_locators"][
                "descriptor_bound_prepared_root"
            ]
            self.assertEqual(retry_receipt["target"]["state"], "present")
            self.assertEqual(list(destination.iterdir()), [])

    def test_patch_pre_rename_exact_root_move_is_publication_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_publish = MODULE._publish_directory_no_replace
            moved = False

            def publish_after_external_exact_move(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                original_before_rename = kwargs["before_rename"]
                self.assertTrue(callable(original_before_rename))

                def move_after_full_prevalidation() -> None:
                    nonlocal moved
                    assert callable(original_before_rename)
                    original_before_rename()
                    source.rename(target)
                    moved = True

                kwargs["before_rename"] = move_after_full_prevalidation
                return original_publish(source, target, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=publish_after_external_exact_move,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)

            self.assertTrue(moved)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertTrue((destination / MODULE.NOTE_STORE_MAIN).is_file())
            self.assertTrue((destination / MODULE.PATCH_MANIFEST).is_file())
            self.assertEqual(list(root.glob(".stage.partial-*")), [])
            locator = raised.exception.details["recovery_locators"][
                "descriptor_bound_destination"
            ]
            self.assertEqual(
                locator["tree_verification"],
                "descriptor-revalidated-before-local-rename",
            )
            self.assertEqual(
                locator["tree_receipt"]["schema"],
                "apple-notes-prepared-tree-receipt/v1",
            )

    def test_directory_pre_rename_unavailable_namespace_is_uncertain(
        self,
    ) -> None:
        for unavailable_name in ("source", "destination"):
            with self.subTest(unavailable_name=unavailable_name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    source = root / "partial"
                    destination = root / "destination"
                    with MODULE._create_bound_directory(source) as binding:
                        original_observe = MODULE._observe_bound_name
                        unavailable_basename = (
                            source.name
                            if unavailable_name == "source"
                            else destination.name
                        )

                        def observe_with_unavailable_name(
                            parent_fd: int,
                            basename: str,
                        ) -> tuple[str, os.stat_result | None]:
                            if basename == unavailable_basename:
                                return "unavailable", None
                            return original_observe(parent_fd, basename)

                        def fail_before_rename() -> None:
                            raise MODULE.StoreSafetyError(
                                "prepared-file-content-mismatch",
                                "simulated pre-rename validation failure",
                            )

                        with (
                            mock.patch.object(
                                MODULE,
                                "_observe_bound_name",
                                side_effect=observe_with_unavailable_name,
                            ),
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            MODULE._publish_directory_no_replace(
                                source,
                                destination,
                                binding=binding,
                                before_rename=fail_before_rename,
                            )

                        self._assert_safety_code(
                            "destination-install-uncertain",
                            raised,
                        )
                        self.assertEqual(
                            raised.exception.details["publication_state"],
                            "uncertain",
                        )
                        self.assertFalse(
                            raised.exception.details["retry_safe"],
                        )
                        evidence = raised.exception.details["recovery_locators"][
                            "descriptor_bound_prepared_root"
                        ]
                        self.assertEqual(
                            evidence["evidence_status"],
                            "inconclusive",
                        )
                        observation_key = (
                            "prepared_name"
                            if unavailable_name == "source"
                            else "destination_name"
                        )
                        observation = evidence["namespace_observations"][
                            observation_key
                        ]
                        self.assertEqual(observation["status"], "unavailable")
                        self.assertEqual(
                            observation["evidence_status"],
                            "inconclusive",
                        )
                        self.assertTrue(
                            evidence["parent"]["matches_creation_receipt"],
                        )
                        self.assertTrue(
                            evidence["prepared_root"]["matches_creation_receipt"],
                        )

    def test_patch_pre_rename_revalidation_rejects_extra_root_entry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_publish = MODULE._publish_directory_no_replace
            injected = False

            def publish_after_extra_entry_injection(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                original_before_rename = kwargs["before_rename"]
                self.assertTrue(callable(original_before_rename))

                def inject_before_full_prevalidation() -> None:
                    nonlocal injected
                    (source / "extra-entry").mkdir()
                    injected = True
                    assert callable(original_before_rename)
                    original_before_rename()

                kwargs["before_rename"] = inject_before_full_prevalidation
                return original_publish(source, target, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=publish_after_extra_entry_injection,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)

            self.assertTrue(injected)
            self._assert_safety_code("prepared-file-set-mismatch", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertEqual(raised.exception.details["cleanup_state"], "retained")
            self.assertFalse(destination.exists())
            partial = self._assert_retained_partial(root, ".stage.partial-*")
            self.assertTrue((partial / "extra-entry").is_dir())

    def test_snapshot_publication_reports_commit_then_error_as_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_rename = MODULE._rename_directory_no_replace_at

            def commit_then_error(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                original_rename(parent_fd, source_name, target_name)
                raise OSError(MODULE.errno.EIO, "simulated post-commit error")

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=commit_then_error,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue((destination / MODULE.SNAPSHOT_MANIFEST).is_file())
            self.assertEqual(list(root.glob(".snapshot.partial-*")), [])

    def test_patch_publication_reports_commit_then_error_as_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_rename = MODULE._rename_directory_no_replace_at

            def commit_then_error(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                original_rename(parent_fd, source_name, target_name)
                raise OSError(MODULE.errno.EIO, "simulated post-commit error")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=commit_then_error,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue((destination / MODULE.PATCH_MANIFEST).is_file())
            self.assertEqual(list(root.glob(".stage.partial-*")), [])

    def test_patch_publication_ambiguous_observation_reports_descriptor_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            rename_attempted = False
            original_observe = MODULE._observe_bound_name

            def fail_rename(
                parent_fd: int,
                source_name: str,
                target_name: str,
            ) -> None:
                nonlocal rename_attempted
                rename_attempted = True
                raise OSError(
                    MODULE.errno.EIO,
                    "simulated ambiguous publication failure",
                )

            def observe_after_rename(
                parent_fd: int,
                basename: str,
            ) -> tuple[str, os.stat_result | None]:
                if rename_attempted:
                    return "unavailable", None
                return original_observe(parent_fd, basename)

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=fail_rename,
                ),
                mock.patch.object(
                    MODULE,
                    "_observe_bound_name",
                    side_effect=observe_after_rename,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            locators = raised.exception.details["recovery_locators"]
            self.assertEqual(Path(locators["destination"]), destination)
            evidence = locators["descriptor_bound_prepared_root"]
            self.assertEqual(evidence["evidence_status"], "inconclusive")
            self.assertTrue(evidence["parent"]["matches_creation_receipt"])
            self.assertTrue(evidence["prepared_root"]["matches_creation_receipt"])
            self.assertEqual(
                evidence["namespace_observations"]["prepared_name"]["status"],
                "unavailable",
            )
            self.assertEqual(
                evidence["namespace_observations"]["destination_name"]["status"],
                "unavailable",
            )
            self.assertEqual(
                evidence["target_tree"]["receipt"]["schema"],
                "apple-notes-prepared-tree-receipt/v1",
            )
            self.assertTrue(Path(evidence["prepared_display_path"]).is_dir())
            self.assertFalse(destination.exists())

    def test_snapshot_parent_replace_restore_during_fsync_uses_bound_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            parked = root.with_name(f"{root.name}-parked")
            original_fsync = MODULE._fsync_bound_parent_descriptor
            attacked = False

            def replace_parent_during_fsync(
                parent_fd: int,
                opened: os.stat_result,
                **kwargs: object,
            ) -> None:
                nonlocal attacked
                display_path = Path(str(kwargs["display_path"]))
                if not attacked and display_path == root:
                    attacked = True
                    root.rename(parked)
                    root.mkdir(mode=0o700)
                    replacement = root.stat()
                    self.assertNotEqual(
                        MODULE._identity(replacement),
                        MODULE._identity(os.fstat(parent_fd)),
                    )
                    try:
                        original_fsync(parent_fd, opened, **kwargs)
                    finally:
                        root.rmdir()
                        parked.rename(root)
                    return
                original_fsync(parent_fd, opened, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_parent_descriptor",
                    side_effect=replace_parent_during_fsync,
                ),
            ):
                result = self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self.assertTrue(attacked)
            self.assertEqual(Path(result["dest"]), destination)
            self.assertTrue((destination / MODULE.SNAPSHOT_MANIFEST).is_file())

    def test_snapshot_permanent_parent_replacement_retains_descriptor_tree_locator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            parked = root.with_name(f"{root.name}-parked")
            original_scan = MODULE._scan_exact_prepared_directory_entries
            attacked = False

            def replace_parent_before_public_scan(
                binding: MODULE._BoundDirectory,
                expected_types: dict[str, int],
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal attacked
                if not attacked and binding.path == destination:
                    attacked = True
                    root.rename(parked)
                    root.mkdir(mode=0o700)
                return original_scan(binding, expected_types, **kwargs)

            try:
                with (
                    mock.patch.object(MODULE, "notes_is_running", return_value=False),
                    mock.patch.object(
                        MODULE,
                        "_scan_exact_prepared_directory_entries",
                        side_effect=replace_parent_before_public_scan,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    self._copy_db(
                        paths,
                        dest=destination,
                        require_notes_quit=True,
                    )
                self._assert_safety_code("destination-install-uncertain", raised)
                self.assertTrue(attacked)
                self.assertFalse(destination.exists())
                parked_destination = parked / destination.name
                self.assertTrue(parked_destination.is_dir())
                locator = raised.exception.details["recovery_locators"][
                    "descriptor_bound_destination"
                ]
                self.assertEqual(locator["display_path"], str(destination))
                self.assertEqual(
                    locator["verification"],
                    "bound-parent-and-directory-match-creation-receipts",
                )
                self.assertEqual(
                    locator["directory_identity"],
                    MODULE._identity(parked_destination.stat()),
                )
                self.assertEqual(
                    locator["tree_verification"],
                    "descriptor-revalidated-after-rename",
                )
                tree = locator["tree_receipt"]
                self.assertEqual(
                    tree["root"]["entry_types"],
                    {
                        "group.com.apple.notes": MODULE.stat.S_IFDIR,
                        MODULE.SNAPSHOT_MANIFEST: MODULE.stat.S_IFREG,
                    },
                )
                self.assertIn("group.com.apple.notes", tree["directories"])
                self.assertIn(MODULE.SNAPSHOT_MANIFEST, tree["files"])
                copied_relative = f"group.com.apple.notes/{MODULE.NOTE_STORE_MAIN}"
                self.assertIn(copied_relative, tree["files"])
                copied = parked_destination / copied_relative
                self.assertEqual(
                    tree["files"][copied_relative]["identity"],
                    MODULE._identity(copied.stat()),
                )
                self.assertEqual(
                    tree["files"][copied_relative]["sha256"],
                    MODULE._fingerprint_exact_file(copied)["sha256"],
                )
            finally:
                if parked.exists():
                    if root.exists():
                        root.rmdir()
                    parked.rename(root)

    def test_snapshot_parent_access_change_during_fsync_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_fsync = MODULE._fsync_bound_parent_descriptor
            attacked = False

            def change_parent_access_during_fsync(
                parent_fd: int,
                opened: os.stat_result,
                **kwargs: object,
            ) -> None:
                nonlocal attacked
                display_path = Path(str(kwargs["display_path"]))
                if not attacked and display_path == root:
                    attacked = True
                    baseline_mode = MODULE.stat.S_IMODE(opened.st_mode)
                    changed_mode = 0o750 if baseline_mode != 0o750 else 0o700
                    os.fchmod(parent_fd, changed_mode)
                    try:
                        original_fsync(parent_fd, opened, **kwargs)
                    finally:
                        os.fchmod(parent_fd, baseline_mode)
                    return
                original_fsync(parent_fd, opened, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_parent_descriptor",
                    side_effect=change_parent_access_during_fsync,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(attacked)
            self.assertIsInstance(raised.exception.__cause__, MODULE.StoreSafetyError)
            assert isinstance(raised.exception.__cause__, MODULE.StoreSafetyError)
            self.assertEqual(
                raised.exception.__cause__.code,
                "prepared-directory-access-policy-mismatch",
            )
            self.assertTrue((destination / MODULE.SNAPSHOT_MANIFEST).is_file())

    def test_snapshot_terminal_revalidation_uses_bound_parent_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            parked = root.with_name(f"{root.name}-parked")
            original_verify = MODULE._verify_bound_directory_at
            destination_checks = 0
            attacked = False

            def replace_parent_during_terminal_revalidation(
                binding: object,
                *,
                parent_fd: int,
                basename: str,
                display_path: Path,
            ) -> dict[str, object]:
                nonlocal attacked, destination_checks
                if basename == destination.name:
                    destination_checks += 1
                    if destination_checks == 2:
                        attacked = True
                        root.rename(parked)
                        root.mkdir(mode=0o700)
                        self.assertNotEqual(
                            MODULE._identity(root.stat()),
                            MODULE._identity(os.fstat(parent_fd)),
                        )
                        try:
                            return original_verify(
                                binding,
                                parent_fd=parent_fd,
                                basename=basename,
                                display_path=display_path,
                            )
                        finally:
                            root.rmdir()
                            parked.rename(root)
                return original_verify(
                    binding,
                    parent_fd=parent_fd,
                    basename=basename,
                    display_path=display_path,
                )

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_verify_bound_directory_at",
                    side_effect=replace_parent_during_terminal_revalidation,
                ),
            ):
                result = self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self.assertTrue(attacked)
            self.assertGreaterEqual(destination_checks, 2)
            self.assertEqual(Path(result["dest"]), destination)
            self.assertTrue((destination / MODULE.SNAPSHOT_MANIFEST).is_file())

    def test_same_descriptor_detects_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file.sqlite"
            path.write_bytes(b"stable-bytes")
            original_hash = MODULE._hash_fd
            call_count = 0

            def replacing_hash(fd: int) -> str:
                nonlocal call_count
                digest = original_hash(fd)
                call_count += 1
                if call_count == 1:
                    replacement = path.with_name("replacement.sqlite")
                    replacement.write_bytes(b"stable-bytes")
                    os.replace(replacement, path)
                return digest

            with mock.patch.object(MODULE, "_hash_fd", side_effect=replacing_hash):
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE._fingerprint_exact_file(path)
        self._assert_safety_code("source-identity-mismatch", raised)

    def test_same_descriptor_detects_in_place_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file.sqlite"
            path.write_bytes(b"stable-bytes")
            original_hash = MODULE._hash_fd
            call_count = 0

            def mutating_hash(fd: int) -> str:
                nonlocal call_count
                digest = original_hash(fd)
                call_count += 1
                if call_count == 1:
                    with path.open("r+b") as handle:
                        handle.write(b"changed-byte")
                        handle.flush()
                        os.fsync(handle.fileno())
                return digest

            with mock.patch.object(MODULE, "_hash_fd", side_effect=mutating_hash):
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE._fingerprint_exact_file(path)
        self._assert_safety_code("source-content-mismatch", raised)

    def test_same_descriptor_detects_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file.sqlite"
            path.write_bytes(b"stable-bytes")
            path.chmod(0o600)
            original_hash = MODULE._hash_fd
            call_count = 0

            def chmod_after_hash(fd: int) -> str:
                nonlocal call_count
                digest = original_hash(fd)
                call_count += 1
                if call_count == 1:
                    path.chmod(0o640)
                return digest

            with mock.patch.object(MODULE, "_hash_fd", side_effect=chmod_after_hash):
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE._fingerprint_exact_file(path)
        self._assert_safety_code("source-access-policy-mismatch", raised)

    def test_metadata_only_transition_is_reported_without_false_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file.sqlite"
            path.write_bytes(b"stable-bytes")
            original_hash = MODULE._hash_fd
            call_count = 0

            def touching_hash(fd: int) -> str:
                nonlocal call_count
                digest = original_hash(fd)
                call_count += 1
                if call_count == 1:
                    current = path.stat()
                    os.utime(
                        path,
                        ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000),
                    )
                return digest

            with mock.patch.object(MODULE, "_hash_fd", side_effect=touching_hash):
                result = MODULE._fingerprint_exact_file(path)
        self.assertEqual(
            result["sha256"], MODULE.hashlib.sha256(b"stable-bytes").hexdigest()
        )
        self.assertIn("mtime_ns", result["metadata_transitions"])

    def test_darwin_file_flags_separate_access_policy_from_metadata(self) -> None:
        benign_flags = (
            0x00000001  # UF_NODUMP
            | 0x00000008  # UF_OPAQUE
            | 0x00000020  # UF_COMPRESSED
            | 0x00000040  # UF_TRACKED
            | 0x00008000  # UF_HIDDEN
            | 0x00010000  # SF_ARCHIVED
            | 0x00800000  # SF_FIRMLINK
            | 0x40000000  # SF_DATALESS
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file.sqlite"
            path.write_bytes(b"stable-bytes")
            parent_fd = os.open(path.parent, MODULE._directory_open_flags())
            file_fd = os.open(
                path.name,
                MODULE._untrusted_regular_read_open_flags(),
                dir_fd=parent_fd,
            )
            try:
                baseline = _StatWithFlags(os.fstat(file_fd), 0)
                benign = _StatWithFlags(os.fstat(file_fd), benign_flags)
                opened = MODULE._OpenedSource(
                    path=path,
                    fd=file_fd,
                    before=baseline,
                    parent_fd=parent_fd,
                    parent_opened=os.fstat(parent_fd),
                    first_sha256=hashlib.sha256(b"stable-bytes").hexdigest(),
                )
                original_fstat = MODULE.os.fstat
                original_stat = MODULE.os.stat

                def benign_fstat(fd: int) -> object:
                    observed = original_fstat(fd)
                    return (
                        _StatWithFlags(observed, benign_flags)
                        if fd == file_fd
                        else observed
                    )

                def benign_stat(
                    target: object,
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    observed = original_stat(target, *args, **kwargs)
                    if target == path.name and kwargs.get("dir_fd") == parent_fd:
                        return _StatWithFlags(observed, benign_flags)
                    return observed

                with (
                    mock.patch.object(
                        MODULE.os,
                        "fstat",
                        side_effect=benign_fstat,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "stat",
                        side_effect=benign_stat,
                    ),
                ):
                    result = MODULE._revalidate_open_source(
                        opened,
                        hashlib.sha256(b"stable-bytes").hexdigest(),
                    )
                self.assertEqual(result["access_policy"]["flags"], 0)
                self.assertEqual(result["metadata"]["platform_flags"], benign_flags)
                self.assertEqual(
                    result["metadata_transitions"]["platform_flags"],
                    {"before": 0, "after": benign_flags},
                )
                self.assertEqual(
                    MODULE._access_policy(baseline),
                    MODULE._access_policy(benign),
                )

                for name, flag in MODULE._DARWIN_ACCESS_POLICY_FLAG_BITS.items():
                    with self.subTest(flag=name):
                        protected = _StatWithFlags(os.fstat(file_fd), flag)
                        self.assertNotEqual(
                            MODULE._access_policy(baseline),
                            MODULE._access_policy(protected),
                        )

                protected_flag = MODULE._DARWIN_ACCESS_POLICY_FLAG_BITS["UF_IMMUTABLE"]

                def protected_fstat(fd: int) -> object:
                    observed = original_fstat(fd)
                    return (
                        _StatWithFlags(observed, protected_flag)
                        if fd == file_fd
                        else observed
                    )

                def protected_stat(
                    target: object,
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    observed = original_stat(target, *args, **kwargs)
                    if target == path.name and kwargs.get("dir_fd") == parent_fd:
                        return _StatWithFlags(observed, protected_flag)
                    return observed

                with (
                    mock.patch.object(
                        MODULE.os,
                        "fstat",
                        side_effect=protected_fstat,
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "stat",
                        side_effect=protected_stat,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._revalidate_open_source(
                        opened,
                        hashlib.sha256(b"stable-bytes").hexdigest(),
                    )
                self._assert_safety_code(
                    "source-access-policy-mismatch",
                    raised,
                )
            finally:
                os.close(file_fd)
                os.close(parent_fd)

    def test_merge_db_creates_readable_sidecar_free_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            src = root / MODULE.NOTE_STORE_MAIN
            self._create_db(src)
            merged = root / "merged.sqlite"
            result = MODULE.merge_db(src, merged)
            with closing(sqlite3.connect(merged)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "ok")
            self.assertEqual(result["output_integrity"]["result"], "ok")
            self.assertEqual(Path(result["merged_db"]), merged)
            self.assertEqual(Path(result["standalone_db"]), merged)
            self.assertFalse(merged.with_name(f"{merged.name}-wal").exists())
            self.assertFalse(merged.with_name(f"{merged.name}-shm").exists())
            terminal = result["terminal_sidecar_revalidation"]
            self.assertEqual(
                terminal["verification"],
                "two-pass-descriptor-relative-no-follow",
            )
            self.assertEqual(
                set(terminal["sidecars"]),
                {
                    f"{merged.name}-wal",
                    f"{merged.name}-shm",
                    f"{merged.name}-journal",
                },
            )
            for sidecar in terminal["sidecars"].values():
                self.assertEqual(
                    [row["status"] for row in sidecar["passes"]],
                    ["absent", "absent"],
                )
            public = result["terminal_public_path_revalidation"]
            self.assertEqual(public["evidence_status"], "checked")
            self.assertEqual(
                public["main"]["sha256"],
                result["sha256"],
            )
            self.assertEqual(
                public["main"]["identity"],
                result["identity"],
            )

    def test_standalone_publication_rejects_terminal_sidecar_races(
        self,
    ) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    source = root / MODULE.NOTE_STORE_MAIN
                    merged = root / "merged.sqlite"
                    sidecar = merged.with_name(f"{merged.name}{suffix}")
                    self._create_db(source)
                    original_publish = MODULE._publish_file_no_replace_from_parent

                    def publish_then_inject(
                        prepared: MODULE._BoundRegularFile,
                        destination: Path,
                        parent_fd: int,
                        *,
                        publication_guard: dict[str, object] | None = None,
                    ) -> dict[str, object]:
                        result = original_publish(
                            prepared,
                            destination,
                            parent_fd,
                            publication_guard=publication_guard,
                        )
                        if destination == merged:
                            sidecar.write_bytes(b"raced-sidecar")
                        return result

                    with (
                        mock.patch.object(
                            MODULE,
                            "_publish_file_no_replace_from_parent",
                            side_effect=publish_then_inject,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE.merge_db(source, merged)

                    self._assert_safety_code(
                        "destination-install-uncertain",
                        raised,
                    )
                    self.assertTrue(merged.is_file())
                    self.assertTrue(sidecar.is_file())
                    details = raised.exception.details
                    self.assertEqual(details["publication_state"], "uncertain")
                    self.assertFalse(details["retry_safe"])
                    self.assertIn(
                        "descriptor_bound_destination",
                        details["recovery_locators"],
                    )
                    terminal = details["terminal_sidecar_revalidation"]
                    self.assertEqual(
                        terminal["reason_code"],
                        "standalone-output-sidecar-present",
                    )
                    self.assertEqual(
                        [
                            row["status"]
                            for row in terminal["sidecars"][sidecar.name]["passes"]
                        ],
                        ["present", "present"],
                    )

    def test_terminal_sidecar_revalidation_does_not_follow_symlinks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            merged = root / "merged.sqlite"
            sidecar = merged.with_name(f"{merged.name}-wal")
            self._create_db(source)
            original_publish = MODULE._publish_file_no_replace_from_parent

            def publish_then_inject_symlink(
                prepared: MODULE._BoundRegularFile,
                destination: Path,
                parent_fd: int,
                *,
                publication_guard: dict[str, object] | None = None,
            ) -> dict[str, object]:
                result = original_publish(
                    prepared,
                    destination,
                    parent_fd,
                    publication_guard=publication_guard,
                )
                if destination == merged:
                    sidecar.symlink_to("missing-target")
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_file_no_replace_from_parent",
                    side_effect=publish_then_inject_symlink,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, merged)

            self._assert_safety_code("destination-install-uncertain", raised)
            row = raised.exception.details["terminal_sidecar_revalidation"]["sidecars"][
                sidecar.name
            ]["passes"][0]
            self.assertEqual(row["status"], "present")
            self.assertEqual(row["identity"]["file_type"], stat.S_IFLNK)
            self.assertTrue(sidecar.is_symlink())

    def test_terminal_sidecar_revalidation_distinguishes_unreadable_and_io(
        self,
    ) -> None:
        cases = (
            (
                PermissionError(errno.EACCES, "simulated permission failure"),
                "standalone-output-sidecar-unreadable",
                "unreadable",
            ),
            (
                OSError(errno.EIO, "simulated I/O failure"),
                "standalone-output-sidecar-revalidation-inconclusive",
                "unverifiable",
            ),
        )
        for failure, reason_code, status_name in cases:
            with self.subTest(reason_code=reason_code):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    source = root / MODULE.NOTE_STORE_MAIN
                    merged = root / "merged.sqlite"
                    self._create_db(source)
                    original_publish = MODULE._publish_file_no_replace_from_parent
                    original_stat = MODULE.os.stat
                    published = False

                    def publish_then_mark(
                        prepared: MODULE._BoundRegularFile,
                        destination: Path,
                        parent_fd: int,
                        *,
                        publication_guard: dict[str, object] | None = None,
                    ) -> dict[str, object]:
                        nonlocal published
                        result = original_publish(
                            prepared,
                            destination,
                            parent_fd,
                            publication_guard=publication_guard,
                        )
                        published = destination == merged
                        return result

                    def fail_terminal_wal_stat(
                        path: object,
                        *args: object,
                        **kwargs: object,
                    ) -> os.stat_result:
                        if (
                            published
                            and path == f"{merged.name}-wal"
                            and kwargs.get("dir_fd") is not None
                            and kwargs.get("follow_symlinks") is False
                        ):
                            raise failure
                        return original_stat(path, *args, **kwargs)

                    with (
                        mock.patch.object(
                            MODULE,
                            "_publish_file_no_replace_from_parent",
                            side_effect=publish_then_mark,
                        ),
                        mock.patch.object(
                            MODULE.os,
                            "stat",
                            side_effect=fail_terminal_wal_stat,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE.merge_db(source, merged)

                    self._assert_safety_code(
                        "destination-install-uncertain",
                        raised,
                    )
                    terminal = raised.exception.details["terminal_sidecar_revalidation"]
                    self.assertEqual(terminal["reason_code"], reason_code)
                    self.assertEqual(
                        [
                            row["status"]
                            for row in terminal["sidecars"][f"{merged.name}-wal"][
                                "passes"
                            ]
                        ],
                        [status_name, status_name],
                    )

    def test_terminal_sidecar_second_pass_catches_late_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            merged = root / "merged.sqlite"
            wal = merged.with_name(f"{merged.name}-wal")
            self._create_db(source)
            original_publish = MODULE._publish_file_no_replace_from_parent
            original_stat = MODULE.os.stat
            published = False
            injected = False

            def publish_then_mark(
                prepared: MODULE._BoundRegularFile,
                destination: Path,
                parent_fd: int,
                *,
                publication_guard: dict[str, object] | None = None,
            ) -> dict[str, object]:
                nonlocal published
                result = original_publish(
                    prepared,
                    destination,
                    parent_fd,
                    publication_guard=publication_guard,
                )
                published = destination == merged
                return result

            def inject_after_first_wal_observation(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal injected
                if (
                    published
                    and not injected
                    and path == f"{merged.name}-shm"
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    wal.write_bytes(b"late-wal")
                    injected = True
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_file_no_replace_from_parent",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=inject_after_first_wal_observation,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, merged)

            self._assert_safety_code("destination-install-uncertain", raised)
            passes = raised.exception.details["terminal_sidecar_revalidation"][
                "sidecars"
            ][wal.name]["passes"]
            self.assertEqual(
                [row["status"] for row in passes],
                ["absent", "present"],
            )

    def test_terminal_sidecar_scan_parent_replacement_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            output_parent = root / "output"
            output_parent.mkdir(mode=0o700)
            merged = output_parent / "merged.sqlite"
            parked_parent = root / "output-receipt-bound"
            self._create_db(source)
            original_stat = MODULE.os.stat
            original_publish = MODULE._publish_file_no_replace_from_parent
            published = False
            attacked = False

            def publish_then_mark(
                prepared: MODULE._BoundRegularFile,
                destination: Path,
                parent_fd: int,
                *,
                publication_guard: dict[str, object] | None = None,
            ) -> dict[str, object]:
                nonlocal published
                result = original_publish(
                    prepared,
                    destination,
                    parent_fd,
                    publication_guard=publication_guard,
                )
                published = destination == merged
                return result

            def replace_parent_during_sidecar_scan(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal attacked
                if (
                    published
                    and not attacked
                    and path == f"{merged.name}-journal"
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    output_parent.rename(parked_parent)
                    output_parent.mkdir(mode=0o700)
                    attacked = True
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_file_no_replace_from_parent",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=replace_parent_during_sidecar_scan,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, merged)

            self.assertTrue(attacked)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertFalse(merged.exists())
            parked_main = parked_parent / merged.name
            self.assertTrue(parked_main.is_file())
            details = raised.exception.details
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            terminal_public = details["terminal_public_path_revalidation"]
            self.assertEqual(
                terminal_public["reason_code"],
                "prepared-directory-identity-mismatch",
            )
            locator = details["recovery_locators"]["descriptor_bound_destination"]
            self.assertEqual(
                locator["leaf_identity"],
                MODULE._identity(parked_main.stat()),
            )

    def test_terminal_sidecar_scan_main_replacement_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            merged = root / "merged.sqlite"
            replacement = root / "replacement.sqlite"
            self._create_db(source, value="validated")
            self._create_db(replacement, value="replacement")
            original_publish = MODULE._publish_file_no_replace_from_parent
            original_stat = MODULE.os.stat
            published = False
            attacked = False

            def publish_then_mark(
                prepared: MODULE._BoundRegularFile,
                destination: Path,
                parent_fd: int,
                *,
                publication_guard: dict[str, object] | None = None,
            ) -> dict[str, object]:
                nonlocal published
                result = original_publish(
                    prepared,
                    destination,
                    parent_fd,
                    publication_guard=publication_guard,
                )
                published = destination == merged
                return result

            def replace_main_during_sidecar_scan(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal attacked
                if (
                    published
                    and not attacked
                    and path == f"{merged.name}-journal"
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    os.replace(replacement, merged)
                    attacked = True
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_file_no_replace_from_parent",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=replace_main_during_sidecar_scan,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, merged)

            self.assertTrue(attacked)
            self._assert_safety_code("destination-install-uncertain", raised)
            details = raised.exception.details
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(
                details["terminal_public_path_revalidation"]["reason_code"],
                "prepared-file-identity-mismatch",
            )
            with closing(sqlite3.connect(merged)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "replacement")

    def test_merge_db_preserves_committed_wal_only_row_with_writer_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            writer = self._create_checkpointed_then_wal_only_db(source)
            try:
                merged = root / "merged.sqlite"
                MODULE.merge_db(source, merged)
                with closing(sqlite3.connect(merged)) as recovered:
                    values = [
                        str(row[0])
                        for row in recovered.execute(
                            "SELECT value FROM evidence ORDER BY rowid"
                        )
                    ]
                source_values = [
                    str(row[0])
                    for row in writer.execute(
                        "SELECT value FROM evidence ORDER BY rowid"
                    )
                ]
            finally:
                writer.close()
        self.assertEqual(source_values, ["checkpointed", "wal-only"])
        self.assertEqual(values, source_values)

    def test_clone_receipt_rejects_directory_replacement_after_sidecar_inspection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "clone"
            parked = root / "parked-clone"
            replacement = root / "replacement-clone"
            original_inspect = MODULE._inspect_bound_sidecars

            def replace_after_inspection(
                store: MODULE._BoundRecoveryStore,
            ) -> dict[str, object]:
                result = original_inspect(store)
                replacement.mkdir()
                self._create_db(replacement / source.name, value="replacement")
                os.replace(destination, parked)
                os.replace(replacement, destination)
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_inspect_bound_sidecars",
                    side_effect=replace_after_inspection,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._make_recovery_clone(source, destination)
        self._assert_safety_code(
            "prepared-directory-identity-mismatch",
            raised,
        )

    def test_clone_receipt_rejects_main_replacement_after_sidecar_inspection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "clone"
            original_inspect = MODULE._inspect_bound_sidecars

            def replace_after_inspection(
                store: MODULE._BoundRecoveryStore,
            ) -> dict[str, object]:
                result = original_inspect(store)
                copied = destination / source.name
                replacement = root / "replacement.sqlite"
                replacement.write_bytes(copied.read_bytes())
                replacement.chmod(copied.stat().st_mode & 0o777)
                os.replace(replacement, copied)
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_inspect_bound_sidecars",
                    side_effect=replace_after_inspection,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._make_recovery_clone(source, destination)
        self._assert_safety_code(
            "prepared-file-identity-mismatch",
            raised,
        )

    def test_clone_receipt_rejects_new_member_after_sidecar_inspection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "clone"
            original_inspect = MODULE._inspect_bound_sidecars

            def inject_after_inspection(
                store: MODULE._BoundRecoveryStore,
            ) -> dict[str, object]:
                result = original_inspect(store)
                (destination / "unexpected-sidecar").write_bytes(b"injected")
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_inspect_bound_sidecars",
                    side_effect=inject_after_inspection,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._make_recovery_clone(source, destination)
        self._assert_safety_code("prepared-file-set-mismatch", raised)

    def test_clone_receipt_binds_wal_identity_content_and_access_policy(
        self,
    ) -> None:
        attacks = (
            ("identity", "prepared-file-identity-mismatch"),
            ("content", "prepared-file-content-mismatch"),
            ("access", "prepared-file-access-policy-mismatch"),
        )
        for attack, expected_code in attacks:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                source = root / MODULE.NOTE_STORE_MAIN
                writer = self._create_checkpointed_then_wal_only_db(source)
                try:
                    clone = MODULE._make_recovery_clone(source, root / "clone")
                    wal = clone.main_path.with_name(f"{clone.main_path.name}-wal")
                    if attack == "identity":
                        replacement = root / "replacement-wal"
                        replacement.write_bytes(wal.read_bytes())
                        replacement.chmod(wal.stat().st_mode & 0o777)
                        os.replace(replacement, wal)
                    elif attack == "content":
                        payload = bytearray(wal.read_bytes())
                        payload[-1] ^= 0xFF
                        wal.write_bytes(payload)
                    else:
                        wal.chmod(0o400)
                    with (
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                        MODULE._bind_recovery_store(
                            clone.main_path,
                            creation_receipt=clone.receipt,
                        ),
                    ):
                        pass
                    self._assert_safety_code(expected_code, raised)
                finally:
                    writer.close()

    def test_standalone_backup_ignores_wal_created_after_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "validated.sqlite"
            setup = self._create_checkpointed_then_wal_only_db(source)
            setup.close()
            for suffix in ("-wal", "-shm"):
                sidecar = source.with_name(f"{source.name}{suffix}")
                if sidecar.exists():
                    sidecar.unlink()
            self.assertFalse(source.with_name(f"{source.name}-wal").exists())
            output = root / "output.sqlite"
            with MODULE._bind_regular_file(
                source,
                MODULE.PREPARED_FILE_CODES,
            ) as bound:
                writer = sqlite3.connect(source)
                try:
                    self.assertEqual(
                        writer.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                        "wal",
                    )
                    writer.execute("PRAGMA wal_autocheckpoint = 0")
                    writer.execute("INSERT INTO evidence VALUES ('injected-wal')")
                    writer.commit()
                    self.assertTrue(source.with_name(f"{source.name}-wal").exists())
                    MODULE._backup_bound_regular_to_standalone(bound, output)
                finally:
                    writer.close()
            with closing(sqlite3.connect(output)) as recovered:
                values = [
                    str(row[0])
                    for row in recovered.execute(
                        "SELECT value FROM evidence ORDER BY rowid"
                    )
                ]
        self.assertEqual(values, ["checkpointed", "wal-only"])

    def test_wal_header_rejects_database_header_page_size_sentinel(self) -> None:
        prefix = struct.pack(
            ">6I",
            0x377F0683,
            MODULE.WAL_VERSION,
            1,
            0,
            0x12345678,
            0x9ABCDEF0,
        )
        checksum = MODULE._wal_checksum(prefix, ">")
        payload = prefix + struct.pack(">2I", *checksum)
        with self.assertRaises(MODULE.StoreSafetyError) as raised:
            MODULE._inspect_wal_payload(payload, Path("sentinel.wal"))
        self._assert_safety_code("wal-invalid", raised)

    def test_wal_header_accepts_direct_65536_page_size(self) -> None:
        prefix = struct.pack(
            ">6I",
            0x377F0683,
            MODULE.WAL_VERSION,
            65536,
            0,
            0x12345678,
            0x9ABCDEF0,
        )
        checksum = MODULE._wal_checksum(prefix, ">")
        payload = prefix + struct.pack(">2I", *checksum)
        result = MODULE._inspect_wal_payload(payload, Path("65536.wal"))
        self.assertEqual(result["page_size"], 65536)
        self.assertEqual(result["status"], "valid")

    def test_bound_backup_rejects_wal_replacement_during_sqlite_backup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_dir = root / "source"
            source_dir.mkdir()
            source = source_dir / MODULE.NOTE_STORE_MAIN
            writer = self._create_checkpointed_then_wal_only_db(source)
            wal = source.with_name(f"{source.name}-wal")
            parked = root / "parked-wal"
            replacement = root / "replacement-wal"
            replacement.write_bytes(wal.read_bytes())
            replacement.chmod(wal.stat().st_mode & 0o777)
            output = root / "output.sqlite"
            original_backup = MODULE._sqlite_backup_bytes
            attacked = False

            def replace_wal_during_backup(
                source_image: MODULE._DeserializedSQLiteImage,
                source_path: Path,
            ) -> bytes:
                nonlocal attacked
                attacked = True
                os.replace(wal, parked)
                os.replace(replacement, wal)
                return original_backup(source_image, source_path)

            try:
                with (
                    MODULE._bind_recovery_store(
                        source,
                    ) as store,
                    mock.patch.object(
                        MODULE,
                        "_sqlite_backup_bytes",
                        side_effect=replace_wal_during_backup,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._backup_sqlite_to_standalone(store, output)
                self._assert_safety_code(
                    "prepared-file-identity-mismatch",
                    raised,
                )
                self.assertTrue(attacked)
                self.assertFalse(output.exists())
            finally:
                if wal.exists():
                    os.replace(wal, replacement)
                if parked.exists():
                    os.replace(parked, wal)
                writer.close()

    def test_bound_backup_ignores_replaced_directory_namespace_during_sqlite_backup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_dir = root / "source"
            source_dir.mkdir()
            source = source_dir / MODULE.NOTE_STORE_MAIN
            writer = self._create_checkpointed_then_wal_only_db(source)
            replacement_dir = root / "replacement"
            replacement_dir.mkdir()
            self._create_db(
                replacement_dir / MODULE.NOTE_STORE_MAIN,
                value="replacement",
            )
            parked_dir = root / "parked-source"
            output = root / "output.sqlite"
            original_backup = MODULE._sqlite_backup_bytes
            attacked = False

            def replace_directory_during_backup(
                source_image: MODULE._DeserializedSQLiteImage,
                source_path: Path,
            ) -> bytes:
                nonlocal attacked
                attacked = True
                os.replace(source_dir, parked_dir)
                os.replace(replacement_dir, source_dir)
                try:
                    return original_backup(source_image, source_path)
                finally:
                    os.replace(source_dir, replacement_dir)
                    os.replace(parked_dir, source_dir)

            try:
                with (
                    MODULE._bind_recovery_store(
                        source,
                    ) as store,
                    mock.patch.object(
                        MODULE,
                        "_sqlite_backup_bytes",
                        side_effect=replace_directory_during_backup,
                    ),
                ):
                    MODULE._backup_sqlite_to_standalone(store, output)
                with closing(sqlite3.connect(output)) as recovered:
                    values = [
                        str(row[0])
                        for row in recovered.execute(
                            "SELECT value FROM evidence ORDER BY rowid"
                        )
                    ]
                with closing(
                    sqlite3.connect(replacement_dir / MODULE.NOTE_STORE_MAIN)
                ) as replacement_db:
                    replacement_value = replacement_db.execute(
                        "SELECT value FROM sample"
                    ).fetchone()[0]
            finally:
                writer.close()
        self.assertTrue(attacked)
        self.assertEqual(values, ["checkpointed", "wal-only"])
        self.assertEqual(replacement_value, "replacement")

    def test_bound_backup_rejects_persistent_directory_replacement_during_backup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_dir = root / "source"
            source_dir.mkdir()
            source = source_dir / MODULE.NOTE_STORE_MAIN
            writer = self._create_checkpointed_then_wal_only_db(source)
            replacement_dir = root / "replacement"
            replacement_dir.mkdir()
            self._create_db(
                replacement_dir / MODULE.NOTE_STORE_MAIN,
                value="replacement",
            )
            parked_dir = root / "parked-source"
            output = root / "output.sqlite"
            original_backup = MODULE._sqlite_backup_bytes
            attacked = False

            def replace_directory_during_backup(
                source_image: MODULE._DeserializedSQLiteImage,
                source_path: Path,
            ) -> bytes:
                nonlocal attacked
                attacked = True
                os.replace(source_dir, parked_dir)
                os.replace(replacement_dir, source_dir)
                return original_backup(source_image, source_path)

            try:
                with (
                    MODULE._bind_recovery_store(
                        source,
                    ) as store,
                    mock.patch.object(
                        MODULE,
                        "_sqlite_backup_bytes",
                        side_effect=replace_directory_during_backup,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._backup_sqlite_to_standalone(store, output)
                self._assert_safety_code(
                    "prepared-directory-identity-mismatch",
                    raised,
                )
                self.assertTrue(attacked)
                self.assertFalse(output.exists())
            finally:
                if source_dir.exists():
                    os.replace(source_dir, replacement_dir)
                if parked_dir.exists():
                    os.replace(parked_dir, source_dir)
                writer.close()

    def test_merge_writes_backup_through_bound_output_after_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            destination = root / "merged.sqlite"
            original_write_all = MODULE._write_all
            attacked = False
            replacement: Path | None = None

            def swap_output_while_writing(fd: int, payload: bytes) -> None:
                nonlocal attacked, replacement
                prepared = next(root.glob(".merged.sqlite.tmp-*"), None)
                if attacked or prepared is None:
                    original_write_all(fd, payload)
                    return
                attacked = True
                parked = prepared.with_name(f"{prepared.name}.owned")
                replacement = prepared.with_name(f"{prepared.name}.replacement")
                replacement.write_bytes(b"replacement")
                os.replace(prepared, parked)
                os.replace(replacement, prepared)
                try:
                    original_write_all(fd, payload)
                finally:
                    os.replace(prepared, replacement)
                    os.replace(parked, prepared)

            with mock.patch.object(
                MODULE,
                "_write_all",
                side_effect=swap_output_while_writing,
            ):
                MODULE.merge_db(source, destination)
            with closing(sqlite3.connect(destination)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertTrue(attacked)
            self.assertEqual(value, "validated")
            self.assertIsNotNone(replacement)
            assert replacement is not None
            self.assertEqual(replacement.read_bytes(), b"replacement")

    def test_bound_sqlite_integrity_ignores_path_swap_during_consumption(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            replacement = root / "replacement.sqlite"
            replacement.write_bytes(b"not a sqlite database")
            parked = root / "validated.sqlite"
            original_exec = MODULE._native_sqlite_exec
            attacked = False

            def exec_with_swap(
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal attacked
                if attacked:
                    return original_exec(*args, **kwargs)
                attacked = True
                os.replace(database, parked)
                os.replace(replacement, database)
                try:
                    return original_exec(*args, **kwargs)
                finally:
                    os.replace(database, replacement)
                    os.replace(parked, database)

            with (
                MODULE._bind_regular_file(
                    database,
                    MODULE.PREPARED_FILE_CODES,
                ) as bound,
                mock.patch.object(
                    MODULE.sqlite3,
                    "connect",
                    side_effect=AssertionError(
                        "bound integrity must not reopen a pathname"
                    ),
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_exec",
                    side_effect=exec_with_swap,
                ),
            ):
                integrity = MODULE._sqlite_integrity(bound)
        self.assertTrue(attacked)
        self.assertEqual(integrity["result"], "ok")

    def test_linux_otmpfile_reopen_failure_does_not_block_sqlite_consumption(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / MODULE.NOTE_STORE_MAIN
            self._create_db(database, value="validated")
            payload = database.read_bytes()
            original_open = MODULE.os.open
            pseudo_path_attempts: list[str] = []

            def reject_descriptor_reopen(
                path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                try:
                    raw_path = os.fsdecode(os.fspath(path))
                except TypeError:
                    raw_path = ""
                if raw_path.startswith(("/dev/fd/", "/proc/self/fd/")):
                    pseudo_path_attempts.append(raw_path)
                    raise FileNotFoundError(
                        errno.ENOENT,
                        "simulated Linux O_TMPFILE reopen failure",
                        raw_path,
                    )
                return original_open(path, flags, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=reject_descriptor_reopen,
                ),
                mock.patch.object(
                    MODULE.sqlite3,
                    "connect",
                    side_effect=AssertionError(
                        "payload SQLite must not reopen a filesystem path"
                    ),
                ),
            ):
                integrity = MODULE._sqlite_integrity_from_payload(
                    payload,
                    database,
                )
                backup = MODULE._sqlite_backup_bytes_from_payload(
                    payload,
                    database,
                )
            recovered = root / "recovered.sqlite"
            recovered.write_bytes(backup)
            with closing(sqlite3.connect(recovered)) as connection:
                value = connection.execute("SELECT value FROM sample").fetchone()[0]
        self.assertEqual(pseudo_path_attempts, [])
        self.assertEqual(integrity["result"], "ok")
        self.assertEqual(value, "validated")

    def test_wal_header_normalization_accepts_exact_wal_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / MODULE.NOTE_STORE_MAIN
            self._create_db(database, value="validated")
            original = database.read_bytes()
            for version_pair in ((1, 1), (2, 2)):
                with self.subTest(version_pair=version_pair):
                    payload = bytearray(original)
                    payload[18], payload[19] = version_pair
                    normalized = MODULE._normalize_deserialized_sqlite_header(
                        bytes(payload),
                        database,
                        error_code="sqlite-integrity-failed",
                    )
                    self.assertEqual(normalized[18:20], b"\x01\x01")
                    integrity = MODULE._sqlite_integrity_from_payload(
                        bytes(payload),
                        database,
                    )
                    backup = MODULE._sqlite_backup_bytes_from_payload(
                        bytes(payload),
                        database,
                    )
                    recovered = root / "recovered.sqlite"
                    recovered.write_bytes(backup)
                    with closing(sqlite3.connect(recovered)) as connection:
                        value = connection.execute(
                            "SELECT value FROM sample"
                        ).fetchone()[0]
                    self.assertEqual(integrity["result"], "ok")
                    self.assertEqual(value, "validated")

    def test_wal_header_normalization_does_not_mask_invalid_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            original = database.read_bytes()
            for version_pair in (
                (1, 2),
                (2, 1),
                (0, 0),
                (3, 3),
                (255, 1),
            ):
                with self.subTest(version_pair=version_pair):
                    payload = bytearray(original)
                    payload[18], payload[19] = version_pair
                    with (
                        mock.patch.object(
                            MODULE,
                            "_load_native_sqlite_api",
                            side_effect=AssertionError(
                                "invalid header pair reached SQLite"
                            ),
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE._sqlite_integrity_from_payload(
                            bytes(payload),
                            database,
                        )
                    self._assert_safety_code(
                        "sqlite-integrity-failed",
                        raised,
                    )
                    versions = raised.exception.details["sqlite_header_versions"]
                    self.assertEqual(
                        (versions["write"], versions["read"]),
                        version_pair,
                    )
            payload = bytearray(original)
            payload[18], payload[19] = (1, 2)
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE._sqlite_backup_bytes_from_payload(
                    bytes(payload),
                    database,
                )
        self._assert_safety_code("sqlite-recovery-failed", raised)

    def test_anonymous_recovery_rejects_prebaseline_mutations(self) -> None:
        for attack, expected_code in (
            ("identity", "prepared-file-identity-mismatch"),
            ("content", "prepared-file-content-mismatch"),
            ("access-policy", "prepared-file-access-policy-mismatch"),
        ):
            with self.subTest(attack=attack):
                with tempfile.TemporaryDirectory() as temp_dir:
                    database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
                    self._create_db(database, value="validated")
                    payload = database.read_bytes()
                    original_write = MODULE._write_all
                    replacement_handles: list[object] = []

                    def write_then_attack(fd: int, data: bytes) -> None:
                        original_write(fd, data)
                        if attack == "identity":
                            replacement = tempfile.TemporaryFile()
                            replacement.write(data)
                            replacement.flush()
                            os.fchmod(replacement.fileno(), 0o600)
                            replacement_handles.append(replacement)
                            os.dup2(replacement.fileno(), fd)
                        elif attack == "content":
                            duplicate = os.dup(fd)
                            try:
                                os.lseek(duplicate, 0, os.SEEK_SET)
                                os.write(duplicate, b"X")
                            finally:
                                os.close(duplicate)
                        else:
                            os.fchmod(fd, 0o400)

                    try:
                        with (
                            mock.patch.object(
                                MODULE,
                                "_write_all",
                                side_effect=write_then_attack,
                            ),
                            mock.patch.object(
                                MODULE,
                                "_verify_anonymous_recovery_file",
                                wraps=MODULE._verify_anonymous_recovery_file,
                            ) as verify_mock,
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            MODULE._sqlite_integrity_from_payload(
                                payload,
                                database,
                            )
                    finally:
                        for handle in replacement_handles:
                            handle.close()
                self._assert_safety_code(expected_code, raised)
                verify_mock.assert_not_called()

    def test_deserialized_sqlite_input_revalidates_adversarial_mutations(
        self,
    ) -> None:
        for attack, expected_code in (
            ("identity", "prepared-file-identity-mismatch"),
            ("content", "prepared-file-content-mismatch"),
            ("access-policy", "prepared-file-access-policy-mismatch"),
            ("sqlite-buffer", "prepared-file-content-mismatch"),
        ):
            with self.subTest(attack=attack):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    database = root / MODULE.NOTE_STORE_MAIN
                    self._create_db(database, value="validated")
                    payload = database.read_bytes()
                    original_query = MODULE._native_sqlite_query_rows
                    attacked = False
                    replacement_handles: list[object] = []

                    def query_then_attack(
                        image: MODULE._DeserializedSQLiteImage,
                        sql: str,
                        source_path: Path,
                        **kwargs: object,
                    ) -> list[list[str | None]]:
                        nonlocal attacked
                        rows = original_query(
                            image,
                            sql,
                            source_path,
                            **kwargs,
                        )
                        if attacked:
                            return rows
                        attacked = True
                        if attack == "identity":
                            replacement = tempfile.TemporaryFile()
                            replacement.write(payload)
                            replacement.flush()
                            os.fchmod(replacement.fileno(), 0o600)
                            replacement_handles.append(replacement)
                            os.dup2(replacement.fileno(), image.bound.fd)
                        elif attack == "content":
                            os.lseek(image.bound.fd, 0, os.SEEK_SET)
                            os.write(image.bound.fd, b"X")
                        elif attack == "access-policy":
                            os.fchmod(image.bound.fd, 0o400)
                        else:
                            ctypes.memset(image.buffer, ord("X"), 1)
                        return rows

                    try:
                        with (
                            mock.patch.object(
                                MODULE,
                                "_native_sqlite_query_rows",
                                side_effect=query_then_attack,
                            ),
                            self.assertRaises(MODULE.StoreSafetyError) as raised,
                        ):
                            MODULE._sqlite_integrity_from_payload(
                                payload,
                                database,
                            )
                    finally:
                        for handle in replacement_handles:
                            handle.close()
                self.assertTrue(attacked)
                self._assert_safety_code(expected_code, raised)

    def test_sqlite_callback_process_control_aborts_and_cleans_up(self) -> None:
        for process_control in (
            KeyboardInterrupt("simulated callback interrupt"),
            SystemExit(23),
        ):
            with (
                self.subTest(exception_type=type(process_control).__name__),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
                self._create_db(database)
                payload = database.read_bytes()
                original_close = MODULE._native_sqlite_close
                original_free = MODULE._native_sqlite_free
                with (
                    mock.patch.object(
                        MODULE,
                        "_decode_sqlite_callback_value",
                        side_effect=process_control,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_native_sqlite_close",
                        wraps=original_close,
                    ) as close_mock,
                    mock.patch.object(
                        MODULE,
                        "_native_sqlite_free",
                        wraps=original_free,
                    ) as free_mock,
                    self.assertRaises(type(process_control)) as raised,
                ):
                    MODULE._sqlite_integrity_from_payload(payload, database)

                self.assertIs(raised.exception, process_control)
                close_mock.assert_called_once()
                self.assertGreaterEqual(free_mock.call_count, 2)

    def test_sqlite_callback_runtime_failure_keeps_cause_and_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            callback_failure = RuntimeError("simulated callback decode failure")
            with (
                mock.patch.object(
                    MODULE,
                    "_decode_sqlite_callback_value",
                    side_effect=callback_failure,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_integrity_from_payload(payload, database)

        self._assert_safety_code("sqlite-integrity-failed", raised)
        self.assertEqual(
            raised.exception.details["sqlite_callback_failure"],
            {"error_type": "RuntimeError"},
        )
        self.assertEqual(
            raised.exception.details["sqlite_input_cleanup"]["status"],
            "complete",
        )
        callback_error = raised.exception.__cause__
        self.assertIsInstance(callback_error, MODULE.StoreSafetyError)
        assert isinstance(callback_error, MODULE.StoreSafetyError)
        self.assertIs(callback_error.__cause__, callback_failure)

    def test_sqlite_callback_failure_survives_terminal_buffer_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            callback_failure = RuntimeError("simulated callback decode failure")
            original_verify = MODULE._verify_deserialized_sqlite_buffer
            verify_calls = 0

            def fail_terminal_buffer_revalidation(
                image: MODULE._DeserializedSQLiteImage,
                source_path: Path,
            ) -> None:
                nonlocal verify_calls
                verify_calls += 1
                if verify_calls == 3:
                    raise MODULE.StoreSafetyError(
                        "prepared-file-content-mismatch",
                        "simulated terminal SQLite buffer mutation",
                    )
                original_verify(image, source_path)

            with (
                mock.patch.object(
                    MODULE,
                    "_decode_sqlite_callback_value",
                    side_effect=callback_failure,
                ),
                mock.patch.object(
                    MODULE,
                    "_verify_deserialized_sqlite_buffer",
                    side_effect=fail_terminal_buffer_revalidation,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_integrity_from_payload(payload, database)

        self._assert_safety_code("prepared-file-content-mismatch", raised)
        self.assertGreaterEqual(verify_calls, 4)
        self.assertEqual(
            raised.exception.details["sqlite_input_secondary_failure"],
            {
                "schema": "apple-notes-sqlite-secondary-failure/v1",
                "phase": "sqlite-row-callback",
                "error_type": "StoreSafetyError",
                "error_code": "sqlite-integrity-failed",
                "sqlite_callback_failure": {
                    "error_type": "RuntimeError",
                },
            },
        )
        self.assertEqual(
            raised.exception.details["sqlite_input_cleanup"]["status"],
            "complete",
        )

    def test_sqlite_callback_failure_survives_terminal_binding_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            callback_failure = RuntimeError("simulated callback decode failure")
            original_query = MODULE._native_sqlite_query_rows
            binding_verify_calls = 0

            def query_with_terminal_binding_failure(
                image: MODULE._DeserializedSQLiteImage,
                sql: str,
                source_path: Path,
                **kwargs: object,
            ) -> list[list[str | None]]:
                def fail_terminal_binding_revalidation() -> object:
                    nonlocal binding_verify_calls
                    binding_verify_calls += 1
                    if binding_verify_calls == 2:
                        raise MODULE.StoreSafetyError(
                            "prepared-file-identity-mismatch",
                            "simulated terminal SQLite binding replacement",
                        )
                    return image.verify_bound()

                query_image = MODULE._DeserializedSQLiteImage(
                    api=image.api,
                    database=image.database,
                    buffer=image.buffer,
                    byte_count=image.byte_count,
                    sha256=image.sha256,
                    bound=image.bound,
                    verify_bound=fail_terminal_binding_revalidation,
                )
                return original_query(
                    query_image,
                    sql,
                    source_path,
                    **kwargs,
                )

            with (
                mock.patch.object(
                    MODULE,
                    "_decode_sqlite_callback_value",
                    side_effect=callback_failure,
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_query_rows",
                    side_effect=query_with_terminal_binding_failure,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_integrity_from_payload(payload, database)

        self._assert_safety_code("prepared-file-identity-mismatch", raised)
        self.assertEqual(binding_verify_calls, 2)
        self.assertEqual(
            raised.exception.details["sqlite_input_secondary_failure"],
            {
                "schema": "apple-notes-sqlite-secondary-failure/v1",
                "phase": "sqlite-row-callback",
                "error_type": "StoreSafetyError",
                "error_code": "sqlite-integrity-failed",
                "sqlite_callback_failure": {
                    "error_type": "RuntimeError",
                },
            },
        )
        self.assertEqual(
            raised.exception.details["sqlite_input_cleanup"]["status"],
            "complete",
        )

    def test_deserialize_failure_closes_descriptor_and_frees_buffer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            original_temporary_file = MODULE.tempfile.TemporaryFile
            original_close = MODULE._native_sqlite_close
            original_free = MODULE._native_sqlite_free
            handles: list[object] = []

            def tracking_temporary_file(
                *args: object,
                **kwargs: object,
            ) -> object:
                handle = original_temporary_file(*args, **kwargs)
                handles.append(handle)
                return handle

            with (
                mock.patch.object(
                    MODULE.tempfile,
                    "TemporaryFile",
                    side_effect=tracking_temporary_file,
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_deserialize",
                    return_value=14,
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_close",
                    wraps=original_close,
                ) as close_mock,
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_free",
                    wraps=original_free,
                ) as free_mock,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_integrity_from_payload(payload, database)
        self._assert_safety_code("sqlite-integrity-failed", raised)
        self.assertEqual(len(handles), 1)
        self.assertTrue(handles[0].closed)
        close_mock.assert_called_once()
        free_mock.assert_called_once()
        cleanup = raised.exception.details["sqlite_input_cleanup"]
        self.assertEqual(cleanup["status"], "complete")
        self.assertEqual(
            cleanup["steps"]["connection_close"]["status"],
            "complete",
        )
        self.assertEqual(
            cleanup["steps"]["buffer_free"]["status"],
            "complete",
        )

    def test_deserialize_runtime_failure_is_classified_with_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            original_close = MODULE._native_sqlite_close
            original_free = MODULE._native_sqlite_free
            with (
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_deserialize",
                    side_effect=RuntimeError("simulated ctypes failure"),
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_close",
                    wraps=original_close,
                ) as close_mock,
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_free",
                    wraps=original_free,
                ) as free_mock,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_integrity_from_payload(payload, database)
        self._assert_safety_code("sqlite-integrity-failed", raised)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        cleanup = raised.exception.details["sqlite_input_cleanup"]
        self.assertEqual(cleanup["status"], "complete")
        close_mock.assert_called_once()
        free_mock.assert_called_once()

    def test_deserialize_revalidation_process_control_is_not_wrapped(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception_type=exception_type.__name__):
                with tempfile.TemporaryDirectory() as temp_dir:
                    database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
                    self._create_db(database)
                    payload = database.read_bytes()
                    original_verify = MODULE._verify_deserialized_sqlite_buffer
                    original_close = MODULE._native_sqlite_close
                    original_free = MODULE._native_sqlite_free
                    verify_calls = 0

                    def interrupt_revalidation(
                        image: MODULE._DeserializedSQLiteImage,
                        source_path: Path,
                    ) -> None:
                        nonlocal verify_calls
                        verify_calls += 1
                        if verify_calls == 2:
                            raise exception_type("simulated process control")
                        original_verify(image, source_path)

                    with MODULE._anonymous_recovery_file(
                        payload,
                        database,
                        error_code="sqlite-integrity-failed",
                    ) as bound:
                        with (
                            mock.patch.object(
                                MODULE,
                                "_verify_deserialized_sqlite_buffer",
                                side_effect=interrupt_revalidation,
                            ),
                            mock.patch.object(
                                MODULE,
                                "_native_sqlite_close",
                                wraps=original_close,
                            ) as close_mock,
                            mock.patch.object(
                                MODULE,
                                "_native_sqlite_free",
                                wraps=original_free,
                            ) as free_mock,
                            self.assertRaises(exception_type),
                        ):
                            with MODULE._deserialized_sqlite_image(
                                bound,
                                database,
                                verify_bound=lambda: (
                                    MODULE._verify_anonymous_recovery_file(bound)
                                ),
                                error_code="sqlite-integrity-failed",
                                require_backup=False,
                            ):
                                raise RuntimeError("simulated consumer failure")
                close_mock.assert_called_once()
                free_mock.assert_called_once()

    def test_deserialize_revalidation_is_primary_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            original_verify = MODULE._verify_deserialized_sqlite_buffer
            verify_calls = 0

            def fail_revalidation(
                image: MODULE._DeserializedSQLiteImage,
                source_path: Path,
            ) -> None:
                nonlocal verify_calls
                verify_calls += 1
                if verify_calls == 2:
                    try:
                        raise OSError(errno.EIO, "simulated buffer read failure")
                    except OSError as cause:
                        raise MODULE.StoreSafetyError(
                            "prepared-file-revalidation-inconclusive",
                            "simulated SQLite input revalidation failure",
                        ) from cause
                original_verify(image, source_path)

            with MODULE._anonymous_recovery_file(
                payload,
                database,
                error_code="sqlite-integrity-failed",
            ) as bound:
                with (
                    mock.patch.object(
                        MODULE,
                        "_verify_deserialized_sqlite_buffer",
                        side_effect=fail_revalidation,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    with MODULE._deserialized_sqlite_image(
                        bound,
                        database,
                        verify_bound=lambda: (
                            MODULE._verify_anonymous_recovery_file(bound)
                        ),
                        error_code="sqlite-integrity-failed",
                        require_backup=False,
                    ):
                        raise RuntimeError("simulated consumer failure")
        self._assert_safety_code(
            "prepared-file-revalidation-inconclusive",
            raised,
        )
        revalidation_error = raised.exception.__cause__
        self.assertIsInstance(revalidation_error, MODULE.StoreSafetyError)
        assert isinstance(revalidation_error, MODULE.StoreSafetyError)
        self.assertIsInstance(revalidation_error.__cause__, OSError)
        self.assertEqual(
            raised.exception.details["sqlite_input_secondary_failure"],
            {
                "schema": "apple-notes-sqlite-secondary-failure/v1",
                "phase": "consumer",
                "error_type": "RuntimeError",
            },
        )
        self.assertEqual(
            raised.exception.details["sqlite_input_cleanup"]["status"],
            "complete",
        )

    def test_deserialize_cleanup_retains_buffer_when_close_is_unproved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            payload = database.read_bytes()
            original_close = MODULE._native_sqlite_close

            def close_then_raise(
                api: MODULE._NativeSQLiteApi,
                connection: ctypes.c_void_p,
            ) -> int:
                original_close(api, connection)
                raise RuntimeError("simulated unproved close")

            with (
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_deserialize",
                    side_effect=RuntimeError("simulated ctypes failure"),
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_close",
                    side_effect=close_then_raise,
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_free",
                ) as free_mock,
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_integrity_from_payload(payload, database)
        self._assert_safety_code("sqlite-integrity-failed", raised)
        cleanup = raised.exception.details["sqlite_input_cleanup"]
        self.assertEqual(cleanup["status"], "incomplete")
        self.assertEqual(
            cleanup["steps"]["connection_close"]["status"],
            "failed",
        )
        self.assertEqual(
            cleanup["steps"]["buffer_free"],
            {
                "status": "skipped-unsafe",
                "reason": "database-close-unproved",
            },
        )
        self.assertEqual(cleanup["buffer"]["release_status"], "retained")
        free_mock.assert_not_called()

    def test_backup_runtime_failure_aggregates_cleanup_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(database, value="validated")
            payload = database.read_bytes()
            original_verify = MODULE._verify_deserialized_sqlite_buffer
            original_close = MODULE._native_sqlite_close
            original_free = MODULE._native_sqlite_free
            verify_calls = 0
            close_calls = 0
            free_calls = 0

            def fail_after_serialization(
                image: MODULE._DeserializedSQLiteImage,
                source_path: Path,
            ) -> None:
                nonlocal verify_calls
                verify_calls += 1
                if verify_calls == 3:
                    raise RuntimeError("simulated post-serialization ctypes failure")
                original_verify(image, source_path)

            def close_then_fail_once(
                api: MODULE._NativeSQLiteApi,
                connection: ctypes.c_void_p,
            ) -> int:
                nonlocal close_calls
                close_calls += 1
                result = original_close(api, connection)
                if close_calls == 1:
                    raise OSError(errno.EIO, "simulated destination close failure")
                return result

            def free_then_fail_once(
                api: MODULE._NativeSQLiteApi,
                pointer: int,
            ) -> None:
                nonlocal free_calls
                free_calls += 1
                original_free(api, pointer)
                if free_calls == 1:
                    raise OSError(errno.EIO, "simulated serialized free failure")

            with (
                mock.patch.object(
                    MODULE,
                    "_verify_deserialized_sqlite_buffer",
                    side_effect=fail_after_serialization,
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_close",
                    side_effect=close_then_fail_once,
                ),
                mock.patch.object(
                    MODULE,
                    "_native_sqlite_free",
                    side_effect=free_then_fail_once,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._sqlite_backup_bytes_from_payload(payload, database)
        self._assert_safety_code("sqlite-recovery-failed", raised)
        backup_cleanup = raised.exception.details["sqlite_backup_cleanup"]
        self.assertEqual(backup_cleanup["status"], "incomplete")
        self.assertEqual(
            backup_cleanup["steps"]["backup_finish"]["status"],
            "complete",
        )
        self.assertEqual(
            backup_cleanup["steps"]["serialized_free"]["status"],
            "failed",
        )
        self.assertEqual(
            backup_cleanup["steps"]["destination_close"]["status"],
            "failed",
        )
        self.assertEqual(
            raised.exception.details["sqlite_input_cleanup"]["status"],
            "complete",
        )
        self.assertEqual(close_calls, 2)
        self.assertEqual(free_calls, 2)

    def test_backup_cleanup_attempts_every_independent_step(self) -> None:
        api = mock.Mock(spec=MODULE._NativeSQLiteApi)
        with (
            mock.patch.object(
                MODULE,
                "_native_sqlite_backup_finish",
                side_effect=RuntimeError("simulated finish failure"),
            ) as finish_mock,
            mock.patch.object(
                MODULE,
                "_native_sqlite_free",
                side_effect=RuntimeError("simulated free failure"),
            ) as free_mock,
            mock.patch.object(
                MODULE,
                "_native_sqlite_close",
                side_effect=RuntimeError("simulated close failure"),
            ) as close_mock,
        ):
            cleanup = MODULE._cleanup_sqlite_backup(
                api,
                ctypes.c_void_p(11),
                12,
                13,
                finish_step={"status": "not-needed"},
            )
        self.assertEqual(cleanup["status"], "incomplete")
        self.assertEqual(
            {name: step["status"] for name, step in cleanup["steps"].items()},
            {
                "backup_finish": "failed",
                "serialized_free": "failed",
                "destination_close": "failed",
            },
        )
        finish_mock.assert_called_once()
        free_mock.assert_called_once()
        close_mock.assert_called_once()

    def test_failed_recovery_preserves_temp_leaf_replaced_after_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            destination = root / "merged.sqlite"
            original_integrity = MODULE._sqlite_integrity
            attacked = False
            moved_prepared: Path | None = None
            replacement: Path | None = None

            def swap_then_fail(
                database: object,
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal attacked, moved_prepared, replacement
                if attacked or not isinstance(database, MODULE._BoundRegularFile):
                    return original_integrity(database, **kwargs)
                attacked = True
                prepared = database.path
                moved_prepared = prepared.with_name(f"{prepared.name}.owned")
                replacement = prepared
                prepared.rename(moved_prepared)
                prepared.write_text("replacement", encoding="utf-8")
                raise MODULE.StoreSafetyError(
                    "sqlite-integrity-failed",
                    "simulated integrity failure after leaf replacement",
                )

            with (
                mock.patch.object(
                    MODULE,
                    "_sqlite_integrity",
                    side_effect=swap_then_fail,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("sqlite-integrity-failed", raised)
            self.assertTrue(attacked)
            self.assertFalse(destination.exists())
            self.assertIsNotNone(moved_prepared)
            self.assertIsNotNone(replacement)
            assert moved_prepared is not None
            assert replacement is not None
            self.assertEqual(replacement.read_text(encoding="utf-8"), "replacement")
            with closing(sqlite3.connect(moved_prepared)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "validated")

    def test_second_source_revalidation_failure_reports_bound_retained_temp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            destination = root / "merged.sqlite"
            self._create_db(source, value="validated")
            revalidation_calls = 0
            prepared_path: Path | None = None

            with MODULE._bind_source_store(source) as source_store:

                def revalidate_source() -> None:
                    nonlocal revalidation_calls, prepared_path
                    revalidation_calls += 1
                    if revalidation_calls != 2:
                        return
                    prepared_path = next(root.glob(".merged.sqlite.tmp-*"))
                    raise MODULE.StoreSafetyError(
                        "source-revalidation-inconclusive",
                        "simulated second source revalidation failure",
                    )

                def backup_source(
                    output: Path,
                    destination_binding: MODULE._BoundDirectory | None,
                ) -> dict[str, object]:
                    return MODULE._backup_sqlite_to_standalone(
                        source_store,
                        output,
                        destination_binding=destination_binding,
                    )

                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE._recover_validated_clone_to_standalone(
                        source,
                        destination,
                        source_db=source,
                        recovery_evidence={},
                        source_integrity={"result": "ok"},
                        source_revalidate=revalidate_source,
                        source_backup=backup_source,
                    )

            self._assert_safety_code(
                "source-revalidation-inconclusive",
                raised,
            )
            self.assertEqual(revalidation_calls, 2)
            self.assertIsNotNone(prepared_path)
            assert prepared_path is not None
            self.assertTrue(prepared_path.is_file())
            self.assertFalse(destination.exists())
            details = raised.exception.details
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertFalse(details["retry_safe"])
            self.assertNotIn("publication_state", details)
            locator = details["recovery_locators"]["descriptor_bound_prepared_file"]
            self.assertEqual(locator["evidence_status"], "checked")
            self.assertEqual(
                locator["file_descriptor"]["identity"],
                MODULE._identity(prepared_path.stat()),
            )
            namespace = locator["namespace_observations"][prepared_path.name]
            self.assertEqual(namespace["status"], "present")
            self.assertTrue(namespace["identity_matches_creation_receipt"])

    def test_second_source_revalidation_runtime_failure_retains_swapped_objects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            destination = root / "merged.sqlite"
            self._create_db(source, value="validated")
            revalidation_calls = 0
            moved_prepared: Path | None = None
            replacement: Path | None = None

            with MODULE._bind_source_store(source) as source_store:

                def revalidate_source() -> None:
                    nonlocal revalidation_calls, moved_prepared, replacement
                    revalidation_calls += 1
                    if revalidation_calls != 2:
                        return
                    prepared = next(root.glob(".merged.sqlite.tmp-*"))
                    moved_prepared = prepared.with_name(f"{prepared.name}.owned")
                    prepared.rename(moved_prepared)
                    prepared.write_text("replacement", encoding="utf-8")
                    replacement = prepared
                    raise OSError(
                        MODULE.errno.EIO,
                        "simulated second source revalidation failure",
                    )

                def backup_source(
                    output: Path,
                    destination_binding: MODULE._BoundDirectory | None,
                ) -> dict[str, object]:
                    return MODULE._backup_sqlite_to_standalone(
                        source_store,
                        output,
                        destination_binding=destination_binding,
                    )

                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE._recover_validated_clone_to_standalone(
                        source,
                        destination,
                        source_db=source,
                        recovery_evidence={},
                        source_integrity={"result": "ok"},
                        source_revalidate=revalidate_source,
                        source_backup=backup_source,
                    )

            self._assert_safety_code("prepared-operation-failed", raised)
            self.assertIsInstance(raised.exception.__cause__, OSError)
            self.assertEqual(
                raised.exception.details["underlying_errno"],
                MODULE.errno.EIO,
            )
            self.assertEqual(revalidation_calls, 2)
            self.assertIsNotNone(moved_prepared)
            self.assertIsNotNone(replacement)
            assert moved_prepared is not None
            assert replacement is not None
            self.assertTrue(moved_prepared.is_file())
            self.assertEqual(
                replacement.read_text(encoding="utf-8"),
                "replacement",
            )
            self.assertFalse(destination.exists())
            details = raised.exception.details
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertFalse(details["retry_safe"])
            locator = details["recovery_locators"]["descriptor_bound_prepared_file"]
            self.assertEqual(
                locator["file_descriptor"]["identity"],
                MODULE._identity(moved_prepared.stat()),
            )
            namespace = locator["namespace_observations"][replacement.name]
            self.assertEqual(namespace["status"], "present")
            self.assertFalse(namespace["identity_matches_creation_receipt"])
            self.assertEqual(
                namespace["identity"],
                MODULE._identity(replacement.stat()),
            )
            with closing(sqlite3.connect(moved_prepared)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "validated")

    def test_prepublication_receipt_mismatch_does_not_sign_attacker_state(
        self,
    ) -> None:
        cases = (
            ("identity", "prepared-file-identity-mismatch"),
            ("content", "prepared-file-content-mismatch"),
            ("access-policy", "prepared-file-access-policy-mismatch"),
        )
        for attack, expected_code in cases:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                source = root / MODULE.NOTE_STORE_MAIN
                destination = root / "merged.sqlite"
                self._create_db(source, value="validated")
                creation_receipt: dict[str, object] | None = None
                prepared_path: Path | None = None
                moved_created: Path | None = None

                with MODULE._bind_source_store(source) as source_store:

                    def backup_source(
                        output: Path,
                        destination_binding: MODULE._BoundDirectory | None,
                    ) -> dict[str, object]:
                        nonlocal creation_receipt, prepared_path, moved_created
                        result = MODULE._backup_sqlite_to_standalone(
                            source_store,
                            output,
                            destination_binding=destination_binding,
                        )
                        creation_receipt = result
                        prepared_path = output
                        if attack == "identity":
                            moved_created = output.with_name(f"{output.name}.created")
                            output.rename(moved_created)
                            shutil.copyfile(moved_created, output)
                            output.chmod(stat.S_IMODE(moved_created.stat().st_mode))
                        elif attack == "content":
                            with output.open("ab") as handle:
                                handle.write(b"tampered-after-creation-receipt")
                                handle.flush()
                                os.fsync(handle.fileno())
                        else:
                            output.chmod(0o640)
                        return result

                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        MODULE._recover_validated_clone_to_standalone(
                            source,
                            destination,
                            source_db=source,
                            recovery_evidence={},
                            source_integrity={"result": "ok"},
                            source_revalidate=lambda: None,
                            source_backup=backup_source,
                        )

                self._assert_safety_code(expected_code, raised)
                self.assertIsNotNone(creation_receipt)
                self.assertIsNotNone(prepared_path)
                assert creation_receipt is not None
                assert prepared_path is not None
                self.assertTrue(prepared_path.is_file())
                self.assertFalse(destination.exists())
                details = raised.exception.details
                self.assertEqual(details["cleanup_state"], "retained")
                self.assertFalse(details["retry_safe"])
                locator = details["recovery_locators"]["descriptor_bound_prepared_file"]
                self.assertEqual(
                    locator["creation_receipt"]["identity"],
                    creation_receipt["identity"],
                )
                initial = locator["initial_bound_descriptor"]
                self.assertEqual(
                    initial["identity_matches_creation_receipt"],
                    attack != "identity",
                )
                self.assertEqual(
                    initial["content_matches_creation_receipt"],
                    attack != "content",
                )
                self.assertEqual(
                    initial["access_policy_matches_creation_receipt"],
                    attack != "access-policy",
                )
                self.assertEqual(
                    locator["content_evidence"]["matches_creation_receipt"],
                    attack != "content",
                )
                namespace = locator["namespace_observations"][prepared_path.name]
                self.assertEqual(namespace["status"], "present")
                self.assertEqual(
                    namespace["identity_matches_creation_receipt"],
                    attack != "identity",
                )
                self.assertEqual(
                    namespace["access_policy_matches_creation_receipt"],
                    attack != "access-policy",
                )
                if attack == "identity":
                    self.assertIsNotNone(moved_created)
                    assert moved_created is not None
                    self.assertEqual(
                        MODULE._identity(moved_created.stat()),
                        creation_receipt["identity"],
                    )

    def test_prepublication_receipt_allows_mtime_only_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            destination = root / "merged.sqlite"
            self._create_db(source, value="validated")

            with MODULE._bind_source_store(source) as source_store:

                def backup_then_touch_mtime(
                    output: Path,
                    destination_binding: MODULE._BoundDirectory | None,
                ) -> dict[str, object]:
                    result = MODULE._backup_sqlite_to_standalone(
                        source_store,
                        output,
                        destination_binding=destination_binding,
                    )
                    observed = output.stat()
                    os.utime(
                        output,
                        ns=(
                            observed.st_atime_ns,
                            observed.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                    return result

                result = MODULE._recover_validated_clone_to_standalone(
                    source,
                    destination,
                    source_db=source,
                    recovery_evidence={},
                    source_integrity={"result": "ok"},
                    source_revalidate=lambda: None,
                    source_backup=backup_then_touch_mtime,
                )

            self.assertEqual(Path(result["standalone_db"]), destination)
            with closing(sqlite3.connect(destination)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "validated")

    def test_snapshot_post_backup_revalidation_reports_retained_temp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_main = (
                snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            )
            destination = root / "recovered.sqlite"
            original_backup = MODULE._backup_bound_store_to_standalone
            prepared_path: Path | None = None

            def backup_then_change_snapshot_access(
                source_store: MODULE._BoundRecoveryStore,
                output: Path,
                *,
                destination_binding: MODULE._BoundDirectory | None = None,
            ) -> dict[str, object]:
                nonlocal prepared_path
                result = original_backup(
                    source_store,
                    output,
                    destination_binding=destination_binding,
                )
                prepared_path = output
                snapshot_main.chmod(0o640)
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_backup_bound_store_to_standalone",
                    side_effect=backup_then_change_snapshot_access,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, destination)

            self._assert_safety_code(
                "snapshot-file-access-policy-mismatch",
                raised,
            )
            self.assertIsNotNone(prepared_path)
            assert prepared_path is not None
            self.assertTrue(prepared_path.is_file())
            self.assertFalse(destination.exists())
            details = raised.exception.details
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertFalse(details["retry_safe"])
            locator = details["recovery_locators"]["descriptor_bound_prepared_file"]
            self.assertTrue(
                locator["initial_bound_descriptor"]["identity_matches_creation_receipt"]
            )
            self.assertTrue(
                locator["initial_bound_descriptor"]["content_matches_creation_receipt"]
            )
            self.assertTrue(
                locator["initial_bound_descriptor"][
                    "access_policy_matches_creation_receipt"
                ]
            )

    def test_temp_bind_failure_reports_unbound_creation_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            destination = root / "merged.sqlite"
            self._create_db(source, value="validated")
            backup_finished = False
            creation_receipt: dict[str, object] | None = None
            prepared_path: Path | None = None
            original_hash = MODULE._hash_fd

            with MODULE._bind_source_store(source) as source_store:

                def backup_source(
                    output: Path,
                    destination_binding: MODULE._BoundDirectory | None,
                ) -> dict[str, object]:
                    nonlocal backup_finished, creation_receipt, prepared_path
                    result = MODULE._backup_sqlite_to_standalone(
                        source_store,
                        output,
                        destination_binding=destination_binding,
                    )
                    creation_receipt = result
                    prepared_path = output
                    backup_finished = True
                    return result

                def fail_rebind_hash(fd: int) -> str:
                    if (
                        backup_finished
                        and creation_receipt is not None
                        and MODULE._identity(os.fstat(fd))
                        == creation_receipt["identity"]
                    ):
                        raise OSError(
                            MODULE.errno.EIO,
                            "simulated descriptor rebind hash failure",
                        )
                    return original_hash(fd)

                with (
                    mock.patch.object(
                        MODULE,
                        "_hash_fd",
                        side_effect=fail_rebind_hash,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._recover_validated_clone_to_standalone(
                        source,
                        destination,
                        source_db=source,
                        recovery_evidence={},
                        source_integrity={"result": "ok"},
                        source_revalidate=lambda: None,
                        source_backup=backup_source,
                    )

            self._assert_safety_code(
                "prepared-file-revalidation-inconclusive",
                raised,
            )
            self.assertIsNotNone(creation_receipt)
            self.assertIsNotNone(prepared_path)
            assert creation_receipt is not None
            assert prepared_path is not None
            self.assertTrue(prepared_path.is_file())
            self.assertFalse(destination.exists())
            details = raised.exception.details
            self.assertEqual(
                details["cleanup_state"],
                "preserved-or-incomplete",
            )
            self.assertFalse(details["retry_safe"])
            self.assertNotIn(
                "descriptor_bound_prepared_file",
                details["recovery_locators"],
            )
            locator = details["recovery_locators"]["creation_receipt_prepared_file"]
            self.assertEqual(locator["binding_status"], "inconclusive")
            self.assertEqual(
                locator["creation_receipt"]["identity"],
                creation_receipt["identity"],
            )
            namespace = locator["namespace_observations"][prepared_path.name]
            self.assertEqual(namespace["status"], "present")
            self.assertTrue(namespace["identity_matches_creation_receipt"])

    def test_retention_evidence_failure_preserves_source_error_and_temp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            destination = root / "merged.sqlite"
            self._create_db(source, value="validated")
            revalidation_calls = 0
            prepared_path: Path | None = None

            with MODULE._bind_source_store(source) as source_store:

                def revalidate_source() -> None:
                    nonlocal revalidation_calls, prepared_path
                    revalidation_calls += 1
                    if revalidation_calls != 2:
                        return
                    prepared_path = next(root.glob(".merged.sqlite.tmp-*"))
                    raise MODULE.StoreSafetyError(
                        "source-content-mismatch",
                        "simulated second source revalidation failure",
                    )

                def backup_source(
                    output: Path,
                    destination_binding: MODULE._BoundDirectory | None,
                ) -> dict[str, object]:
                    return MODULE._backup_sqlite_to_standalone(
                        source_store,
                        output,
                        destination_binding=destination_binding,
                    )

                with (
                    mock.patch.object(
                        MODULE,
                        "_retained_rebound_regular_file_details",
                        side_effect=OSError(
                            MODULE.errno.EIO,
                            "simulated retention evidence failure",
                        ),
                    ),
                    mock.patch.object(
                        MODULE.os,
                        "unlink",
                        wraps=MODULE.os.unlink,
                    ) as unlink,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE._recover_validated_clone_to_standalone(
                        source,
                        destination,
                        source_db=source,
                        recovery_evidence={},
                        source_integrity={"result": "ok"},
                        source_revalidate=revalidate_source,
                        source_backup=backup_source,
                    )
                self.assertFalse(
                    any(
                        ".merged.sqlite.tmp-" in os.fspath(call.args[0])
                        for call in unlink.call_args_list
                    )
                )

            self._assert_safety_code("source-content-mismatch", raised)
            self.assertIsNotNone(prepared_path)
            assert prepared_path is not None
            self.assertTrue(prepared_path.is_file())
            self.assertFalse(destination.exists())
            details = raised.exception.details
            self.assertEqual(details["cleanup_state"], "inconclusive")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(details["cleanup_error_type"], "OSError")
            locator = details["recovery_locators"]["descriptor_bound_prepared_file"]
            self.assertEqual(locator["evidence_status"], "inconclusive")
            self.assertEqual(
                locator["retention_evidence_error_type"],
                "OSError",
            )
            self.assertEqual(
                locator["initial_bound_descriptor"]["identity"],
                MODULE._identity(prepared_path.stat()),
            )

    def test_merge_db_rejects_corrupt_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            src.write_bytes(b"not a sqlite database")
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE.merge_db(src, Path(temp_dir) / "merged.sqlite")
        self._assert_safety_code("sqlite-integrity-failed", raised)

    def test_recovery_rejects_invalid_wal_even_when_main_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / MODULE.NOTE_STORE_MAIN
            self._create_db(src)
            src.with_name(f"{src.name}-wal").write_bytes(b"invalid-wal")
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE.validate_database_recovery(src)
        self._assert_safety_code("wal-invalid", raised)

    def test_recovery_ignores_mismatched_derived_shm(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source" / MODULE.NOTE_STORE_MAIN
            source.parent.mkdir()
            conn = self._create_wal_db(source)
            copied = root / "copied"
            copied.mkdir()
            try:
                for basename in MODULE.NOTE_STORE_BASENAMES:
                    shutil.copy2(source.parent / basename, copied / basename)
            finally:
                conn.close()
            copied_shm = copied / f"{MODULE.NOTE_STORE_MAIN}-shm"
            with copied_shm.open("r+b") as handle:
                handle.write(b"\0" * 96)
            result = MODULE.validate_database_recovery(copied / MODULE.NOTE_STORE_MAIN)
        self.assertEqual(
            result["sidecars"]["shm"]["status"], "derived-rebuild-required"
        )
        self.assertEqual(result["sqlite_integrity"]["result"], "ok")

    def test_valid_duplicate_shm_headers_match_current_wal_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = source.with_name(f"{source.name}-wal").read_bytes()
                shm_payload = source.with_name(f"{source.name}-shm").read_bytes()
                result = MODULE._classify_sidecar_payloads(
                    source,
                    wal_payload=wal_payload,
                    shm_payload=shm_payload,
                )
            finally:
                connection.close()
        self.assertEqual(result["shm"]["status"], "derived-match")
        self.assertEqual(result["shm"]["valid_header_copies"], 2)
        self.assertTrue(result["shm"]["duplicate_headers_consistent"])
        self.assertEqual(result["shm"]["matching_wal_header_copies"], 2)
        self.assertEqual(result["shm"]["native_byte_order"], sys.byteorder)
        binding = result["shm"]["committed_frame_binding"]
        commit = result["wal"]["last_valid_commit_evidence"]
        self.assertEqual(binding["frame"], commit["frame"])
        self.assertEqual(
            binding["database_page_count"],
            commit["database_page_count"],
        )
        self.assertEqual(binding["frame_checksum"], commit["frame_checksum"])

    def test_foreign_endian_shm_headers_are_never_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = source.with_name(f"{source.name}-wal").read_bytes()
                native_shm = source.with_name(f"{source.name}-shm").read_bytes()
            finally:
                connection.close()
            native = MODULE._parse_shm_header_copy(native_shm, 0)
            self.assertIsNotNone(native)
            assert native is not None
            foreign_order = ">" if sys.byteorder == "little" else "<"
            foreign = bytearray(48)
            struct.pack_into(f"{foreign_order}I", foreign, 0, MODULE.WAL_VERSION)
            struct.pack_into(
                f"{foreign_order}I",
                foreign,
                8,
                native["change_counter"],
            )
            foreign[12] = int(native["initialized"])
            foreign[13] = int(native["big_end_checksum"])
            struct.pack_into(
                f"{foreign_order}H",
                foreign,
                14,
                native["raw_page_size"],
            )
            struct.pack_into(
                f"{foreign_order}2I",
                foreign,
                16,
                native["max_frame"],
                native["database_page_count"],
            )
            struct.pack_into(
                f"{foreign_order}2I",
                foreign,
                24,
                *native["frame_checksum"],
            )
            struct.pack_into(">2I", foreign, 32, *native["salt"])
            checksum = MODULE._wal_checksum(bytes(foreign[:40]), foreign_order)
            struct.pack_into(f"{foreign_order}2I", foreign, 40, *checksum)
            result = MODULE._classify_sidecar_payloads(
                source,
                wal_payload=wal_payload,
                shm_payload=bytes(foreign + foreign),
            )

        self.assertEqual(result["shm"]["status"], "derived-rebuild-required")
        self.assertEqual(result["shm"]["valid_header_copies"], 0)

    def test_unrelated_valid_shm_cannot_promote_wal_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = bytearray(
                    source.with_name(f"{source.name}-wal").read_bytes()
                )
                shm_payload = bytearray(
                    source.with_name(f"{source.name}-shm").read_bytes()
                )
            finally:
                connection.close()
            wal_payload[32 + 24] ^= 0xFF
            parsed = MODULE._parse_shm_header_copy(shm_payload, 0)
            self.assertIsNotNone(parsed)
            assert parsed is not None
            byte_order = "<" if sys.byteorder == "little" else ">"
            unrelated_checksum = [
                parsed["frame_checksum"][0] ^ 0xFFFFFFFF,
                parsed["frame_checksum"][1],
            ]
            struct.pack_into(
                f"{byte_order}2I",
                shm_payload,
                24,
                *unrelated_checksum,
            )
            checksum = MODULE._wal_checksum(bytes(shm_payload[:40]), byte_order)
            struct.pack_into(f"{byte_order}2I", shm_payload, 40, *checksum)
            shm_payload[48:96] = shm_payload[:48]
            result = MODULE._classify_sidecar_payloads(
                source,
                wal_payload=bytes(wal_payload),
                shm_payload=bytes(shm_payload),
            )

        self.assertEqual(result["shm"]["status"], "derived-rebuild-required")
        self.assertEqual(result["shm"]["valid_header_copies"], 2)
        self.assertTrue(result["shm"]["duplicate_headers_consistent"])
        self.assertEqual(result["shm"]["same_generation_header_copies"], 2)
        self.assertEqual(result["shm"]["matching_wal_header_copies"], 0)

    def test_shm_npage_must_match_its_physical_commit_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = source.with_name(f"{source.name}-wal").read_bytes()
                shm_payload = bytearray(
                    source.with_name(f"{source.name}-shm").read_bytes()
                )
            finally:
                connection.close()
            parsed = MODULE._parse_shm_header_copy(shm_payload, 0)
            self.assertIsNotNone(parsed)
            assert parsed is not None
            byte_order = "<" if sys.byteorder == "little" else ">"
            for offset in (0, 48):
                struct.pack_into(
                    f"{byte_order}I",
                    shm_payload,
                    offset + 20,
                    parsed["database_page_count"] + 1,
                )
                checksum = MODULE._wal_checksum(
                    bytes(shm_payload[offset : offset + 40]),
                    byte_order,
                )
                struct.pack_into(
                    f"{byte_order}2I",
                    shm_payload,
                    offset + 40,
                    *checksum,
                )
            result = MODULE._classify_sidecar_payloads(
                source,
                wal_payload=wal_payload,
                shm_payload=bytes(shm_payload),
            )

        self.assertEqual(result["shm"]["status"], "derived-rebuild-required")
        self.assertEqual(result["shm"]["valid_header_copies"], 2)
        self.assertTrue(result["shm"]["duplicate_headers_consistent"])
        self.assertEqual(result["shm"]["same_generation_header_copies"], 2)
        self.assertEqual(result["shm"]["matching_wal_header_copies"], 0)

    def test_corrupt_shm_checksums_cannot_prove_corrupt_wal_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = bytearray(
                    source.with_name(f"{source.name}-wal").read_bytes()
                )
                shm_payload = bytearray(
                    source.with_name(f"{source.name}-shm").read_bytes()
                )
            finally:
                connection.close()
            wal_payload[32 + 24] ^= 0xFF
            shm_payload[40] ^= 0xFF
            shm_payload[88] ^= 0xFF
            result = MODULE._classify_sidecar_payloads(
                source,
                wal_payload=bytes(wal_payload),
                shm_payload=bytes(shm_payload),
            )
        self.assertEqual(result["shm"]["status"], "derived-rebuild-required")
        self.assertEqual(result["shm"]["valid_header_copies"], 0)
        self.assertFalse(result["shm"]["duplicate_headers_consistent"])

    def test_one_torn_shm_header_copy_is_derived_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = source.with_name(f"{source.name}-wal").read_bytes()
                shm_payload = bytearray(
                    source.with_name(f"{source.name}-shm").read_bytes()
                )
            finally:
                connection.close()
            shm_payload[88] ^= 0xFF
            result = MODULE._classify_sidecar_payloads(
                source,
                wal_payload=wal_payload,
                shm_payload=bytes(shm_payload),
            )
        self.assertEqual(result["shm"]["status"], "derived-rebuild-required")
        self.assertEqual(result["shm"]["valid_header_copies"], 1)
        self.assertFalse(result["shm"]["duplicate_headers_consistent"])
        self.assertEqual(result["shm"]["same_generation_header_copies"], 0)

    def test_valid_but_torn_shm_header_copy_is_not_commit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            connection = self._create_wal_db(source)
            try:
                wal_payload = source.with_name(f"{source.name}-wal").read_bytes()
                shm_payload = bytearray(
                    source.with_name(f"{source.name}-shm").read_bytes()
                )
            finally:
                connection.close()
            second = MODULE._parse_shm_header_copy(shm_payload, 48)
            self.assertIsNotNone(second)
            assert second is not None
            byte_order = "<" if second["byte_order"] == "little" else ">"
            struct.pack_into(
                f"{byte_order}I",
                shm_payload,
                48 + 16,
                second["max_frame"] + 100,
            )
            checksum = MODULE._wal_checksum(
                bytes(shm_payload[48:88]),
                byte_order,
            )
            struct.pack_into(f"{byte_order}2I", shm_payload, 88, *checksum)
            result = MODULE._classify_sidecar_payloads(
                source,
                wal_payload=wal_payload,
                shm_payload=bytes(shm_payload),
            )
        self.assertEqual(result["shm"]["status"], "derived-rebuild-required")
        self.assertEqual(result["shm"]["valid_header_copies"], 2)
        self.assertFalse(result["shm"]["duplicate_headers_consistent"])
        self.assertEqual(result["shm"]["same_generation_header_copies"], 0)

    def test_recovery_rejects_checksum_corruption_advertised_by_shm(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source" / MODULE.NOTE_STORE_MAIN
            source.parent.mkdir()
            conn = self._create_wal_db(source)
            copied = root / "copied"
            copied.mkdir()
            try:
                for basename in MODULE.NOTE_STORE_BASENAMES:
                    shutil.copy2(source.parent / basename, copied / basename)
            finally:
                conn.close()
            copied_wal = copied / f"{MODULE.NOTE_STORE_MAIN}-wal"
            with copied_wal.open("r+b") as handle:
                handle.seek(32 + 24)
                original = handle.read(1)
                handle.seek(32 + 24)
                handle.write(bytes([original[0] ^ 0xFF]))
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE.validate_database_recovery(copied / MODULE.NOTE_STORE_MAIN)
        self._assert_safety_code("wal-shm-commit-mismatch", raised)

    def test_validate_snapshot_detects_copy_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            copied_db = (
                Path(snapshot["dest"])
                / "group.com.apple.notes"
                / MODULE.NOTE_STORE_MAIN
            )
            with copied_db.open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                self._validate_snapshot(Path(snapshot["dest"]))
        self._assert_safety_code("snapshot-content-mismatch", raised)

    def test_snapshot_manifest_rejects_non_string_basenames_across_api_and_cli(
        self,
    ) -> None:
        malformed_basenames = (
            ("list", []),
            ("object", {}),
            ("null", None),
            ("bool", True),
        )
        for label, malformed_basename in malformed_basenames:
            with self.subTest(kind=label):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    self._create_db(
                        paths.group_container / MODULE.NOTE_STORE_MAIN,
                    )
                    with mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ):
                        snapshot = self._copy_db(
                            paths,
                            dest=root / "snapshot",
                            require_notes_quit=True,
                        )
                    snapshot_dir = Path(snapshot["dest"])
                    manifest_path = snapshot_dir / MODULE.SNAPSHOT_MANIFEST
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["files"][0]["basename"] = malformed_basename
                    manifest_path.write_text(
                        json.dumps(manifest),
                        encoding="utf-8",
                    )
                    receipt = self._reanchor_manifest_for_test(
                        snapshot_dir,
                        artifact_kind="snapshot",
                    )

                    with self.assertRaises(MODULE.StoreSafetyError) as api_raised:
                        MODULE.validate_snapshot(snapshot_dir, receipt)
                    self._assert_safety_code("manifest-invalid", api_raised)

                    receipt_file = root / "snapshot-receipt.json"
                    receipt_file.write_text(
                        json.dumps(receipt),
                        encoding="utf-8",
                    )
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        return_code = MODULE.main(
                            [
                                "validate-snapshot",
                                "--snapshot-dir",
                                str(snapshot_dir),
                                "--manifest-creation-receipt-file",
                                str(receipt_file),
                            ]
                        )
                    cli_payload = json.loads(stdout.getvalue())

                self.assertEqual(return_code, 1)
                self.assertEqual(cli_payload["error_code"], "manifest-invalid")

    def test_bounded_manifest_json_failures_are_manifest_invalid(self) -> None:
        bounded_payloads = {
            "oversized-integer": (
                b'{"schema":"'
                + MODULE.PATCH_SCHEMA.encode("ascii")
                + b'","value":'
                + b"9" * (MODULE.MANIFEST_JSON_MAX_INTEGER_DIGITS + 1)
                + b"}"
            ),
            "excessive-depth": (
                b'{"schema":"'
                + MODULE.PATCH_SCHEMA.encode("ascii")
                + b'","value":'
                + b"[" * (MODULE.MANIFEST_JSON_MAX_DEPTH + 1)
                + b"0"
                + b"]" * (MODULE.MANIFEST_JSON_MAX_DEPTH + 1)
                + b"}"
            ),
        }
        for label, payload in bounded_payloads.items():
            with self.subTest(boundary=label):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    edited = root / "edited.sqlite"
                    self._create_db(edited)
                    stage_dir = Path(
                        self._stage_patch(edited, root / "stage")["stage_dir"]
                    )
                    manifest_path = stage_dir / MODULE.PATCH_MANIFEST
                    manifest_path.write_bytes(payload)
                    receipt = self._reanchor_manifest_for_test(
                        stage_dir,
                        artifact_kind="patch-stage",
                    )
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        MODULE.validate_patch_stage(stage_dir, receipt)
                    self._assert_safety_code("manifest-invalid", raised)

        with (
            mock.patch.object(
                MODULE,
                "_bounded_json_loads",
                side_effect=RecursionError("simulated decoder recursion"),
            ),
            self.assertRaises(MODULE.StoreSafetyError) as raised,
        ):
            MODULE._parse_manifest_bytes(
                json.dumps({"schema": MODULE.PATCH_SCHEMA}).encode("utf-8"),
                path=Path("/bounded/manifest.json"),
                expected_schema=MODULE.PATCH_SCHEMA,
            )
        self._assert_safety_code("manifest-invalid", raised)

    def test_bounded_external_receipt_json_failures_are_receipt_invalid(
        self,
    ) -> None:
        bounded_payloads = {
            "oversized-integer": (
                b'{"value":'
                + b"9" * (MODULE.MANIFEST_JSON_MAX_INTEGER_DIGITS + 1)
                + b"}"
            ),
            "excessive-depth": (
                b'{"value":'
                + b"[" * (MODULE.MANIFEST_JSON_MAX_DEPTH + 1)
                + b"0"
                + b"]" * (MODULE.MANIFEST_JSON_MAX_DEPTH + 1)
                + b"}"
            ),
        }
        for label, payload in bounded_payloads.items():
            with self.subTest(boundary=label):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    edited = root / "edited.sqlite"
                    self._create_db(edited)
                    stage_dir = Path(
                        self._stage_patch(edited, root / "stage")["stage_dir"]
                    )
                    receipt_file = root / "creation-receipt.json"
                    receipt_file.write_bytes(payload)
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        MODULE.validate_patch_stage(
                            stage_dir,
                            manifest_creation_receipt_file=receipt_file,
                        )
                    self._assert_safety_code(
                        "manifest-creation-receipt-invalid",
                        raised,
                    )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = self._stage_patch(edited, root / "stage")
            stage_dir = Path(stage["stage_dir"])
            receipt_file = root / "creation-receipt.json"
            receipt_file.write_text(
                json.dumps(stage["manifest_creation_receipt"]),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    MODULE,
                    "_bounded_json_loads",
                    side_effect=RecursionError("simulated decoder recursion"),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.validate_patch_stage(
                    stage_dir,
                    manifest_creation_receipt_file=receipt_file,
                )
        self._assert_safety_code(
            "manifest-creation-receipt-invalid",
            raised,
        )

    def test_creators_return_exact_external_manifest_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = self._stage_patch(edited, root / "stage")

            for result, artifact_kind, artifact_schema, manifest_name in (
                (
                    snapshot,
                    "snapshot",
                    MODULE.SNAPSHOT_SCHEMA,
                    MODULE.SNAPSHOT_MANIFEST,
                ),
                (
                    stage,
                    "patch-stage",
                    MODULE.PATCH_SCHEMA,
                    MODULE.PATCH_MANIFEST,
                ),
            ):
                with self.subTest(artifact_kind=artifact_kind):
                    receipt = result["manifest_creation_receipt"]
                    self.assertEqual(
                        set(receipt),
                        {
                            "schema",
                            "artifact_kind",
                            "artifact_schema",
                            "manifest_name",
                            "manifest",
                        },
                    )
                    self.assertEqual(
                        receipt["schema"],
                        MODULE.MANIFEST_CREATION_RECEIPT_SCHEMA,
                    )
                    self.assertEqual(receipt["artifact_kind"], artifact_kind)
                    self.assertEqual(receipt["artifact_schema"], artifact_schema)
                    self.assertEqual(receipt["manifest_name"], manifest_name)
                    self.assertEqual(
                        set(receipt["manifest"]),
                        {
                            "sha256",
                            "size",
                            "identity",
                            "access_policy",
                        },
                    )
                    self.assertNotIn(
                        ".partial-",
                        json.dumps(receipt, sort_keys=True),
                    )

    def test_manifest_receipt_is_required_before_manifest_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = self._stage_patch(edited, root / "stage")
            targets = (
                (
                    Path(snapshot["dest"]) / MODULE.SNAPSHOT_MANIFEST,
                    lambda: MODULE.validate_snapshot(Path(snapshot["dest"])),
                ),
                (
                    Path(stage["stage_dir"]) / MODULE.PATCH_MANIFEST,
                    lambda: MODULE.validate_patch_stage(Path(stage["stage_dir"])),
                ),
            )
            for manifest_path, validate in targets:
                with self.subTest(manifest=manifest_path.name):
                    manifest_path.write_bytes(b"not-json")
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        validate()
                    self._assert_safety_code(
                        "manifest-creation-receipt-required",
                        raised,
                    )

    def test_external_receipt_schema_and_file_failures_use_receipt_codes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])

            malformed = json.loads(json.dumps(snapshot["manifest_creation_receipt"]))
            malformed["manifest"]["identity"]["device"] = False
            with self.assertRaises(MODULE.StoreSafetyError) as malformed_raised:
                MODULE.validate_snapshot(snapshot_dir, malformed)
            self._assert_safety_code(
                "manifest-creation-receipt-invalid",
                malformed_raised,
            )

            receipt_target = root / "receipt-target.json"
            receipt_target.write_text(
                json.dumps(snapshot, default=str),
                encoding="utf-8",
            )

            def load_receipt(path: Path) -> dict[str, object]:
                with MODULE._bind_existing_directory(snapshot_dir) as artifact_root:
                    return MODULE._load_external_manifest_creation_receipt(
                        path,
                        artifact_root=artifact_root,
                        artifact_kind="snapshot",
                        artifact_schema=MODULE.SNAPSHOT_SCHEMA,
                        manifest_name=MODULE.SNAPSHOT_MANIFEST,
                    )

            receipt_link = root / "receipt-link.json"
            receipt_link.symlink_to(receipt_target.name)
            with self.assertRaises(MODULE.StoreSafetyError) as symlink_raised:
                load_receipt(receipt_link)
            self._assert_safety_code(
                "manifest-creation-receipt-file-identity-mismatch",
                symlink_raised,
            )

            original_stat = MODULE.os.stat

            def fail_receipt_stat(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if (
                    path == receipt_target.name
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    raise OSError(errno.EIO, "simulated receipt stat failure")
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE.os,
                    "stat",
                    side_effect=fail_receipt_stat,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as stat_raised,
            ):
                load_receipt(receipt_target)
            self._assert_safety_code(
                "manifest-creation-receipt-file-revalidation-inconclusive",
                stat_raised,
            )

    def test_external_receipt_parent_failures_use_receipt_taxonomy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            receipt_parent = root / "receipts"
            receipt_parent.mkdir()
            receipt_file = receipt_parent / "creation.json"
            receipt_file.write_text(
                json.dumps(snapshot["manifest_creation_receipt"]),
                encoding="utf-8",
            )

            def load_receipt(path: Path) -> dict[str, object]:
                with MODULE._bind_existing_directory(snapshot_dir) as artifact_root:
                    return MODULE._load_external_manifest_creation_receipt(
                        path,
                        artifact_root=artifact_root,
                        artifact_kind="snapshot",
                        artifact_schema=MODULE.SNAPSHOT_SCHEMA,
                        manifest_name=MODULE.SNAPSHOT_MANIFEST,
                    )

            with self.assertRaises(MODULE.StoreSafetyError) as missing_raised:
                load_receipt(root / "missing-parent" / "creation.json")
            self._assert_safety_code(
                "manifest-creation-receipt-missing",
                missing_raised,
            )

            receipt_alias = root / "receipt-parent-alias"
            receipt_alias.symlink_to(receipt_parent, target_is_directory=True)
            with self.assertRaises(MODULE.StoreSafetyError) as symlink_raised:
                load_receipt(receipt_alias / receipt_file.name)
            self._assert_safety_code(
                "manifest-creation-receipt-scope-inconclusive",
                symlink_raised,
            )

            original_open = MODULE.os.open

            def reject_receipt_parent_open(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> int:
                if path == receipt_parent.name and kwargs.get("dir_fd") is not None:
                    raise PermissionError(
                        errno.EACCES,
                        "simulated receipt-parent denial",
                    )
                return original_open(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=reject_receipt_parent_open,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as unreadable_raised,
            ):
                load_receipt(receipt_file)
            self._assert_safety_code(
                "manifest-creation-receipt-unreadable",
                unreadable_raised,
            )

            def fail_receipt_parent_open(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> int:
                if path == receipt_parent.name and kwargs.get("dir_fd") is not None:
                    raise OSError(
                        errno.EIO,
                        "simulated receipt-parent open failure",
                    )
                return original_open(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=fail_receipt_parent_open,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as open_raised,
            ):
                load_receipt(receipt_file)
            self._assert_safety_code(
                "manifest-creation-receipt-scope-inconclusive",
                open_raised,
            )

            original_verify_directory = MODULE._verify_bound_directory_at

            def fail_receipt_parent_revalidation(
                *args: object,
                **kwargs: object,
            ) -> dict[str, object]:
                if kwargs.get("display_path") == receipt_parent:
                    raise MODULE.StoreSafetyError(
                        "prepared-directory-identity-mismatch",
                        "simulated receipt-parent revalidation failure",
                    )
                return original_verify_directory(*args, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_verify_bound_directory_at",
                    side_effect=fail_receipt_parent_revalidation,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as revalidation_raised,
            ):
                load_receipt(receipt_file)
            self._assert_safety_code(
                "manifest-creation-receipt-scope-inconclusive",
                revalidation_raised,
            )

    def test_external_receipt_rejects_joint_database_and_manifest_rewrite(
        self,
    ) -> None:
        for artifact_kind in ("snapshot", "patch-stage"):
            with self.subTest(artifact_kind=artifact_kind):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    replacement = root / "replacement.sqlite"
                    self._create_db(replacement, value="attacker")
                    if artifact_kind == "snapshot":
                        paths = self._make_paths(root)
                        self._create_db(
                            paths.group_container / MODULE.NOTE_STORE_MAIN,
                            value="original",
                        )
                        with mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ):
                            result = self._copy_db(
                                paths,
                                dest=root / "snapshot",
                                require_notes_quit=True,
                            )
                        artifact_dir = Path(result["dest"])
                        database = (
                            artifact_dir
                            / "group.com.apple.notes"
                            / MODULE.NOTE_STORE_MAIN
                        )
                        manifest_path = artifact_dir / MODULE.SNAPSHOT_MANIFEST
                    else:
                        edited = root / "edited.sqlite"
                        self._create_db(edited, value="original")
                        result = self._stage_patch(edited, root / "stage")
                        artifact_dir = Path(result["stage_dir"])
                        database = artifact_dir / MODULE.NOTE_STORE_MAIN
                        manifest_path = artifact_dir / MODULE.PATCH_MANIFEST

                    os.replace(replacement, database)
                    database_bytes = database.read_bytes()
                    observed = os.stat(database, follow_symlinks=False)
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if artifact_kind == "snapshot":
                        row = next(
                            item
                            for item in manifest["files"]
                            if item["basename"] == MODULE.NOTE_STORE_MAIN
                        )
                        row["sha256"] = hashlib.sha256(database_bytes).hexdigest()
                        row["size"] = len(database_bytes)
                        row["copy"] = {
                            "identity": MODULE._identity(observed),
                            "access_policy": MODULE._access_policy(observed),
                        }
                    else:
                        manifest["database"].update(
                            {
                                "sha256": hashlib.sha256(database_bytes).hexdigest(),
                                "size": len(database_bytes),
                                "identity": MODULE._identity(observed),
                                "access_policy": MODULE._access_policy(observed),
                            }
                        )
                    manifest_path.write_text(
                        json.dumps(manifest),
                        encoding="utf-8",
                    )

                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        if artifact_kind == "snapshot":
                            self._validate_snapshot(artifact_dir)
                        else:
                            self._validate_patch_stage(artifact_dir)
                    self._assert_safety_code(
                        "manifest-creation-receipt-content-mismatch",
                        raised,
                    )

    def test_external_receipt_protects_manifest_identity_and_access_policy(
        self,
    ) -> None:
        cases = (
            (
                "identity",
                "manifest-creation-receipt-identity-mismatch",
            ),
            (
                "access-policy",
                "manifest-creation-receipt-access-policy-mismatch",
            ),
        )
        for attack, expected_code in cases:
            with self.subTest(attack=attack):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    edited = root / "edited.sqlite"
                    self._create_db(edited)
                    stage = self._stage_patch(edited, root / "stage")
                    stage_dir = Path(stage["stage_dir"])
                    manifest = stage_dir / MODULE.PATCH_MANIFEST
                    if attack == "identity":
                        replacement = root / "replacement-manifest.json"
                        shutil.copy2(manifest, replacement)
                        os.replace(replacement, manifest)
                    else:
                        current_mode = stat.S_IMODE(manifest.stat().st_mode)
                        manifest.chmod(0o640 if current_mode != 0o640 else 0o600)
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        self._validate_patch_stage(stage_dir)
                    self._assert_safety_code(expected_code, raised)

    def test_preflight_rejects_manifest_source_evidence_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="original")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="edited")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                backup = self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, root / "stage")
                replacement = root / "new-live.sqlite"
                self._create_db(replacement, value="changed-live")
                os.replace(replacement, live)
                current = MODULE.fingerprint_note_store(paths)["files"][0]
                manifest_path = Path(backup["manifest"])
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                source = next(
                    row["source"]
                    for row in manifest["files"]
                    if row["basename"] == MODULE.NOTE_STORE_MAIN
                )
                for field in (
                    "sha256",
                    "size",
                    "identity",
                    "access_policy",
                ):
                    source[field] = current[field]
                manifest_path.write_text(
                    json.dumps(manifest),
                    encoding="utf-8",
                )

                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._preflight_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
            self._assert_safety_code(
                "manifest-creation-receipt-content-mismatch",
                raised,
            )

    def test_cli_loads_full_creator_results_only_from_outside_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            external_receipt = root / "snapshot-creation-result.json"
            external_receipt.write_text(
                json.dumps(snapshot, default=str),
                encoding="utf-8",
            )
            success = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(SCRIPT_PATH),
                    "validate-snapshot",
                    "--snapshot-dir",
                    str(snapshot_dir),
                    "--manifest-creation-receipt-file",
                    str(external_receipt),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(
                json.loads(success.stdout)["sqlite_validation"]["result"],
                "ok",
            )

            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = self._stage_patch(edited, root / "stage")
            stage_dir = Path(stage["stage_dir"])
            stage_receipt = root / "stage-creation-result.json"
            stage_receipt.write_text(
                json.dumps(stage, default=str),
                encoding="utf-8",
            )
            stage_success = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(SCRIPT_PATH),
                    "validate-patch-stage",
                    "--stage-dir",
                    str(stage_dir),
                    "--manifest-creation-receipt-file",
                    str(stage_receipt),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                stage_success.returncode,
                0,
                stage_success.stderr,
            )
            self.assertEqual(
                json.loads(stage_success.stdout)["sqlite_validation"]["result"],
                "ok",
            )

            internal_receipt = snapshot_dir / "creation-result.json"
            internal_receipt.write_text(
                json.dumps(snapshot, default=str),
                encoding="utf-8",
            )
            failure = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(SCRIPT_PATH),
                    "validate-snapshot",
                    "--snapshot-dir",
                    str(snapshot_dir),
                    "--manifest-creation-receipt-file",
                    str(internal_receipt),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(failure.returncode, 1, failure.stderr)
            self.assertEqual(
                json.loads(failure.stdout)["error_code"],
                "manifest-creation-receipt-not-external",
            )

    def test_relative_snapshot_paths_work_across_api_and_cli_boundaries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
                stage = self._stage_patch(edited, root / "stage")
            snapshot_receipt_file = root / "snapshot-result.json"
            snapshot_receipt_file.write_text(
                json.dumps(snapshot, default=str),
                encoding="utf-8",
            )
            stage_receipt_file = root / "stage-result.json"
            stage_receipt_file.write_text(
                json.dumps(stage, default=str),
                encoding="utf-8",
            )

            previous_cwd = Path.cwd()
            try:
                os.chdir(root)
                canonical_cwd = Path.cwd()

                validation = MODULE.validate_snapshot(
                    Path("snapshot"),
                    snapshot["manifest_creation_receipt"],
                )
                self.assertEqual(
                    Path(validation["snapshot_dir"]),
                    canonical_cwd / "snapshot",
                )
                recovered = MODULE.recover_snapshot(
                    Path("snapshot"),
                    Path("api-recovered.sqlite"),
                    snapshot["manifest_creation_receipt"],
                    paths=paths,
                )
                self.assertEqual(
                    Path(recovered["recovered"]["standalone_db"]),
                    canonical_cwd / "api-recovered.sqlite",
                )
                with mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    return_value=False,
                ):
                    preflight = MODULE.preflight_writeback(
                        paths,
                        backup_dir=Path("snapshot"),
                        stage_dir=Path("stage"),
                        backup_manifest_creation_receipt=(
                            snapshot["manifest_creation_receipt"]
                        ),
                        stage_manifest_creation_receipt=(
                            stage["manifest_creation_receipt"]
                        ),
                    )
                self.assertEqual(
                    Path(preflight["backup_dir"]),
                    canonical_cwd / "snapshot",
                )
                self.assertEqual(
                    Path(preflight["stage_dir"]),
                    canonical_cwd / "stage",
                )

                def run_cli(arguments: list[str]) -> tuple[int, dict[str, object]]:
                    output = io.StringIO()
                    with (
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        redirect_stdout(output),
                    ):
                        returncode = MODULE.main(arguments)
                    return returncode, json.loads(output.getvalue())

                common_paths = [
                    "--group-container",
                    str(paths.group_container),
                    "--app-container",
                    str(paths.app_container),
                ]
                cli_cases = (
                    [
                        "validate-snapshot",
                        "--snapshot-dir",
                        "snapshot",
                        "--manifest-creation-receipt-file",
                        "snapshot-result.json",
                    ],
                    [
                        "recover-snapshot",
                        *common_paths,
                        "--snapshot-dir",
                        "snapshot",
                        "--out",
                        "cli-recovered.sqlite",
                        "--manifest-creation-receipt-file",
                        "snapshot-result.json",
                    ],
                    [
                        "preflight-writeback",
                        *common_paths,
                        "--backup-dir",
                        "snapshot",
                        "--stage-dir",
                        "stage",
                        "--backup-manifest-creation-receipt-file",
                        "snapshot-result.json",
                        "--stage-manifest-creation-receipt-file",
                        "stage-result.json",
                    ],
                )
                for arguments in cli_cases:
                    with self.subTest(command=arguments[0]):
                        returncode, payload = run_cli(arguments)
                        self.assertEqual(returncode, 0, payload)

                replacement = root / "replacement.sqlite"
                shutil.copyfile(root / "stage" / MODULE.NOTE_STORE_MAIN, replacement)
                replacement.chmod(stat.S_IMODE(live.stat().st_mode))
                os.replace(replacement, live)
                with mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    return_value=False,
                ):
                    verified = MODULE.verify_writeback(
                        paths,
                        backup_dir=Path("snapshot"),
                        stage_dir=Path("stage"),
                        backup_manifest_creation_receipt=(
                            snapshot["manifest_creation_receipt"]
                        ),
                        stage_manifest_creation_receipt=(
                            stage["manifest_creation_receipt"]
                        ),
                    )
                self.assertTrue(verified["writeback_verified"])
                returncode, payload = run_cli(
                    [
                        "verify-writeback",
                        *common_paths,
                        "--backup-dir",
                        "snapshot",
                        "--stage-dir",
                        "stage",
                        "--backup-manifest-creation-receipt-file",
                        "snapshot-result.json",
                        "--stage-manifest-creation-receipt-file",
                        "stage-result.json",
                    ]
                )
                self.assertEqual(returncode, 0, payload)
                self.assertTrue(payload["writeback_verified"])

                snapshot_alias = root / "snapshot-alias"
                snapshot_alias.symlink_to("snapshot", target_is_directory=True)
                with self.assertRaises(MODULE.StoreSafetyError) as alias_raised:
                    MODULE.validate_snapshot(
                        Path("snapshot-alias"),
                        snapshot["manifest_creation_receipt"],
                    )
                self._assert_safety_code(
                    "directory-identity-mismatch",
                    alias_raised,
                )

                original_receipt = MODULE._manifest_creation_receipt_for_bound_artifact
                parked = root / "snapshot-parked"
                replacement_snapshot = root / "snapshot-replacement"
                swapped = False

                def replace_snapshot_after_binding(
                    *args: object,
                    **kwargs: object,
                ) -> dict[str, object]:
                    nonlocal swapped
                    if not swapped:
                        swapped = True
                        shutil.copytree(root / "snapshot", replacement_snapshot)
                        (root / "snapshot").rename(parked)
                        replacement_snapshot.rename(root / "snapshot")
                    return original_receipt(*args, **kwargs)

                with (
                    mock.patch.object(
                        MODULE,
                        "_manifest_creation_receipt_for_bound_artifact",
                        side_effect=replace_snapshot_after_binding,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as replacement_raised,
                ):
                    MODULE.validate_snapshot(
                        Path("snapshot"),
                        snapshot["manifest_creation_receipt"],
                    )
                self.assertTrue(swapped)
                self.assertIn(
                    replacement_raised.exception.code,
                    {
                        "snapshot-directory-identity-mismatch",
                        "directory-identity-mismatch",
                    },
                )
            finally:
                os.chdir(previous_cwd)

    def test_multi_path_apis_freeze_one_cwd_before_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_cwd = root / "source-cwd"
            other_cwd = root / "other-cwd"
            source_cwd.mkdir()
            other_cwd.mkdir()
            for cwd, value in (
                (source_cwd, "frozen-live-source"),
                (other_cwd, "wrong-live-source"),
            ):
                (cwd / "group").mkdir()
                (cwd / "app").mkdir()
                self._create_db(
                    cwd / "group" / MODULE.NOTE_STORE_MAIN,
                    value=value,
                )
            self._create_db(
                source_cwd / "edited.sqlite",
                value="frozen-edited-source",
            )

            previous_cwd = Path.cwd()
            try:
                os.chdir(source_cwd)
                frozen_cwd = Path.cwd()
                paths = MODULE.NoteStorePaths(
                    group_container=Path("group"),
                    app_container=Path("app"),
                )

                def change_cwd_after_notes_probe(
                    *,
                    require_notes_quit: bool,
                ) -> bool:
                    self.assertTrue(require_notes_quit)
                    os.chdir(other_cwd)
                    return False

                with (
                    mock.patch.object(
                        MODULE,
                        "_preflight_copy_notes_state",
                        side_effect=change_cwd_after_notes_probe,
                    ),
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                ):
                    snapshot = self._copy_db(
                        paths,
                        dest=Path("snapshot"),
                        require_notes_quit=True,
                    )
                self.assertEqual(Path(snapshot["dest"]), frozen_cwd / "snapshot")
                self.assertFalse((other_cwd / "snapshot").exists())

                os.chdir(source_cwd)
                stage = self._stage_patch(
                    Path("edited.sqlite"),
                    Path("stage"),
                    paths=paths,
                )
                snapshot_receipt_file = source_cwd / "snapshot-result.json"
                snapshot_receipt_file.write_text(
                    json.dumps(snapshot, default=str),
                    encoding="utf-8",
                )
                stage_receipt_file = source_cwd / "stage-result.json"
                stage_receipt_file.write_text(
                    json.dumps(stage, default=str),
                    encoding="utf-8",
                )

                original_snapshot_paths = MODULE._snapshot_artifact_paths

                def change_cwd_after_snapshot_paths(
                    *args: object,
                    **kwargs: object,
                ) -> MODULE._SnapshotArtifactPaths:
                    artifact_paths = original_snapshot_paths(*args, **kwargs)
                    os.chdir(other_cwd)
                    return artifact_paths

                original_patch_paths = MODULE._patch_artifact_paths

                def change_cwd_after_patch_paths(
                    *args: object,
                    **kwargs: object,
                ) -> MODULE._PatchArtifactPaths:
                    artifact_paths = original_patch_paths(*args, **kwargs)
                    os.chdir(other_cwd)
                    return artifact_paths

                os.chdir(source_cwd)
                with mock.patch.object(
                    MODULE,
                    "_snapshot_artifact_paths",
                    side_effect=change_cwd_after_snapshot_paths,
                ):
                    validation = MODULE.validate_snapshot(
                        Path("snapshot"),
                        manifest_creation_receipt_file=Path("snapshot-result.json"),
                    )
                self.assertEqual(
                    Path(validation["snapshot_dir"]),
                    frozen_cwd / "snapshot",
                )

                os.chdir(source_cwd)
                with mock.patch.object(
                    MODULE,
                    "_snapshot_artifact_paths",
                    side_effect=change_cwd_after_snapshot_paths,
                ):
                    recovered = MODULE.recover_snapshot(
                        Path("snapshot"),
                        Path("recovered.sqlite"),
                        manifest_creation_receipt_file=Path("snapshot-result.json"),
                        paths=paths,
                    )
                recovered_db = frozen_cwd / "recovered.sqlite"
                self.assertEqual(
                    Path(recovered["recovered"]["standalone_db"]),
                    recovered_db,
                )
                self.assertFalse((other_cwd / "recovered.sqlite").exists())
                with closing(sqlite3.connect(recovered_db)) as connection:
                    self.assertEqual(
                        connection.execute("SELECT value FROM sample").fetchone()[0],
                        "frozen-live-source",
                    )

                os.chdir(source_cwd)
                with mock.patch.object(
                    MODULE,
                    "_patch_artifact_paths",
                    side_effect=change_cwd_after_patch_paths,
                ):
                    stage_validation = MODULE.validate_patch_stage(
                        Path("stage"),
                        manifest_creation_receipt_file=Path("stage-result.json"),
                    )
                self.assertEqual(
                    Path(stage_validation["stage_dir"]),
                    frozen_cwd / "stage",
                )

                os.chdir(source_cwd)
                with (
                    mock.patch.object(
                        MODULE,
                        "_snapshot_artifact_paths",
                        side_effect=change_cwd_after_snapshot_paths,
                    ),
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                ):
                    preflight = MODULE.preflight_writeback(
                        paths,
                        backup_dir=Path("snapshot"),
                        stage_dir=Path("stage"),
                        backup_manifest_creation_receipt_file=Path(
                            "snapshot-result.json"
                        ),
                        stage_manifest_creation_receipt_file=Path("stage-result.json"),
                    )
                self.assertEqual(
                    Path(preflight["backup_dir"]),
                    frozen_cwd / "snapshot",
                )
                self.assertEqual(
                    Path(preflight["stage_dir"]),
                    frozen_cwd / "stage",
                )
                self.assertEqual(
                    Path(preflight["live_source_root"]),
                    frozen_cwd / "group",
                )

                replacement = source_cwd / "replacement.sqlite"
                shutil.copyfile(
                    source_cwd / "stage" / MODULE.NOTE_STORE_MAIN,
                    replacement,
                )
                live = source_cwd / "group" / MODULE.NOTE_STORE_MAIN
                replacement.chmod(stat.S_IMODE(live.stat().st_mode))
                os.replace(replacement, live)

                os.chdir(source_cwd)
                with (
                    mock.patch.object(
                        MODULE,
                        "_snapshot_artifact_paths",
                        side_effect=change_cwd_after_snapshot_paths,
                    ),
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                ):
                    verified = MODULE.verify_writeback(
                        paths,
                        backup_dir=Path("snapshot"),
                        stage_dir=Path("stage"),
                        backup_manifest_creation_receipt_file=Path(
                            "snapshot-result.json"
                        ),
                        stage_manifest_creation_receipt_file=Path("stage-result.json"),
                    )
                self.assertTrue(verified["writeback_verified"])
                self.assertEqual(
                    Path(verified["backup_dir"]),
                    frozen_cwd / "snapshot",
                )
                self.assertEqual(
                    Path(verified["stage_dir"]),
                    frozen_cwd / "stage",
                )
            finally:
                os.chdir(previous_cwd)

    def test_multi_path_cli_commands_freeze_cwd_before_argument_callbacks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_cwd = root / "source-cwd"
            other_cwd = root / "other-cwd"
            source_cwd.mkdir()
            other_cwd.mkdir()
            for cwd, value in (
                (source_cwd, "frozen-live-source"),
                (other_cwd, "wrong-live-source"),
            ):
                (cwd / "group").mkdir()
                (cwd / "app").mkdir()
                self._create_db(
                    cwd / "group" / MODULE.NOTE_STORE_MAIN,
                    value=value,
                )
            self._create_db(
                source_cwd / "edited.sqlite",
                value="frozen-edited-source",
            )

            previous_cwd = Path.cwd()
            try:
                os.chdir(source_cwd)
                frozen_cwd = Path.cwd()
                paths = MODULE.NoteStorePaths(
                    group_container=Path("group"),
                    app_container=Path("app"),
                )
                with mock.patch.object(
                    MODULE,
                    "notes_is_running",
                    return_value=False,
                ):
                    snapshot = self._copy_db(
                        paths,
                        dest=Path("snapshot"),
                        require_notes_quit=True,
                    )
                    stage = self._stage_patch(
                        Path("edited.sqlite"),
                        Path("stage"),
                        paths=paths,
                    )
                (source_cwd / "snapshot-result.json").write_text(
                    json.dumps(snapshot, default=str),
                    encoding="utf-8",
                )
                (source_cwd / "stage-result.json").write_text(
                    json.dumps(stage, default=str),
                    encoding="utf-8",
                )

                real_build_parser = MODULE.build_parser

                def build_parser_with_chdir_callback() -> object:
                    parser = real_build_parser()
                    real_parse_args = parser.parse_args

                    def parse_args_and_change_cwd(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        parsed = real_parse_args(*args, **kwargs)
                        os.chdir(other_cwd)
                        return parsed

                    parser.parse_args = parse_args_and_change_cwd
                    return parser

                def run_cli(arguments: list[str]) -> tuple[int, dict[str, object]]:
                    os.chdir(source_cwd)
                    output = io.StringIO()
                    with (
                        mock.patch.object(
                            MODULE,
                            "build_parser",
                            side_effect=build_parser_with_chdir_callback,
                        ),
                        mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ),
                        redirect_stdout(output),
                    ):
                        return_code = MODULE.main(arguments)
                    return return_code, json.loads(output.getvalue())

                common_paths = [
                    "--group-container",
                    "group",
                    "--app-container",
                    "app",
                ]
                cases = (
                    (
                        [
                            "copy-db",
                            *common_paths,
                            "--dest",
                            "cli-snapshot",
                            "--result-file",
                            "cli-snapshot-result.json",
                            "--require-notes-quit",
                        ],
                        "dest",
                        frozen_cwd / "cli-snapshot",
                    ),
                    (
                        [
                            "validate-snapshot",
                            "--snapshot-dir",
                            "snapshot",
                            "--manifest-creation-receipt-file",
                            "snapshot-result.json",
                        ],
                        "snapshot_dir",
                        frozen_cwd / "snapshot",
                    ),
                    (
                        [
                            "recover-snapshot",
                            *common_paths,
                            "--snapshot-dir",
                            "snapshot",
                            "--out",
                            "cli-recovered.sqlite",
                            "--manifest-creation-receipt-file",
                            "snapshot-result.json",
                        ],
                        "snapshot_dir",
                        frozen_cwd / "snapshot",
                    ),
                    (
                        [
                            "validate-patch-stage",
                            "--stage-dir",
                            "stage",
                            "--manifest-creation-receipt-file",
                            "stage-result.json",
                        ],
                        "stage_dir",
                        frozen_cwd / "stage",
                    ),
                    (
                        [
                            "preflight-writeback",
                            *common_paths,
                            "--backup-dir",
                            "snapshot",
                            "--stage-dir",
                            "stage",
                            "--backup-manifest-creation-receipt-file",
                            "snapshot-result.json",
                            "--stage-manifest-creation-receipt-file",
                            "stage-result.json",
                        ],
                        "backup_dir",
                        frozen_cwd / "snapshot",
                    ),
                )
                for arguments, result_key, expected_path in cases:
                    with self.subTest(command=arguments[0]):
                        return_code, payload = run_cli(arguments)
                        self.assertEqual(return_code, 0, payload)
                        self.assertEqual(Path(payload[result_key]), expected_path)

                self.assertTrue((source_cwd / "cli-snapshot").is_dir())
                self.assertTrue((source_cwd / "cli-snapshot-result.json").is_file())
                self.assertFalse((other_cwd / "cli-snapshot").exists())
                self.assertFalse((other_cwd / "cli-snapshot-result.json").exists())
                copy_manifest = json.loads(
                    (source_cwd / "cli-snapshot" / MODULE.SNAPSHOT_MANIFEST).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    Path(copy_manifest["source_root"]),
                    frozen_cwd / "group",
                )
                recovered_db = source_cwd / "cli-recovered.sqlite"
                self.assertTrue(recovered_db.is_file())
                self.assertFalse((other_cwd / "cli-recovered.sqlite").exists())
                with closing(sqlite3.connect(recovered_db)) as connection:
                    self.assertEqual(
                        connection.execute("SELECT value FROM sample").fetchone()[0],
                        "frozen-live-source",
                    )

                replacement = source_cwd / "replacement.sqlite"
                shutil.copyfile(
                    source_cwd / "stage" / MODULE.NOTE_STORE_MAIN,
                    replacement,
                )
                live = source_cwd / "group" / MODULE.NOTE_STORE_MAIN
                replacement.chmod(stat.S_IMODE(live.stat().st_mode))
                os.replace(replacement, live)
                return_code, verified = run_cli(
                    [
                        "verify-writeback",
                        *common_paths,
                        "--backup-dir",
                        "snapshot",
                        "--stage-dir",
                        "stage",
                        "--backup-manifest-creation-receipt-file",
                        "snapshot-result.json",
                        "--stage-manifest-creation-receipt-file",
                        "stage-result.json",
                    ]
                )
                self.assertEqual(return_code, 0, verified)
                self.assertTrue(verified["writeback_verified"])
                self.assertEqual(
                    Path(verified["backup_dir"]),
                    frozen_cwd / "snapshot",
                )
                self.assertEqual(
                    Path(verified["stage_dir"]),
                    frozen_cwd / "stage",
                )
            finally:
                os.chdir(previous_cwd)

    def test_relative_container_paths_stay_fixed_after_preflight_cwd_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_cwd = root / "source-cwd"
            other_cwd = root / "other-cwd"
            source_cwd.mkdir()
            other_cwd.mkdir()
            (source_cwd / "group").mkdir()
            (source_cwd / "app").mkdir()
            self._create_db(
                source_cwd / "group" / MODULE.NOTE_STORE_MAIN,
                value="fixed-source",
            )
            previous_cwd = Path.cwd()
            try:
                os.chdir(source_cwd)
                canonical_source_cwd = Path.cwd()
                paths = MODULE.NoteStorePaths(
                    group_container=Path("group"),
                    app_container=Path("app"),
                )
                self.assertEqual(
                    paths.group_container,
                    canonical_source_cwd / "group",
                )
                self.assertEqual(paths.app_container, canonical_source_cwd / "app")

                api_destination = root / "api-snapshot"
                with MODULE._preflight_live_safe_destination_parent(
                    paths,
                    api_destination,
                ) as preflight:
                    os.chdir(other_cwd)
                    api_result = self._copy_db(
                        paths,
                        dest=api_destination,
                        require_notes_quit=False,
                        _destination_preflight=preflight,
                        _notes_running=False,
                    )
                api_manifest = json.loads(
                    (api_destination / MODULE.SNAPSHOT_MANIFEST).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    Path(api_manifest["source_root"]),
                    canonical_source_cwd / "group",
                )
                self.assertEqual(
                    MODULE.fingerprint_note_store(paths)["source_root"],
                    canonical_source_cwd / "group",
                )
                self.assertEqual(Path(api_result["dest"]), api_destination)

                os.chdir(source_cwd)
                cli_destination = root / "cli-snapshot"
                original_preflight = MODULE._preflight_creator_destinations

                @contextmanager
                def change_cwd_after_preflight(
                    *args: object,
                    **kwargs: object,
                ) -> Iterator[MODULE._CreatorDestinationPreflights]:
                    with original_preflight(*args, **kwargs) as preflights:
                        os.chdir(other_cwd)
                        yield preflights

                stdout = io.StringIO()
                with (
                    mock.patch.object(
                        MODULE,
                        "_preflight_creator_destinations",
                        side_effect=change_cwd_after_preflight,
                    ),
                    mock.patch.object(MODULE, "notes_is_running", return_value=False),
                    redirect_stdout(stdout),
                ):
                    return_code = MODULE.main(
                        [
                            "copy-db",
                            "--group-container",
                            "group",
                            "--app-container",
                            "app",
                            "--dest",
                            str(cli_destination),
                        ]
                    )
                cli_result = json.loads(stdout.getvalue())
                cli_manifest = json.loads(
                    (cli_destination / MODULE.SNAPSHOT_MANIFEST).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(return_code, 0, cli_result)
                self.assertEqual(
                    Path(cli_manifest["source_root"]),
                    canonical_source_cwd / "group",
                )
                self.assertEqual(
                    Path(cli_result["copied_files"][0]["source"]),
                    canonical_source_cwd / "group" / MODULE.NOTE_STORE_MAIN,
                )
            finally:
                os.chdir(previous_cwd)

    def test_stage_patch_freezes_relative_paths_before_preflight_cwd_change(
        self,
    ) -> None:
        for interface in ("api", "cli"):
            with (
                self.subTest(interface=interface),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                source_cwd = root / "source-cwd"
                other_cwd = root / "other-cwd"
                source_cwd.mkdir()
                other_cwd.mkdir()
                for cwd in (source_cwd, other_cwd):
                    (cwd / "group").mkdir()
                    (cwd / "app").mkdir()
                self._create_db(
                    source_cwd / "edited.sqlite",
                    value="frozen-edited-source",
                )
                self._create_db(
                    other_cwd / "edited.sqlite",
                    value="wrong-edited-source",
                )
                previous_cwd = Path.cwd()
                try:
                    os.chdir(source_cwd)
                    frozen_cwd = Path.cwd()
                    if interface == "api":
                        paths = MODULE.NoteStorePaths(
                            group_container=Path("group"),
                            app_container=Path("app"),
                        )
                        original_preflight = MODULE._bind_live_safe_destination_parent

                        @contextmanager
                        def change_api_cwd_after_preflight(
                            *args: object,
                            **kwargs: object,
                        ) -> Iterator[MODULE._LiveDestinationScope]:
                            with original_preflight(*args, **kwargs) as scope:
                                os.chdir(other_cwd)
                                yield scope

                        with mock.patch.object(
                            MODULE,
                            "_bind_live_safe_destination_parent",
                            side_effect=change_api_cwd_after_preflight,
                        ):
                            result = self._stage_patch(
                                Path("edited.sqlite"),
                                Path("stage"),
                                paths=paths,
                            )
                        result_file = None
                    else:
                        original_preflight = MODULE._preflight_creator_destinations

                        @contextmanager
                        def change_cli_cwd_after_preflight(
                            *args: object,
                            **kwargs: object,
                        ) -> Iterator[MODULE._CreatorDestinationPreflights]:
                            with original_preflight(*args, **kwargs) as preflights:
                                os.chdir(other_cwd)
                                yield preflights

                        stdout = io.StringIO()
                        with (
                            mock.patch.object(
                                MODULE,
                                "_preflight_creator_destinations",
                                side_effect=change_cli_cwd_after_preflight,
                            ),
                            redirect_stdout(stdout),
                        ):
                            return_code = MODULE.main(
                                [
                                    "stage-patch",
                                    "--src",
                                    "edited.sqlite",
                                    "--dest",
                                    "stage",
                                    "--result-file",
                                    "stage-result.json",
                                    "--group-container",
                                    "group",
                                    "--app-container",
                                    "app",
                                ]
                            )
                        result = json.loads(stdout.getvalue())
                        self.assertEqual(return_code, 0, result)
                        result_file = frozen_cwd / "stage-result.json"

                    stage_dir = frozen_cwd / "stage"
                    manifest = json.loads(
                        (stage_dir / MODULE.PATCH_MANIFEST).read_text(encoding="utf-8")
                    )
                    with closing(
                        sqlite3.connect(stage_dir / MODULE.NOTE_STORE_MAIN)
                    ) as connection:
                        value = connection.execute(
                            "SELECT value FROM sample"
                        ).fetchone()[0]
                    self.assertEqual(value, "frozen-edited-source")
                    self.assertEqual(
                        Path(manifest["source_db"]),
                        frozen_cwd / "edited.sqlite",
                    )
                    self.assertEqual(Path(result["stage_dir"]), stage_dir)
                    self.assertFalse((other_cwd / "stage").exists())
                    if result_file is not None:
                        persisted = json.loads(result_file.read_text(encoding="utf-8"))
                        self.assertEqual(Path(persisted["stage_dir"]), stage_dir)
                        self.assertFalse((other_cwd / "stage-result.json").exists())
                finally:
                    os.chdir(previous_cwd)

    def test_merge_db_freezes_relative_paths_before_preflight_cwd_change(
        self,
    ) -> None:
        for interface in ("api", "cli"):
            with (
                self.subTest(interface=interface),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                source_cwd = root / "source-cwd"
                other_cwd = root / "other-cwd"
                source_cwd.mkdir()
                other_cwd.mkdir()
                for cwd in (source_cwd, other_cwd):
                    (cwd / "group").mkdir()
                    (cwd / "app").mkdir()
                self._create_db(
                    source_cwd / "source.sqlite",
                    value="frozen-merge-source",
                )
                self._create_db(
                    other_cwd / "source.sqlite",
                    value="wrong-merge-source",
                )
                previous_cwd = Path.cwd()
                try:
                    os.chdir(source_cwd)
                    frozen_cwd = Path.cwd()
                    original_preflight = MODULE._bind_live_safe_destination_parent

                    @contextmanager
                    def change_cwd_after_preflight(
                        *args: object,
                        **kwargs: object,
                    ) -> Iterator[MODULE._LiveDestinationScope]:
                        with original_preflight(*args, **kwargs) as scope:
                            os.chdir(other_cwd)
                            yield scope

                    with mock.patch.object(
                        MODULE,
                        "_bind_live_safe_destination_parent",
                        side_effect=change_cwd_after_preflight,
                    ):
                        if interface == "api":
                            paths = MODULE.NoteStorePaths(
                                group_container=Path("group"),
                                app_container=Path("app"),
                            )
                            result = MODULE.merge_db(
                                Path("source.sqlite"),
                                Path("merged.sqlite"),
                                paths=paths,
                            )
                        else:
                            stdout = io.StringIO()
                            with redirect_stdout(stdout):
                                return_code = MODULE.main(
                                    [
                                        "merge-db",
                                        "--src",
                                        "source.sqlite",
                                        "--out",
                                        "merged.sqlite",
                                        "--group-container",
                                        "group",
                                        "--app-container",
                                        "app",
                                    ]
                                )
                            result = json.loads(stdout.getvalue())
                            self.assertEqual(return_code, 0, result)

                    output = frozen_cwd / "merged.sqlite"
                    with closing(sqlite3.connect(output)) as connection:
                        value = connection.execute(
                            "SELECT value FROM sample"
                        ).fetchone()[0]
                    self.assertEqual(value, "frozen-merge-source")
                    self.assertEqual(
                        Path(result["source_db"]),
                        frozen_cwd / "source.sqlite",
                    )
                    self.assertEqual(Path(result["merged_db"]), output)
                    self.assertFalse((other_cwd / "merged.sqlite").exists())
                finally:
                    os.chdir(previous_cwd)

    def test_artifact_swap_between_receipt_load_and_consumption_is_rejected(
        self,
    ) -> None:
        for artifact_kind in ("snapshot", "patch-stage"):
            with self.subTest(artifact_kind=artifact_kind):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    if artifact_kind == "snapshot":
                        paths = self._make_paths(root)
                        self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                        with mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ):
                            creator_result = self._copy_db(
                                paths,
                                dest=root / "snapshot",
                                require_notes_quit=True,
                            )
                        artifact_dir = Path(creator_result["dest"])
                    else:
                        edited = root / "edited.sqlite"
                        self._create_db(edited)
                        creator_result = self._stage_patch(
                            edited,
                            root / "stage",
                        )
                        artifact_dir = Path(creator_result["stage_dir"])

                    receipt_file = root / f"{artifact_kind}-creation-result.json"
                    receipt_file.write_text(
                        json.dumps(creator_result, default=str),
                        encoding="utf-8",
                    )
                    parked = root / f"{artifact_dir.name}-receipt-bound"
                    original_load = MODULE._load_external_manifest_creation_receipt
                    attacked = False

                    def load_then_replace_artifact(
                        *args: object,
                        **kwargs: object,
                    ) -> dict[str, object]:
                        nonlocal attacked
                        receipt = original_load(*args, **kwargs)
                        artifact_dir.rename(parked)
                        artifact_dir.mkdir(mode=0o700)
                        (artifact_dir / "attacker-marker").write_text(
                            "replacement artifact",
                            encoding="utf-8",
                        )
                        attacked = True
                        return receipt

                    with (
                        mock.patch.object(
                            MODULE,
                            "_load_external_manifest_creation_receipt",
                            side_effect=load_then_replace_artifact,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        if artifact_kind == "snapshot":
                            MODULE.validate_snapshot(
                                artifact_dir,
                                manifest_creation_receipt_file=receipt_file,
                            )
                        else:
                            MODULE.validate_patch_stage(
                                artifact_dir,
                                manifest_creation_receipt_file=receipt_file,
                            )

                    self.assertTrue(attacked)
                    self._assert_safety_code(
                        (
                            "snapshot-directory-identity-mismatch"
                            if artifact_kind == "snapshot"
                            else "stage-directory-identity-mismatch"
                        ),
                        raised,
                    )
                    self.assertTrue(parked.is_dir())
                    self.assertEqual(
                        {entry.name for entry in artifact_dir.iterdir()},
                        {"attacker-marker"},
                    )

    def test_manifest_consumer_reuses_receipt_bound_root_during_swap_restore(
        self,
    ) -> None:
        for artifact_kind in ("snapshot", "patch-stage"):
            with self.subTest(artifact_kind=artifact_kind):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    if artifact_kind == "snapshot":
                        paths = self._make_paths(root)
                        self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                        with mock.patch.object(
                            MODULE,
                            "notes_is_running",
                            return_value=False,
                        ):
                            creator_result = self._copy_db(
                                paths,
                                dest=root / "snapshot",
                                require_notes_quit=True,
                            )
                        artifact_dir = Path(creator_result["dest"])
                        manifest_name = MODULE.SNAPSHOT_MANIFEST
                    else:
                        edited = root / "edited.sqlite"
                        self._create_db(edited)
                        creator_result = self._stage_patch(
                            edited,
                            root / "stage",
                        )
                        artifact_dir = Path(creator_result["stage_dir"])
                        manifest_name = MODULE.PATCH_MANIFEST

                    receipt_file = root / f"{artifact_kind}-creation-result.json"
                    receipt_file.write_text(
                        json.dumps(creator_result, default=str),
                        encoding="utf-8",
                    )
                    parked = root / f"{artifact_dir.name}-receipt-bound"
                    original_load = MODULE._load_external_manifest_creation_receipt
                    original_bind_at = MODULE._bind_regular_file_at
                    receipt_root_id: int | None = None
                    attacked = False

                    def record_receipt_root(
                        *args: object,
                        **kwargs: object,
                    ) -> dict[str, object]:
                        nonlocal receipt_root_id
                        artifact_root = kwargs["artifact_root"]
                        receipt_root_id = id(artifact_root)
                        return original_load(*args, **kwargs)

                    @contextmanager
                    def bind_manifest_during_swap(
                        path: Path,
                        parent: MODULE._BoundDirectory,
                        codes: MODULE._FileProtectionCodes,
                    ) -> object:
                        nonlocal attacked
                        if (
                            not attacked
                            and path.name == manifest_name
                            and parent.path == artifact_dir
                        ):
                            self.assertEqual(id(parent), receipt_root_id)
                            artifact_dir.rename(parked)
                            artifact_dir.mkdir(mode=0o700)
                            restored = False
                            try:
                                with original_bind_at(
                                    path,
                                    parent,
                                    codes,
                                ) as bound:
                                    artifact_dir.rmdir()
                                    parked.rename(artifact_dir)
                                    restored = True
                                    attacked = True
                                    yield bound
                            finally:
                                if not restored:
                                    artifact_dir.rmdir()
                                    parked.rename(artifact_dir)
                            return
                        with original_bind_at(path, parent, codes) as bound:
                            yield bound

                    with (
                        mock.patch.object(
                            MODULE,
                            "_load_external_manifest_creation_receipt",
                            side_effect=record_receipt_root,
                        ),
                        mock.patch.object(
                            MODULE,
                            "_bind_regular_file_at",
                            side_effect=bind_manifest_during_swap,
                        ),
                    ):
                        if artifact_kind == "snapshot":
                            validation = MODULE.validate_snapshot(
                                artifact_dir,
                                manifest_creation_receipt_file=receipt_file,
                            )
                        else:
                            validation = MODULE.validate_patch_stage(
                                artifact_dir,
                                manifest_creation_receipt_file=receipt_file,
                            )

                    self.assertTrue(attacked)
                    self.assertEqual(
                        validation["sqlite_validation"]["result"],
                        "ok",
                    )

    def test_validate_snapshot_enforces_creation_identity_and_access_receipts(
        self,
    ) -> None:
        cases = (
            ("root-identity", "snapshot-directory-identity-mismatch"),
            ("store-identity", "snapshot-directory-identity-mismatch"),
            ("file-identity", "snapshot-file-identity-mismatch"),
            ("root-access", "snapshot-directory-access-policy-mismatch"),
            ("store-access", "snapshot-directory-access-policy-mismatch"),
            ("file-access", "snapshot-file-access-policy-mismatch"),
        )
        for attack, expected_code in cases:
            with self.subTest(attack=attack):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
                    with mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ):
                        snapshot = self._copy_db(
                            paths,
                            dest=root / "snapshot",
                            require_notes_quit=True,
                        )
                    snapshot_dir = Path(snapshot["dest"])
                    store = snapshot_dir / "group.com.apple.notes"
                    database = store / MODULE.NOTE_STORE_MAIN
                    if attack == "root-identity":
                        replacement = root / "replacement-snapshot"
                        parked = root / "original-snapshot"
                        shutil.copytree(snapshot_dir, replacement)
                        snapshot_dir.rename(parked)
                        replacement.rename(snapshot_dir)
                        self._reanchor_manifest_for_test(
                            snapshot_dir,
                            artifact_kind="snapshot",
                        )
                    elif attack == "store-identity":
                        replacement = snapshot_dir / "replacement-store"
                        parked = root / "original-store"
                        shutil.copytree(store, replacement)
                        store.rename(parked)
                        replacement.rename(store)
                    elif attack == "file-identity":
                        replacement = store / ".replacement.sqlite"
                        shutil.copy2(database, replacement)
                        os.replace(replacement, database)
                    else:
                        target = {
                            "root-access": snapshot_dir,
                            "store-access": store,
                            "file-access": database,
                        }[attack]
                        current_mode = MODULE.stat.S_IMODE(target.stat().st_mode)
                        target.chmod(0o750 if current_mode != 0o750 else 0o700)
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        self._validate_snapshot(snapshot_dir)
                    self._assert_safety_code(expected_code, raised)

    def test_validate_patch_stage_enforces_creation_identity_and_access_receipts(
        self,
    ) -> None:
        cases = (
            ("root-identity", "stage-directory-identity-mismatch"),
            ("file-identity", "patch-file-identity-mismatch"),
            ("root-access", "stage-directory-access-policy-mismatch"),
            ("file-access", "patch-file-access-policy-mismatch"),
        )
        for attack, expected_code in cases:
            with self.subTest(attack=attack):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    edited = root / "edited.sqlite"
                    self._create_db(edited)
                    stage = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
                    database = stage / MODULE.NOTE_STORE_MAIN
                    if attack == "root-identity":
                        replacement = root / "replacement-stage"
                        parked = root / "original-stage"
                        shutil.copytree(stage, replacement)
                        stage.rename(parked)
                        replacement.rename(stage)
                        self._reanchor_manifest_for_test(
                            stage,
                            artifact_kind="patch-stage",
                        )
                    elif attack == "file-identity":
                        replacement = stage / ".replacement.sqlite"
                        shutil.copy2(database, replacement)
                        os.replace(replacement, database)
                    else:
                        target = stage if attack == "root-access" else database
                        current_mode = MODULE.stat.S_IMODE(target.stat().st_mode)
                        target.chmod(0o750 if current_mode != 0o750 else 0o700)
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        self._validate_patch_stage(stage)
                    self._assert_safety_code(expected_code, raised)

    def test_patch_manifest_enforces_every_access_policy_field(self) -> None:
        for receipt_name in ("stage_directory", "database"):
            for field in ("mode", "uid", "gid", "flags"):
                with self.subTest(receipt=receipt_name, field=field):
                    with tempfile.TemporaryDirectory() as temp_dir:
                        root = Path(temp_dir)
                        edited = root / "edited.sqlite"
                        self._create_db(edited)
                        stage = Path(
                            self._stage_patch(edited, root / "stage")["stage_dir"]
                        )
                        manifest_path = stage / MODULE.PATCH_MANIFEST
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        if receipt_name == "stage_directory":
                            receipt = manifest["creation_receipts"]["stage_directory"]
                            expected_code = "stage-directory-access-policy-mismatch"
                        else:
                            receipt = manifest["database"]
                            expected_code = "patch-file-access-policy-mismatch"
                        if field == "flags":
                            receipt["access_policy"][field] ^= (
                                MODULE._DARWIN_ACCESS_POLICY_FLAG_BITS["UF_IMMUTABLE"]
                            )
                        else:
                            receipt["access_policy"][field] += 1
                        manifest_path.write_text(
                            json.dumps(manifest),
                            encoding="utf-8",
                        )
                        # This test intentionally re-anchors a modified manifest
                        # so it can exercise the nested receipt validation.
                        self._reanchor_manifest_for_test(
                            stage,
                            artifact_kind="patch-stage",
                        )
                        with self.assertRaises(MODULE.StoreSafetyError) as raised:
                            self._validate_patch_stage(stage)
                        self._assert_safety_code(expected_code, raised)

    def test_legacy_raw_benign_flags_are_normalized_in_manifests_and_receipts(
        self,
    ) -> None:
        benign_flags = (
            0x00000001  # UF_NODUMP
            | 0x00000020  # UF_COMPRESSED
            | 0x00000040  # UF_TRACKED
            | 0x00008000  # UF_HIDDEN
            | 0x40000000  # SF_DATALESS
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(self._stage_patch(edited, root / "stage")["stage_dir"])

            manifest_path = snapshot_dir / MODULE.SNAPSHOT_MANIFEST
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for receipt_name in ("snapshot_directory", "store_directory"):
                manifest["creation_receipts"][receipt_name]["access_policy"][
                    "flags"
                ] |= benign_flags
            for row in manifest["files"]:
                row["source"]["access_policy"]["flags"] |= benign_flags
                row["copy"]["access_policy"]["flags"] |= benign_flags
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            snapshot_receipt = self._reanchor_manifest_for_test(
                snapshot_dir,
                artifact_kind="snapshot",
            )
            snapshot_receipt["manifest"]["access_policy"]["flags"] |= benign_flags

            stage_receipt = self._stage_manifest_receipts[stage_dir]
            stage_receipt["manifest"]["access_policy"]["flags"] |= benign_flags

            snapshot_validation = MODULE.validate_snapshot(
                snapshot_dir,
                snapshot_receipt,
            )
            stage_validation = MODULE.validate_patch_stage(
                stage_dir,
                stage_receipt,
            )
            self.assertEqual(
                snapshot_validation["sqlite_validation"]["result"],
                "ok",
            )
            self.assertEqual(stage_validation["sqlite_validation"]["result"], "ok")

            with mock.patch.object(
                MODULE,
                "notes_is_running",
                return_value=False,
            ):
                preflight = MODULE.preflight_writeback(
                    paths,
                    backup_dir=snapshot_dir,
                    stage_dir=stage_dir,
                    backup_manifest_creation_receipt=snapshot_receipt,
                    stage_manifest_creation_receipt=stage_receipt,
                )
            self.assertEqual(preflight["live_source_root"], paths.group_container)
            self.assertTrue(preflight["ready_for_explicit_writeback"])

    def test_legacy_manifests_fail_closed_without_v3_external_receipts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    Path(snapshot["dest"]) / MODULE.SNAPSHOT_MANIFEST,
                    self._validate_snapshot,
                    Path(snapshot["dest"]),
                    "apple-notes-snapshot/v1",
                ),
                (
                    Path(snapshot["dest"]) / MODULE.SNAPSHOT_MANIFEST,
                    self._validate_snapshot,
                    Path(snapshot["dest"]),
                    "apple-notes-snapshot/v2",
                ),
                (
                    stage / MODULE.PATCH_MANIFEST,
                    self._validate_patch_stage,
                    stage,
                    "apple-notes-patch/v1",
                ),
                (
                    stage / MODULE.PATCH_MANIFEST,
                    self._validate_patch_stage,
                    stage,
                    "apple-notes-patch/v2",
                ),
            )
            for manifest_path, validator, argument, legacy_schema in targets:
                with self.subTest(manifest=manifest_path.name):
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["schema"] = legacy_schema
                    manifest.pop("creation_receipts", None)
                    manifest_path.write_text(
                        json.dumps(manifest),
                        encoding="utf-8",
                    )
                    self._reanchor_manifest_for_test(
                        argument,
                        artifact_kind=(
                            "snapshot"
                            if manifest_path.name == MODULE.SNAPSHOT_MANIFEST
                            else "patch-stage"
                        ),
                    )
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        validator(argument)
                    self._assert_safety_code(
                        "manifest-schema-mismatch",
                        raised,
                    )

    def test_exact_file_sets_reject_extra_directory(self) -> None:
        self._assert_snapshot_and_stage_reject_extra_entry("directory")

    def test_exact_file_sets_reject_extra_fifo(self) -> None:
        self._assert_snapshot_and_stage_reject_extra_entry("fifo")

    def test_exact_file_sets_reject_extra_broken_symlink(self) -> None:
        self._assert_snapshot_and_stage_reject_extra_entry("broken-symlink")

    def test_directory_mtime_only_change_does_not_fail_exact_file_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_store = snapshot_dir / "group.com.apple.notes"
            stage = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            for directory in (snapshot_store, stage):
                current = directory.stat()
                os.utime(
                    directory,
                    ns=(
                        current.st_atime_ns,
                        current.st_mtime_ns + 1_000_000_000,
                    ),
                )
            snapshot_validation = self._validate_snapshot(snapshot_dir)
            stage_validation = self._validate_patch_stage(stage)
        self.assertEqual(snapshot_validation["sqlite_validation"]["result"], "ok")
        self.assertEqual(stage_validation["sqlite_validation"]["result"], "ok")

    def test_patch_validation_detects_directory_identity_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            original_integrity = MODULE._sqlite_integrity

            def replace_after_integrity(
                path: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                result = original_integrity(path, **kwargs)
                replacement = root / "replacement-stage"
                shutil.copytree(stage, replacement)
                stage.rename(root / "original-stage")
                replacement.rename(stage)
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_sqlite_integrity",
                    side_effect=replace_after_integrity,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._validate_patch_stage(stage)
        self._assert_safety_code("stage-directory-identity-mismatch", raised)

    def test_patch_validation_detects_directory_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            stage.chmod(0o700)
            original_integrity = MODULE._sqlite_integrity

            def chmod_after_integrity(
                path: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                result = original_integrity(path, **kwargs)
                stage.chmod(0o750)
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_sqlite_integrity",
                    side_effect=chmod_after_integrity,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._validate_patch_stage(stage)
        self._assert_safety_code(
            "stage-directory-access-policy-mismatch",
            raised,
        )

    def test_stage_patch_normalizes_and_validates_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="patched")
            result = self._stage_patch(edited, root / "stage")
            stage_dir = Path(result["stage_dir"])
            self.assertEqual(
                {path.name for path in stage_dir.iterdir()},
                {MODULE.NOTE_STORE_MAIN, MODULE.PATCH_MANIFEST},
            )
            validation = self._validate_patch_stage(stage_dir)
            self.assertEqual(validation["sqlite_validation"]["result"], "ok")
            self.assertFalse(result["live_mutation_performed"])

    def test_stage_patch_creates_database_through_bound_parent_during_swap_restore(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="patched")
            original_write = MODULE._write_standalone_backup_payload
            real_open = MODULE.os.open
            attacked = False
            replacement_entries: list[str] = []

            def write_with_create_swap(
                payload: bytes,
                output: Path,
                *,
                destination_binding: MODULE._BoundDirectory | None = None,
            ) -> dict[str, object]:
                if (
                    destination_binding is None
                    or not destination_binding.path.name.startswith(".stage.partial-")
                ):
                    return original_write(
                        payload,
                        output,
                        destination_binding=destination_binding,
                    )

                def open_with_swap(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal attacked
                    if (
                        not attacked
                        and os.fspath(path) == output.name
                        and dir_fd == destination_binding.fd
                        and flags & os.O_CREAT
                    ):
                        attacked = True
                        parent = destination_binding.path
                        parked = parent.with_name(f"{parent.name}.parked")
                        parent.rename(parked)
                        parent.mkdir(mode=0o700)
                        try:
                            opened_fd = real_open(
                                path,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )
                            replacement_entries.extend(
                                child.name for child in parent.iterdir()
                            )
                            return opened_fd
                        finally:
                            shutil.rmtree(parent)
                            parked.rename(parent)
                    return real_open(
                        path,
                        flags,
                        mode,
                        dir_fd=dir_fd,
                    )

                with mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=open_with_swap,
                ):
                    return original_write(
                        payload,
                        output,
                        destination_binding=destination_binding,
                    )

            with mock.patch.object(
                MODULE,
                "_write_standalone_backup_payload",
                side_effect=write_with_create_swap,
            ):
                result = self._stage_patch(edited, root / "stage")

            self.assertTrue(attacked)
            self.assertEqual(replacement_entries, [])
            self.assertEqual(
                self._validate_patch_stage(Path(result["stage_dir"]))[
                    "sqlite_validation"
                ]["result"],
                "ok",
            )

    def test_patch_stage_rejects_new_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = root / "stage"
            self._stage_patch(edited, stage)
            (stage / f"{MODULE.NOTE_STORE_MAIN}-wal").write_bytes(b"")
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                self._validate_patch_stage(stage)
        self._assert_safety_code("patch-file-set-mismatch", raised)

    def test_validators_detect_same_byte_file_replacement_during_integrity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN,
                    self._validate_snapshot,
                    snapshot_dir,
                    "snapshot-file-identity-mismatch",
                ),
                (
                    stage_dir / MODULE.NOTE_STORE_MAIN,
                    self._validate_patch_stage,
                    stage_dir,
                    "patch-file-identity-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(target=target):
                    integrity_boundary = (
                        "_bound_recovery_integrity"
                        if expected_code.startswith("snapshot-")
                        else "_sqlite_integrity"
                    )
                    original_integrity = getattr(MODULE, integrity_boundary)
                    attacked = False

                    def replace_after_integrity(
                        database: object,
                        **kwargs: object,
                    ) -> dict[str, object]:
                        nonlocal attacked
                        result = original_integrity(database, **kwargs)
                        if not attacked:
                            attacked = True
                            replacement = target.with_name(
                                f".{target.name}.replacement"
                            )
                            shutil.copy2(target, replacement)
                            os.replace(replacement, target)
                        return result

                    with (
                        mock.patch.object(
                            MODULE,
                            integrity_boundary,
                            side_effect=replace_after_integrity,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        validator(argument)
                    self._assert_safety_code(expected_code, raised)

    def test_patch_integrity_races_preserve_patch_file_taxonomy(self) -> None:
        cases = (
            ("identity", "patch-file-identity-mismatch"),
            ("content", "patch-content-mismatch"),
            ("access-policy", "patch-file-access-policy-mismatch"),
        )
        for attack, expected_code in cases:
            with (
                self.subTest(attack=attack),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                stage_dir = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
                database = stage_dir / MODULE.NOTE_STORE_MAIN
                original_exec = MODULE._native_sqlite_exec
                attacked = False

                def attack_after_integrity_query(
                    api: MODULE._NativeSQLiteApi,
                    database_handle: ctypes.c_void_p,
                    sql: bytes,
                    callback: object,
                    error_text: ctypes.c_char_p,
                ) -> int:
                    nonlocal attacked
                    result = original_exec(
                        api,
                        database_handle,
                        sql,
                        callback,
                        error_text,
                    )
                    if not attacked and sql == b"PRAGMA integrity_check":
                        if attack == "identity":
                            replacement = database.with_name(
                                f".{database.name}.replacement"
                            )
                            shutil.copy2(database, replacement)
                            os.replace(replacement, database)
                        elif attack == "content":
                            with database.open("ab") as handle:
                                handle.write(b"tampered")
                                handle.flush()
                                os.fsync(handle.fileno())
                        else:
                            database.chmod(0o640)
                        attacked = True
                    return result

                with (
                    mock.patch.object(
                        MODULE,
                        "_native_sqlite_exec",
                        side_effect=attack_after_integrity_query,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    self._validate_patch_stage(stage_dir)

                self.assertTrue(attacked)
                self._assert_safety_code(expected_code, raised)

    def test_validators_detect_file_access_change_during_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN,
                    self._validate_snapshot,
                    snapshot_dir,
                    "snapshot-file-access-policy-mismatch",
                ),
                (
                    stage_dir / MODULE.NOTE_STORE_MAIN,
                    self._validate_patch_stage,
                    stage_dir,
                    "patch-file-access-policy-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(target=target):
                    target.chmod(0o600)
                    integrity_boundary = (
                        "_bound_recovery_integrity"
                        if expected_code.startswith("snapshot-")
                        else "_sqlite_integrity"
                    )
                    original_integrity = getattr(MODULE, integrity_boundary)
                    attacked = False

                    def chmod_after_integrity(
                        database: object,
                        **kwargs: object,
                    ) -> dict[str, object]:
                        nonlocal attacked
                        result = original_integrity(database, **kwargs)
                        if not attacked:
                            attacked = True
                            target.chmod(0o640)
                        return result

                    with (
                        mock.patch.object(
                            MODULE,
                            integrity_boundary,
                            side_effect=chmod_after_integrity,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        validator(argument)
                    self._assert_safety_code(expected_code, raised)

    def test_validators_detect_in_place_content_change_during_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN,
                    self._validate_snapshot,
                    snapshot_dir,
                    "snapshot-content-mismatch",
                ),
                (
                    stage_dir / MODULE.NOTE_STORE_MAIN,
                    self._validate_patch_stage,
                    stage_dir,
                    "patch-content-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(target=target):
                    integrity_boundary = (
                        "_bound_recovery_integrity"
                        if expected_code.startswith("snapshot-")
                        else "_sqlite_integrity"
                    )
                    original_integrity = getattr(MODULE, integrity_boundary)
                    attacked = False

                    def mutate_after_integrity(
                        database: object,
                        **kwargs: object,
                    ) -> dict[str, object]:
                        nonlocal attacked
                        result = original_integrity(database, **kwargs)
                        if not attacked:
                            attacked = True
                            with target.open("ab") as handle:
                                handle.write(b"tampered")
                                handle.flush()
                                os.fsync(handle.fileno())
                        return result

                    with (
                        mock.patch.object(
                            MODULE,
                            integrity_boundary,
                            side_effect=mutate_after_integrity,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        validator(argument)
                    self._assert_safety_code(expected_code, raised)

    def test_validator_allows_file_mtime_only_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage_dir = Path(self._stage_patch(edited, root / "stage")["stage_dir"])
            staged_db = stage_dir / MODULE.NOTE_STORE_MAIN
            original_integrity = MODULE._sqlite_integrity
            touched = False

            def touch_after_integrity(
                path: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal touched
                result = original_integrity(path, **kwargs)
                if not touched:
                    touched = True
                    current = staged_db.stat()
                    os.utime(
                        staged_db,
                        ns=(
                            current.st_atime_ns,
                            current.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                return result

            with mock.patch.object(
                MODULE,
                "_sqlite_integrity",
                side_effect=touch_after_integrity,
            ):
                validation = self._validate_patch_stage(stage_dir)
        transitions = validation["source_integrity"]["database"]["metadata_transitions"]
        self.assertIn("mtime_ns", transitions)

    def test_recover_snapshot_identity_swap_after_publication_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="validated")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_db = (
                snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            )
            original_recover = MODULE._recover_validated_clone_to_standalone

            def recover_then_swap(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                result = original_recover(recovered_main, out, **kwargs)
                replacement = root / "replacement.sqlite"
                self._create_db(replacement, value="replacement")
                os.replace(replacement, snapshot_db)
                return result

            recovered = root / "recovered.sqlite"
            with (
                mock.patch.object(
                    MODULE,
                    "_recover_validated_clone_to_standalone",
                    side_effect=recover_then_swap,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, recovered)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertEqual(
                raised.exception.details["post_publication_error_code"],
                "snapshot-file-identity-mismatch",
            )
            locator = raised.exception.details["recovery_locators"][
                "descriptor_bound_destination"
            ]
            self.assertEqual(
                locator["verification"],
                "bound-parent-and-leaf-match-creation-receipts",
            )
            with closing(sqlite3.connect(recovered)) as conn:
                recovered_value = conn.execute("SELECT value FROM sample").fetchone()[0]
            with closing(sqlite3.connect(snapshot_db)) as conn:
                current_value = conn.execute("SELECT value FROM sample").fetchone()[0]
        self.assertEqual(recovered_value, "validated")
        self.assertEqual(current_value, "replacement")

    def test_recover_snapshot_content_change_after_publication_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_db = (
                snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            )
            original_recover = MODULE._recover_validated_clone_to_standalone

            def recover_then_mutate(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                result = original_recover(recovered_main, out, **kwargs)
                with snapshot_db.open("ab") as handle:
                    handle.write(b"post-publication-content-change")
                    handle.flush()
                    os.fsync(handle.fileno())
                return result

            recovered = root / "recovered.sqlite"
            with (
                mock.patch.object(
                    MODULE,
                    "_recover_validated_clone_to_standalone",
                    side_effect=recover_then_mutate,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, recovered)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["post_publication_error_code"],
                "snapshot-content-mismatch",
            )
            self.assertTrue(recovered.is_file())

    def test_recover_snapshot_access_change_after_publication_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_db = (
                snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            )
            snapshot_db.chmod(0o600)
            original_recover = MODULE._recover_validated_clone_to_standalone

            def recover_then_chmod(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                result = original_recover(recovered_main, out, **kwargs)
                snapshot_db.chmod(0o640)
                return result

            recovered = root / "recovered.sqlite"
            with (
                mock.patch.object(
                    MODULE,
                    "_recover_validated_clone_to_standalone",
                    side_effect=recover_then_chmod,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, recovered)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["post_publication_error_code"],
                "snapshot-file-access-policy-mismatch",
            )
            self.assertTrue(recovered.is_file())

    def test_recover_snapshot_parent_replacement_after_publication_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            output_parent = root / "output"
            output_parent.mkdir()
            parked_parent = root / "output-parked"
            recovered = output_parent / "recovered.sqlite"
            original_recover = MODULE._recover_validated_clone_to_standalone

            def recover_then_replace_parent(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                result = original_recover(recovered_main, out, **kwargs)
                output_parent.rename(parked_parent)
                output_parent.mkdir()
                return result

            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_recover_validated_clone_to_standalone",
                        side_effect=recover_then_replace_parent,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    self._recover_snapshot(snapshot_dir, recovered)
                self._assert_safety_code("destination-install-uncertain", raised)
                self.assertEqual(
                    raised.exception.details["publication_state"],
                    "uncertain",
                )
                self.assertFalse(raised.exception.details["retry_safe"])
                self.assertEqual(
                    raised.exception.details["post_publication_error_code"],
                    "prepared-directory-identity-mismatch",
                )
                locator = raised.exception.details["recovery_locators"][
                    "descriptor_bound_destination"
                ]
                self.assertEqual(
                    locator["leaf_identity"],
                    MODULE._identity((parked_parent / recovered.name).stat()),
                )
                self.assertFalse(recovered.exists())
                self.assertTrue((parked_parent / recovered.name).is_file())
            finally:
                if parked_parent.exists():
                    output_parent.rmdir()
                    parked_parent.rename(output_parent)

    def test_recover_snapshot_preserves_snapshot_source_integrity_receipts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            validation = self._validate_snapshot(snapshot_dir)
            result = self._recover_snapshot(
                snapshot_dir,
                root / "recovered.sqlite",
            )

        self.assertEqual(
            result["recovered"]["source_integrity"],
            validation["source_integrity"],
        )
        self.assertEqual(
            result["snapshot_validation"]["source_integrity"],
            validation["source_integrity"],
        )
        for receipt in [
            validation["source_integrity"]["manifest"],
            *validation["source_integrity"]["files"],
        ]:
            self.assertIn("identity", receipt)
            self.assertIn("sha256", receipt)
            self.assertIn("size", receipt)
            self.assertIn("access_policy", receipt)
        for receipt in validation["source_integrity"]["directories"].values():
            self.assertIn("identity", receipt)
            self.assertIn("access_policy", receipt)

    def test_recover_snapshot_binds_artifact_root_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            recovered = root / "recovered.sqlite"
            original_bind = MODULE._bind_artifact_root
            snapshot_bind_count = 0
            expected_bound_snapshot = Path(os.path.abspath(snapshot_dir))

            @contextmanager
            def count_snapshot_bind(
                path: Path,
                *,
                missing_code: str,
            ) -> Iterator[MODULE._BoundDirectory]:
                nonlocal snapshot_bind_count
                if path == expected_bound_snapshot:
                    snapshot_bind_count += 1
                with original_bind(path, missing_code=missing_code) as binding:
                    yield binding

            with mock.patch.object(
                MODULE,
                "_bind_artifact_root",
                side_effect=count_snapshot_bind,
            ):
                result = self._recover_snapshot(snapshot_dir, recovered)

            self.assertEqual(snapshot_bind_count, 1)
            self.assertEqual(
                Path(result["recovered"]["standalone_db"]),
                recovered,
            )

    def test_recover_snapshot_rejects_terminal_output_wal_race(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            recovered = root / "recovered.sqlite"
            wal = recovered.with_name(f"{recovered.name}-wal")
            original_publish = MODULE._publish_file_no_replace_from_parent

            def publish_then_inject_wal(
                prepared: MODULE._BoundRegularFile,
                destination: Path,
                parent_fd: int,
                *,
                publication_guard: dict[str, object] | None = None,
            ) -> dict[str, object]:
                result = original_publish(
                    prepared,
                    destination,
                    parent_fd,
                    publication_guard=publication_guard,
                )
                if destination == recovered:
                    wal.write_bytes(b"raced-wal")
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_file_no_replace_from_parent",
                    side_effect=publish_then_inject_wal,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, recovered)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(recovered.is_file())
            self.assertTrue(wal.is_file())
            self.assertEqual(
                raised.exception.details["terminal_sidecar_revalidation"][
                    "reason_code"
                ],
                "standalone-output-sidecar-present",
            )

    def test_recover_snapshot_rejects_nested_output_before_parent_creation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            initial_members = sorted(child.name for child in snapshot_dir.iterdir())
            nested_parent = snapshot_dir / "analysis" / "nested"
            recovered = nested_parent / "recovered.sqlite"

            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                self._recover_snapshot(snapshot_dir, recovered)

            self._assert_safety_code(
                "recovery-output-inside-snapshot",
                raised,
            )
            self.assertFalse(nested_parent.exists())
            self.assertEqual(
                sorted(child.name for child in snapshot_dir.iterdir()),
                initial_members,
            )
            self.assertEqual(
                self._validate_snapshot(snapshot_dir)["sqlite_validation"]["result"],
                "ok",
            )

    def test_recover_illegal_outputs_stop_before_temp_clone_or_writer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            receipt = snapshot["manifest_creation_receipt"]
            live_alias = root / "live-group-alias"
            live_alias.symlink_to(
                paths.group_container,
                target_is_directory=True,
            )
            cases = (
                (
                    "group",
                    paths.group_container / "blocked.sqlite",
                    "snapshot-destination-inside-live-container",
                ),
                (
                    "app",
                    paths.app_container / "blocked.sqlite",
                    "snapshot-destination-inside-live-container",
                ),
                (
                    "reserved",
                    root / MODULE.NOTE_STORE_MAIN / "blocked.sqlite",
                    "snapshot-destination-reserved-store-path",
                ),
                (
                    "symlink-alias",
                    live_alias / "blocked.sqlite",
                    "snapshot-destination-inside-live-container",
                ),
            )
            for label, destination, expected_code in cases:
                with (
                    self.subTest(label=label),
                    mock.patch.object(
                        MODULE.tempfile,
                        "TemporaryDirectory",
                    ) as temporary_directory,
                    mock.patch.object(
                        MODULE,
                        "_make_recovery_clone_from_bound",
                    ) as clone,
                    mock.patch.object(
                        MODULE,
                        "_recover_validated_clone_to_standalone",
                    ) as writer,
                    mock.patch.object(
                        MODULE,
                        "_write_standalone_backup_payload",
                    ) as standalone_writer,
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.recover_snapshot(
                        snapshot_dir,
                        destination,
                        receipt,
                        paths=paths,
                    )
                self._assert_safety_code(expected_code, raised)
                temporary_directory.assert_not_called()
                clone.assert_not_called()
                writer.assert_not_called()
                standalone_writer.assert_not_called()
                self.assertFalse(destination.exists())

    def test_recover_snapshot_rejects_case_variant_and_symlink_aliases(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            case_alias = root / snapshot_dir.name.swapcase()
            if not case_alias.exists():
                case_alias.symlink_to(snapshot_dir, target_is_directory=True)
            symlink_alias = root / "snapshot-symlink-alias"
            symlink_alias.symlink_to(snapshot_dir, target_is_directory=True)
            initial_members = sorted(child.name for child in snapshot_dir.iterdir())

            for label, alias in (
                ("case-variant", case_alias),
                ("symlink", symlink_alias),
            ):
                output_parent = alias / f"{label}-analysis" / "nested"
                with (
                    self.subTest(label=label),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    self._recover_snapshot(
                        snapshot_dir,
                        output_parent / "recovered.sqlite",
                    )
                self._assert_safety_code(
                    "recovery-output-inside-snapshot",
                    raised,
                )
                self.assertFalse(output_parent.exists())
                self.assertEqual(
                    sorted(child.name for child in snapshot_dir.iterdir()),
                    initial_members,
                )

    def test_recover_snapshot_creates_safe_missing_output_parent_from_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            recovered = root / "analysis" / "nested" / "recovered.sqlite"

            result = self._recover_snapshot(snapshot_dir, recovered)

            self.assertEqual(Path(result["recovered"]["standalone_db"]), recovered)
            with closing(sqlite3.connect(recovered)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "ok")

    def test_recover_snapshot_creates_output_through_bound_parent_during_swap_restore(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(
                paths.group_container / MODULE.NOTE_STORE_MAIN,
                value="validated",
            )
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            recovered = root / "recovered.sqlite"
            original_write = MODULE._write_standalone_backup_payload
            real_open = MODULE.os.open
            attacked = False
            replacement_entries: list[str] = []

            def write_with_create_swap(
                payload: bytes,
                output: Path,
                *,
                destination_binding: MODULE._BoundDirectory | None = None,
            ) -> dict[str, object]:
                if (
                    destination_binding is None
                    or output.parent != root
                    or not output.name.startswith(".recovered.sqlite.tmp-")
                ):
                    return original_write(
                        payload,
                        output,
                        destination_binding=destination_binding,
                    )

                def open_with_swap(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal attacked
                    if (
                        not attacked
                        and os.fspath(path) == output.name
                        and dir_fd == destination_binding.fd
                        and flags & os.O_CREAT
                    ):
                        attacked = True
                        parked = root.with_name(f"{root.name}.parked")
                        root.rename(parked)
                        root.mkdir(mode=0o700)
                        try:
                            opened_fd = real_open(
                                path,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )
                            replacement_entries.extend(
                                child.name for child in root.iterdir()
                            )
                            return opened_fd
                        finally:
                            shutil.rmtree(root)
                            parked.rename(root)
                    return real_open(
                        path,
                        flags,
                        mode,
                        dir_fd=dir_fd,
                    )

                with mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=open_with_swap,
                ):
                    return original_write(
                        payload,
                        output,
                        destination_binding=destination_binding,
                    )

            with mock.patch.object(
                MODULE,
                "_write_standalone_backup_payload",
                side_effect=write_with_create_swap,
            ):
                self._recover_snapshot(snapshot_dir, recovered)

            self.assertTrue(attacked)
            self.assertEqual(replacement_entries, [])
            with closing(sqlite3.connect(recovered)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "validated")

    def test_recover_snapshot_rejects_validated_artifact_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(
                paths.group_container / MODULE.NOTE_STORE_MAIN,
                value="validated",
            )
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            original_recover = MODULE._recover_validated_clone_to_standalone

            def replace_artifact_then_recover(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                replacement = recovered_main.with_name("replacement.sqlite")
                self._create_db(replacement, value="replacement")
                os.replace(replacement, recovered_main)
                return original_recover(recovered_main, out, **kwargs)

            recovered = root / "recovered.sqlite"
            with (
                mock.patch.object(
                    MODULE,
                    "_recover_validated_clone_to_standalone",
                    side_effect=replace_artifact_then_recover,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, recovered)
            self._assert_safety_code(
                "snapshot-file-identity-mismatch",
                raised,
            )
            self.assertFalse(recovered.exists())

    def test_recover_snapshot_rejects_wal_injected_after_artifact_validation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(
                paths.group_container / MODULE.NOTE_STORE_MAIN,
                value="validated",
            )
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            original_recover = MODULE._recover_validated_clone_to_standalone
            injected = False

            def inject_wal_then_recover(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal injected
                attacker = recovered_main.with_name("attacker.sqlite")
                shutil.copy2(recovered_main, attacker)
                writer = sqlite3.connect(attacker)
                try:
                    self.assertEqual(
                        writer.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                        "wal",
                    )
                    writer.execute("PRAGMA wal_autocheckpoint = 0")
                    writer.execute("UPDATE sample SET value = 'injected-from-wal'")
                    writer.commit()
                    attacker_wal = attacker.with_name(f"{attacker.name}-wal")
                    injected_wal = recovered_main.with_name(
                        f"{recovered_main.name}-wal"
                    )
                    shutil.copy2(attacker_wal, injected_wal)
                    injected = injected_wal.exists()
                    return original_recover(recovered_main, out, **kwargs)
                finally:
                    writer.close()

            recovered = root / "recovered.sqlite"
            with (
                mock.patch.object(
                    MODULE,
                    "_recover_validated_clone_to_standalone",
                    side_effect=inject_wal_then_recover,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._recover_snapshot(snapshot_dir, recovered)
        self.assertTrue(injected)
        self._assert_safety_code("snapshot-file-set-mismatch", raised)
        self.assertFalse(recovered.exists())

    def test_recover_snapshot_binds_clone_during_native_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(
                paths.group_container / MODULE.NOTE_STORE_MAIN,
                value="validated",
            )
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            original_recover = MODULE._recover_validated_clone_to_standalone
            original_image = MODULE._deserialized_sqlite_image
            attacked = False

            def recover_with_native_swap(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                replacement = root / "connect-replacement.sqlite"
                parked = root / "connect-validated.sqlite"
                self._create_db(replacement, value="replacement")

                @contextmanager
                def image_with_swap(
                    bound: MODULE._BoundRegularFile,
                    source_path: Path,
                    **image_kwargs: object,
                ) -> Iterator[MODULE._DeserializedSQLiteImage]:
                    nonlocal attacked
                    with original_image(
                        bound,
                        source_path,
                        **image_kwargs,
                    ) as image:
                        if attacked or source_path != recovered_main:
                            yield image
                            return
                        attacked = True
                        os.replace(recovered_main, parked)
                        os.replace(replacement, recovered_main)
                        try:
                            yield image
                        finally:
                            os.replace(recovered_main, replacement)
                            os.replace(parked, recovered_main)

                with mock.patch.object(
                    MODULE,
                    "_deserialized_sqlite_image",
                    side_effect=image_with_swap,
                ):
                    return original_recover(recovered_main, out, **kwargs)

            recovered = root / "recovered.sqlite"
            with mock.patch.object(
                MODULE,
                "_recover_validated_clone_to_standalone",
                side_effect=recover_with_native_swap,
            ):
                self._recover_snapshot(snapshot_dir, recovered)
            with closing(sqlite3.connect(recovered)) as conn:
                recovered_value = conn.execute("SELECT value FROM sample").fetchone()[0]
        self.assertTrue(attacked)
        self.assertEqual(recovered_value, "validated")

    def test_snapshot_rejects_partial_root_replacement_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_publish = MODULE._publish_directory_no_replace
            replacement_root: Path | None = None

            def replace_partial(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                nonlocal replacement_root
                source.rename(source.with_name(f"{source.name}.original"))
                source.mkdir(mode=0o700)
                replacement_root = source
                original_publish(source, target, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=replace_partial,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self._assert_safety_code(
                "prepared-directory-identity-mismatch",
                raised,
            )
            self.assertIsNotNone(replacement_root)
            assert replacement_root is not None
            self.assertTrue(replacement_root.is_dir())
            self.assertFalse(destination.exists())

    def test_retained_partial_inventory_stops_at_bounded_entry_cap(
        self,
    ) -> None:
        class LazyEntry:
            def __init__(self, name: str) -> None:
                self.name = name

        class LazyEntries:
            def __init__(self, total: int) -> None:
                self.total = total
                self.yielded = 0
                self.closed = False

            def __enter__(self) -> LazyEntries:
                return self

            def __exit__(
                self,
                exc_type: object,
                exc: object,
                traceback: object,
            ) -> None:
                self.closed = True

            def __iter__(self) -> LazyEntries:
                return self

            def __next__(self) -> LazyEntry:
                if self.yielded >= self.total:
                    raise StopIteration
                entry = LazyEntry(f"retained-{self.yielded:08d}")
                self.yielded += 1
                return entry

        with tempfile.TemporaryDirectory() as temp_dir:
            partial = Path(temp_dir) / "retained"
            partial.mkdir(mode=0o700)
            simulated = LazyEntries(MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES * 1024)
            with (
                MODULE._bind_existing_directory_with_trusted_alias(partial) as binding,
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    return_value=simulated,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._retained_bound_directory_receipt(binding, partial)

        self._assert_safety_code(
            "prepared-directory-revalidation-inconclusive",
            raised,
        )
        self.assertEqual(
            simulated.yielded,
            MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES + 1,
        )
        self.assertTrue(simulated.closed)
        self.assertEqual(
            raised.exception.details["entry_limit"],
            MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES,
        )
        self.assertEqual(
            raised.exception.details["observed_entries"],
            MODULE.BOUND_DIRECTORY_SCAN_MAX_ENTRIES + 1,
        )
        self.assertEqual(
            raised.exception.details["recovery_locators"],
            {
                "prepared_namespace": str(partial),
                "prepared_parent": str(partial.parent),
            },
        )
        encoded_details = json.dumps(
            raised.exception.details,
            ensure_ascii=True,
            sort_keys=True,
        ).encode("utf-8")
        self.assertLess(len(encoded_details), 2048)
        self.assertNotIn(
            "sensitive_partial_inventory",
            raised.exception.details,
        )

    def test_retained_partial_inventory_stops_at_raw_name_byte_cap(
        self,
    ) -> None:
        class LongNameEntry:
            name = "x" * (MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES + 1)

        class LazyEntries:
            def __init__(self) -> None:
                self.yielded = 0

            def __enter__(self) -> LazyEntries:
                return self

            def __exit__(
                self,
                exc_type: object,
                exc: object,
                traceback: object,
            ) -> None:
                return None

            def __iter__(self) -> LazyEntries:
                return self

            def __next__(self) -> LongNameEntry:
                self.yielded += 1
                return LongNameEntry()

        with tempfile.TemporaryDirectory() as temp_dir:
            partial = Path(temp_dir) / "retained"
            partial.mkdir(mode=0o700)
            simulated = LazyEntries()
            with (
                MODULE._bind_existing_directory_with_trusted_alias(partial) as binding,
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    return_value=simulated,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE._retained_bound_directory_receipt(binding, partial)

        self._assert_safety_code(
            "prepared-directory-revalidation-inconclusive",
            raised,
        )
        self.assertEqual(simulated.yielded, 1)
        self.assertEqual(
            raised.exception.details["raw_name_bytes_limit"],
            MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES,
        )
        self.assertEqual(
            raised.exception.details["observed_raw_name_bytes"],
            MODULE.BOUND_DIRECTORY_SCAN_MAX_RAW_NAME_BYTES + 1,
        )
        self.assertEqual(
            raised.exception.details["recovery_locators"]["prepared_namespace"],
            str(partial),
        )

    def test_retained_partial_receipt_failure_still_reports_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            partial = Path(temp_dir) / "retained"
            with (
                mock.patch.object(
                    MODULE,
                    "_retained_bound_directory_receipt",
                    side_effect=OSError(
                        errno.EIO,
                        "simulated retained receipt evidence failure",
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                with MODULE._create_bound_directory(
                    partial,
                    retain_failure_receipt=True,
                ):
                    raise RuntimeError("simulated prepared-tree failure")

            self._assert_safety_code("prepared-operation-failed", raised)
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["cleanup_state"], "preserved-or-incomplete")
            self.assertEqual(
                details["cleanup_error_code"],
                "prepared-directory-revalidation-inconclusive",
            )
            self.assertEqual(details["cleanup_error_type"], "OSError")
            self.assertEqual(
                details["recovery_locators"]["prepared_namespace"],
                str(partial),
            )
            self.assertTrue(partial.is_dir())

    def test_cleanup_preserves_root_swapped_before_recursive_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_scandir = MODULE.os.scandir
            attacked = False
            publication_rejected = False
            moved_root: Path | None = None
            replacement_root: Path | None = None

            def reject_publication(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                nonlocal publication_rejected
                publication_rejected = True
                raise MODULE.StoreSafetyError(
                    "destination-exists",
                    f"simulated publication failure: {source} -> {target}",
                )

            def swap_after_identity_observation(
                directory: object,
            ) -> os.ScandirIterator[str]:
                nonlocal attacked, moved_root, replacement_root
                if publication_rejected and not attacked and isinstance(directory, int):
                    attacked = True
                    display_path = next(root.glob(".stage.partial-*"))
                    moved_root = display_path.with_name(f"{display_path.name}.owned")
                    display_path.rename(moved_root)
                    display_path.mkdir(mode=0o700)
                    replacement_root = display_path
                    (replacement_root / "do-not-delete").write_text(
                        "replacement",
                        encoding="utf-8",
                    )
                return original_scandir(directory)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=reject_publication,
                ),
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    side_effect=swap_after_identity_observation,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("destination-exists", raised)
            self.assertTrue(attacked)
            self.assertIsNotNone(moved_root)
            self.assertIsNotNone(replacement_root)
            assert moved_root is not None
            assert replacement_root is not None
            self.assertTrue(moved_root.is_dir())
            self.assertTrue((moved_root / MODULE.NOTE_STORE_MAIN).is_file())
            self.assertTrue((moved_root / MODULE.PATCH_MANIFEST).is_file())
            self.assertEqual(
                (replacement_root / "do-not-delete").read_text(encoding="utf-8"),
                "replacement",
            )
            self.assertEqual(
                raised.exception.details["cleanup_state"],
                "preserved-or-incomplete",
            )
            self.assertEqual(
                raised.exception.details["cleanup_error_code"],
                "prepared-directory-identity-mismatch",
            )
            self.assertIn(
                "prepared_parent",
                raised.exception.details["recovery_locators"],
            )
            self.assertFalse(destination.exists())

    def test_ordinary_stage_failure_reports_retained_sensitive_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            with (
                mock.patch.object(
                    MODULE,
                    "_write_json_atomic",
                    side_effect=OSError(
                        MODULE.errno.EIO,
                        "simulated manifest write failure",
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("prepared-operation-failed", raised)
            self.assertIsInstance(raised.exception.__cause__, OSError)
            self.assertEqual(
                raised.exception.details["underlying_errno"],
                MODULE.errno.EIO,
            )
            self.assertEqual(raised.exception.details["cleanup_state"], "retained")
            partial = self._assert_retained_partial(root, ".stage.partial-*")
            self.assertEqual(
                Path(
                    raised.exception.details["recovery_locators"]["prepared_namespace"]
                ),
                partial,
            )
            self.assertEqual(
                {
                    row["relative_path"]
                    for row in raised.exception.details["sensitive_partial_inventory"]
                },
                {MODULE.NOTE_STORE_MAIN},
            )
            self.assertTrue((partial / MODULE.NOTE_STORE_MAIN).is_file())
            self.assertFalse(destination.exists())

    def test_receipt_runtime_failure_does_not_replace_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_scandir = MODULE.os.scandir
            publication_rejected = False

            def reject_publication(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                nonlocal publication_rejected
                publication_rejected = True
                raise MODULE.StoreSafetyError(
                    "destination-exists",
                    f"simulated publication failure: {source} -> {target}",
                )

            def fail_retained_inventory(
                directory: object,
            ) -> os.ScandirIterator[str]:
                if publication_rejected and isinstance(directory, int):
                    raise OSError(
                        MODULE.errno.EIO,
                        "simulated inventory failure",
                    )
                return original_scandir(directory)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=reject_publication,
                ),
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    side_effect=fail_retained_inventory,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("destination-exists", raised)
            self.assertEqual(
                raised.exception.details["cleanup_error_code"],
                "prepared-directory-revalidation-inconclusive",
            )
            self.assertEqual(
                raised.exception.details["cleanup_state"],
                "preserved-or-incomplete",
            )
            self.assertEqual(
                raised.exception.details["recovery_locators"]["prepared_parent"],
                str(root),
            )
            self._assert_retained_partial(root, ".stage.partial-*")
            self.assertFalse(destination.exists())

    def test_cleanup_preserves_regular_leaf_replaced_after_root_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="validated")
            destination = root / "stage"
            original_scandir = MODULE.os.scandir
            attacked = False
            publication_rejected = False
            moved_prepared: Path | None = None
            replacement: Path | None = None

            def reject_publication(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                nonlocal publication_rejected
                publication_rejected = True
                raise MODULE.StoreSafetyError(
                    "destination-exists",
                    f"simulated publication failure: {source} -> {target}",
                )

            def replace_leaf_after_root_binding(
                directory: object,
            ) -> os.ScandirIterator[str]:
                nonlocal attacked, moved_prepared, replacement
                if publication_rejected and not attacked and isinstance(directory, int):
                    attacked = True
                    partial = next(root.glob(".stage.partial-*"))
                    prepared = partial / MODULE.NOTE_STORE_MAIN
                    moved_prepared = prepared.with_name(f"{prepared.name}.owned")
                    prepared.rename(moved_prepared)
                    prepared.write_text("replacement", encoding="utf-8")
                    replacement = prepared
                return original_scandir(directory)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=reject_publication,
                ),
                mock.patch.object(
                    MODULE.os,
                    "scandir",
                    side_effect=replace_leaf_after_root_binding,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("destination-exists", raised)
            self.assertTrue(attacked)
            self.assertIsNotNone(moved_prepared)
            self.assertIsNotNone(replacement)
            assert moved_prepared is not None
            assert replacement is not None
            self.assertEqual(replacement.read_text(encoding="utf-8"), "replacement")
            with closing(sqlite3.connect(moved_prepared)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "validated")
            self.assertEqual(raised.exception.details["cleanup_state"], "retained")
            inventory = {
                row["relative_path"]
                for row in raised.exception.details["sensitive_partial_inventory"]
            }
            self.assertIn(MODULE.NOTE_STORE_MAIN, inventory)
            self.assertIn(f"{MODULE.NOTE_STORE_MAIN}.owned", inventory)
            self.assertIn(MODULE.PATCH_MANIFEST, inventory)
            self.assertFalse(destination.exists())

    def test_stage_rejects_partial_root_replacement_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_publish = MODULE._publish_directory_no_replace
            replacement_root: Path | None = None

            def replace_partial(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                nonlocal replacement_root
                source.rename(source.with_name(f"{source.name}.original"))
                source.mkdir(mode=0o700)
                replacement_root = source
                original_publish(source, target, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=replace_partial,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code(
                "prepared-directory-identity-mismatch",
                raised,
            )
            self.assertIsNotNone(replacement_root)
            assert replacement_root is not None
            self.assertTrue(replacement_root.is_dir())
            self.assertFalse(destination.exists())

    def test_stage_rejects_prepared_file_tamper_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_publish = MODULE._publish_directory_no_replace

            def tamper_before_publish(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                with (source / MODULE.NOTE_STORE_MAIN).open("ab") as handle:
                    handle.write(b"tampered")
                    handle.flush()
                    os.fsync(handle.fileno())
                original_publish(source, target, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=tamper_before_publish,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code("prepared-file-content-mismatch", raised)
            self.assertFalse(destination.exists())
            self._assert_retained_partial(root, ".stage.partial-*")

    def test_snapshot_rejects_prepared_file_tamper_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_publish = MODULE._publish_directory_no_replace

            def tamper_before_publish(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                prepared_db = source / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
                with prepared_db.open("ab") as handle:
                    handle.write(b"tampered")
                    handle.flush()
                    os.fsync(handle.fileno())
                original_publish(source, target, **kwargs)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=tamper_before_publish,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self._assert_safety_code("prepared-file-content-mismatch", raised)
            self.assertFalse(destination.exists())
            self._assert_retained_partial(root, ".snapshot.partial-*")

    def test_stage_rejects_partial_root_access_change_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_publish = MODULE._publish_directory_no_replace

            def chmod_before_publish(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                source.chmod(0o750)
                original_publish(source, target, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=chmod_before_publish,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                self._stage_patch(edited, destination)
            self._assert_safety_code(
                "prepared-directory-access-policy-mismatch",
                raised,
            )
            self.assertFalse(destination.exists())
            self._assert_retained_partial(root, ".stage.partial-*")

    def test_single_file_rename_then_error_is_uncertain_and_preserves_destination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_rename = MODULE._rename_file_no_replace_at

            def rename_then_error(
                parent_fd: int,
                prepared: str,
                target: str,
            ) -> None:
                original_rename(parent_fd, prepared, target)
                raise OSError(MODULE.errno.EIO, "simulated rename completion error")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=rename_then_error,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            locators = raised.exception.details["recovery_locators"]
            self.assertTrue(Path(locators["destination"]).is_file())
            self.assertNotIn("prepared", locators)
            self.assertEqual(
                locators["prepared_unverified"]["verification"],
                "absent-or-parent-missing",
            )

    def test_single_file_rename_failure_retains_verified_prepared_locator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"

            def fail_rename(
                parent_fd: int,
                prepared: str,
                target: str,
            ) -> None:
                del parent_fd, prepared, target
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=fail_rename,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code(
                "destination-install-failed",
                raised,
            )
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertTrue(raised.exception.details["retry_safe"])
            locators = raised.exception.details["recovery_locators"]
            self.assertTrue(Path(locators["prepared"]).is_file())
            retry_receipt = locators["descriptor_bound_prepared_file"]
            self.assertEqual(
                retry_receipt["verification"],
                "bound-parent-leaf-identity-content-size-and-access-match-"
                "creation-receipts",
            )
            self.assertEqual(
                retry_receipt["sha256"],
                MODULE._fingerprint_exact_file(Path(locators["prepared"]))["sha256"],
            )
            self.assertEqual(retry_receipt["target"]["state"], "absent")
            self.assertEqual(
                retry_receipt["target"]["verification"],
                "terminal-descriptor-relative-no-follow-observation",
            )
            self.assertFalse(destination.exists())

    def test_single_file_rename_failure_target_appears_during_retry_hash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_hash = MODULE._hash_fd
            rename_failed = False
            injected = False

            def fail_rename(
                parent_fd: int,
                prepared_name: str,
                target_name: str,
            ) -> None:
                nonlocal rename_failed
                del parent_fd, prepared_name, target_name
                rename_failed = True
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            def hash_and_inject_target(fd: int) -> str:
                nonlocal injected
                result = original_hash(fd)
                if rename_failed and not injected:
                    destination.write_text("concurrent target", encoding="utf-8")
                    injected = True
                return result

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=fail_rename,
                ),
                mock.patch.object(
                    MODULE,
                    "_hash_fd",
                    side_effect=hash_and_inject_target,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)

            self.assertTrue(injected)
            self._assert_safety_code("destination-exists", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncommitted",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            retry_receipt = raised.exception.details["recovery_locators"][
                "descriptor_bound_prepared_file"
            ]
            self.assertEqual(retry_receipt["target"]["state"], "present")
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                "concurrent target",
            )

    def test_single_file_rename_failure_target_terminal_observation_unavailable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_observe = MODULE._observe_bound_sibling
            rename_failed = False
            destination_observations = 0

            def fail_rename(
                parent_fd: int,
                prepared_name: str,
                target_name: str,
            ) -> None:
                nonlocal rename_failed
                del parent_fd, prepared_name, target_name
                rename_failed = True
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            def make_terminal_target_unavailable(
                parent_fd: int,
                prepared: MODULE._BoundRegularFile,
                path: Path,
            ) -> tuple[str, os.stat_result | None]:
                nonlocal destination_observations
                if rename_failed and path == destination:
                    destination_observations += 1
                    if destination_observations == 2:
                        return "unavailable", None
                return original_observe(parent_fd, prepared, path)

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=fail_rename,
                ),
                mock.patch.object(
                    MODULE,
                    "_observe_bound_sibling",
                    side_effect=make_terminal_target_unavailable,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            retry_receipt = raised.exception.details["recovery_locators"][
                "descriptor_bound_prepared_file"
            ]
            self.assertEqual(retry_receipt["target"]["state"], "unavailable")
            self.assertEqual(
                retry_receipt["target"]["evidence_status"],
                "inconclusive",
            )

    def test_single_file_rename_failure_with_in_place_content_drift_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"

            def mutate_then_fail(
                parent_fd: int,
                prepared_name: str,
                target_name: str,
            ) -> None:
                del target_name
                attack_fd = os.open(
                    prepared_name,
                    os.O_WRONLY | os.O_TRUNC,
                    dir_fd=parent_fd,
                )
                try:
                    os.write(attack_fd, b"in-place replacement bytes")
                    os.fsync(attack_fd)
                finally:
                    os.close(attack_fd)
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=mutate_then_fail,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertEqual(
                raised.exception.details["retry_revalidation"]["error_code"],
                "prepared-file-content-mismatch",
            )
            self.assertFalse(destination.exists())

    def test_single_file_rename_failure_with_in_place_mode_drift_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"

            def chmod_then_fail(
                parent_fd: int,
                prepared_name: str,
                target_name: str,
            ) -> None:
                del target_name
                attack_fd = os.open(
                    prepared_name,
                    os.O_RDONLY,
                    dir_fd=parent_fd,
                )
                try:
                    os.fchmod(attack_fd, 0o640)
                finally:
                    os.close(attack_fd)
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=chmod_then_fail,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertEqual(
                raised.exception.details["retry_revalidation"]["error_code"],
                "prepared-file-access-policy-mismatch",
            )
            self.assertFalse(destination.exists())

    def test_replaced_prepared_leaf_is_not_reported_as_verified_locator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            destination = root / "recovered.sqlite"
            moved_prepared: Path | None = None
            replacement: Path | None = None

            def replace_then_fail(
                parent_fd: int,
                prepared_name: str,
                target_name: str,
            ) -> None:
                nonlocal moved_prepared, replacement
                del parent_fd, target_name
                prepared = root / prepared_name
                moved_prepared = prepared.with_name(f"{prepared.name}.owned")
                prepared.rename(moved_prepared)
                prepared.write_text("replacement", encoding="utf-8")
                replacement = prepared
                raise OSError(MODULE.errno.EIO, "simulated rename failure")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=replace_then_fail,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            locators = raised.exception.details["recovery_locators"]
            self.assertNotIn("prepared", locators)
            unverified = locators["prepared_unverified"]
            self.assertEqual(
                unverified["verification"],
                "creation-receipt-mismatch",
            )
            self.assertIsNotNone(replacement)
            self.assertIsNotNone(moved_prepared)
            assert replacement is not None
            assert moved_prepared is not None
            self.assertEqual(replacement.read_text(encoding="utf-8"), "replacement")
            self.assertNotEqual(
                unverified["identity"]["inode"],
                unverified["observed_identity"]["inode"],
            )
            with closing(sqlite3.connect(moved_prepared)) as conn:
                value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(value, "validated")
            self.assertFalse(destination.exists())

    def test_single_file_leaf_swap_during_rename_preserves_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            destination = root / "recovered.sqlite"
            original_rename = MODULE._rename_file_no_replace_at
            attacked = False
            moved_prepared: Path | None = None

            def swap_during_rename(
                parent_fd: int,
                prepared_name: str,
                target_name: str,
            ) -> None:
                nonlocal attacked, moved_prepared
                if not attacked:
                    attacked = True
                    prepared = root / prepared_name
                    moved_prepared = prepared.with_name(f"{prepared.name}.owned")
                    prepared.rename(moved_prepared)
                    prepared.write_text("replacement", encoding="utf-8")
                original_rename(parent_fd, prepared_name, target_name)

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=swap_during_rename,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(attacked)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            locators = raised.exception.details["recovery_locators"]
            self.assertEqual(Path(locators["destination"]), destination)
            self.assertNotIn("prepared", locators)
            self.assertEqual(
                locators["prepared_unverified"]["verification"],
                "absent-or-parent-missing",
            )
            self.assertIsNotNone(moved_prepared)
            assert moved_prepared is not None
            self.assertTrue(moved_prepared.is_file())
            self.assertTrue(destination.is_file())
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                "replacement",
            )
            with closing(sqlite3.connect(moved_prepared)) as conn:
                recovered_value = conn.execute("SELECT value FROM sample").fetchone()[0]
            self.assertEqual(recovered_value, "validated")

    def test_single_file_parent_fsync_failure_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"

            with (
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_parent_descriptor",
                    side_effect=OSError(
                        MODULE.errno.EIO,
                        "simulated parent fsync failure",
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertTrue(destination.is_file())

    def test_single_file_parent_replace_restore_during_fsync_uses_bound_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            parked = root.with_name(f"{root.name}-parked")
            original_fsync = MODULE._fsync_bound_parent_descriptor
            attacked = False

            def replace_parent_during_fsync(
                parent_fd: int,
                opened: os.stat_result,
                **kwargs: object,
            ) -> None:
                nonlocal attacked
                display_path = Path(str(kwargs["display_path"]))
                if not attacked and display_path == root:
                    attacked = True
                    root.rename(parked)
                    root.mkdir(mode=0o700)
                    self.assertNotEqual(
                        MODULE._identity(root.stat()),
                        MODULE._identity(os.fstat(parent_fd)),
                    )
                    try:
                        original_fsync(parent_fd, opened, **kwargs)
                    finally:
                        root.rmdir()
                        parked.rename(root)
                    return
                original_fsync(parent_fd, opened, **kwargs)

            with mock.patch.object(
                MODULE,
                "_fsync_bound_parent_descriptor",
                side_effect=replace_parent_during_fsync,
            ):
                result = MODULE.merge_db(source, destination)
            self.assertTrue(attacked)
            self.assertEqual(Path(result["standalone_db"]), destination)
            self.assertTrue(destination.is_file())

    def test_single_file_permanent_parent_replacement_is_uncertain_with_locator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            destination = root / "recovered.sqlite"
            parked = root.with_name(f"{root.name}-parked")
            original_fsync = MODULE._fsync_bound_parent_descriptor
            attacked = False

            def replace_parent_permanently(
                parent_fd: int,
                opened: os.stat_result,
                **kwargs: object,
            ) -> None:
                nonlocal attacked
                display_path = Path(str(kwargs["display_path"]))
                if not attacked and display_path == root and destination.exists():
                    attacked = True
                    root.rename(parked)
                    root.mkdir(mode=0o700)
                    self.assertNotEqual(
                        MODULE._identity(root.stat()),
                        MODULE._identity(os.fstat(parent_fd)),
                    )
                original_fsync(parent_fd, opened, **kwargs)

            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_fsync_bound_parent_descriptor",
                        side_effect=replace_parent_permanently,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.merge_db(source, destination)
                self._assert_safety_code("destination-install-uncertain", raised)
                self.assertTrue(attacked)
                self.assertFalse(destination.exists())
                parked_destination = parked / destination.name
                self.assertTrue(parked_destination.is_file())
                locators = raised.exception.details["recovery_locators"]
                locator = locators["descriptor_bound_destination"]
                self.assertEqual(locator["display_path"], str(destination))
                self.assertEqual(
                    locator["verification"],
                    "bound-parent-and-leaf-match-creation-receipts",
                )
                self.assertEqual(
                    locator["leaf_identity"],
                    MODULE._identity(parked_destination.stat()),
                )
                self.assertEqual(
                    locator["size"],
                    parked_destination.stat().st_size,
                )
                self.assertEqual(
                    locator["sha256"],
                    MODULE._fingerprint_exact_file(parked_destination)["sha256"],
                )
            finally:
                if parked.exists():
                    if root.exists():
                        root.rmdir()
                    parked.rename(root)

    def test_single_file_content_tamper_after_rename_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_fsync = MODULE._fsync_bound_parent_descriptor
            attacked = False

            def tamper_after_rename(
                parent_fd: int,
                opened: os.stat_result,
                **kwargs: object,
            ) -> None:
                nonlocal attacked
                display_path = Path(str(kwargs["display_path"]))
                if not attacked and display_path == root and destination.exists():
                    attacked = True
                    with destination.open("ab") as handle:
                        handle.write(b"tampered-after-rename")
                        handle.flush()
                        os.fsync(handle.fileno())
                original_fsync(parent_fd, opened, **kwargs)

            with (
                mock.patch.object(
                    MODULE,
                    "_fsync_bound_parent_descriptor",
                    side_effect=tamper_after_rename,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(attacked)
            self.assertIsInstance(raised.exception.__cause__, MODULE.StoreSafetyError)
            assert isinstance(raised.exception.__cause__, MODULE.StoreSafetyError)
            self.assertEqual(
                raised.exception.__cause__.code,
                "prepared-file-content-mismatch",
            )
            self.assertTrue(destination.is_file())

    def test_single_file_final_fingerprint_failure_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_verify = MODULE._verify_bound_regular_file_at
            destination_checks = 0

            def fail_final_fingerprint(
                bound: object,
                codes: object,
                *,
                dir_fd: int,
                basename: str,
            ) -> dict[str, object]:
                nonlocal destination_checks
                if basename == destination.name:
                    destination_checks += 1
                    if destination_checks == 2:
                        raise MODULE.StoreSafetyError(
                            "prepared-file-revalidation-inconclusive",
                            "simulated final fingerprint failure",
                        )
                return original_verify(
                    bound,
                    codes,
                    dir_fd=dir_fd,
                    basename=basename,
                )

            with (
                mock.patch.object(
                    MODULE,
                    "_verify_bound_regular_file_at",
                    side_effect=fail_final_fingerprint,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertEqual(
                raised.exception.details["publication_state"],
                "uncertain",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            self.assertTrue(destination.is_file())

    def test_all_standalone_terminal_boundaries_translate_raw_failures_to_uncertain(
        self,
    ) -> None:
        boundaries = (
            "_verify_installed_file_path",
            "_terminal_standalone_sidecar_absence_receipt",
            "_terminal_public_standalone_output_receipt",
            "_descriptor_bound_destination_receipt",
        )
        failures: tuple[BaseException, ...] = (
            OSError(errno.ENOENT, "simulated terminal ENOENT"),
            OSError(errno.EACCES, "simulated terminal EACCES"),
            OSError(errno.EIO, "simulated terminal EIO"),
            RuntimeError("simulated unexpected terminal descriptor failure"),
        )
        for boundary in boundaries:
            for failure in failures:
                with (
                    self.subTest(boundary=boundary, failure=type(failure).__name__),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    source = paths.group_container / MODULE.NOTE_STORE_MAIN
                    self._create_db(source)
                    destination = root / "recovered.sqlite"
                    with (
                        mock.patch.object(
                            MODULE,
                            boundary,
                            side_effect=failure,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE.merge_db(
                            source,
                            destination,
                            paths=paths,
                        )
                    self._assert_safety_code(
                        "destination-install-uncertain",
                        raised,
                    )
                    details = raised.exception.details
                    self.assertEqual(details["publication_state"], "uncertain")
                    self.assertFalse(details["retry_safe"])
                    self.assertTrue(destination.is_file())
                    locators = details["recovery_locators"]
                    self.assertIn(
                        "descriptor_bound_prepared_file",
                        locators,
                    )
                    fallback = locators["descriptor_bound_prepared_file"]
                    self.assertIn(
                        fallback["evidence_status"], {"checked", "inconclusive"}
                    )
                    self.assertIn("namespace_observations", fallback)
                    self.assertIn("content", fallback)

    def test_directory_terminal_boundaries_translate_raw_failures_to_uncertain(
        self,
    ) -> None:
        boundaries = (
            "_verify_installed_directory_path",
            "_descriptor_bound_directory_destination_receipt",
        )
        failures: tuple[BaseException, ...] = (
            OSError(errno.ENOENT, "simulated terminal ENOENT"),
            OSError(errno.EACCES, "simulated terminal EACCES"),
            OSError(errno.EIO, "simulated terminal EIO"),
            RuntimeError("simulated unexpected terminal descriptor failure"),
        )
        for boundary in boundaries:
            for failure in failures:
                with (
                    self.subTest(boundary=boundary, failure=type(failure).__name__),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    root = Path(temp_dir)
                    paths = self._make_paths(root)
                    edited = root / "edited.sqlite"
                    self._create_db(edited)
                    destination = root / "stage"
                    with (
                        mock.patch.object(
                            MODULE,
                            boundary,
                            side_effect=failure,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        MODULE.stage_patch(
                            edited,
                            destination,
                            paths=paths,
                        )
                    self._assert_safety_code(
                        "destination-install-uncertain",
                        raised,
                    )
                    details = raised.exception.details
                    self.assertEqual(details["publication_state"], "uncertain")
                    self.assertFalse(details["retry_safe"])
                    self.assertTrue(destination.is_dir())
                    self.assertIn(
                        "descriptor_bound_prepared_root",
                        details["recovery_locators"],
                    )

    def test_standalone_commit_latch_precedes_recovery_evidence_failures(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"

            with (
                mock.patch.object(
                    MODULE,
                    "_descriptor_bound_destination_receipt",
                    side_effect=RuntimeError(
                        "simulated terminal destination receipt failure"
                    ),
                ),
                mock.patch.object(
                    MODULE,
                    "_descriptor_bound_file_recovery_evidence",
                    side_effect=RuntimeError("simulated fallback evidence failure"),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(
                    source,
                    destination,
                    paths=paths,
                )

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(destination.is_file())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertEqual(
                details["post_publication_phase"],
                "standalone-output-transaction-teardown",
            )
            self.assertIn(
                "post_publication_failure",
                details["recovery_locators"],
            )
            self.assertEqual(
                details["post_publication_error_type"],
                "RuntimeError",
            )
            receipt = details["recovery_locators"]["post_publication_failure"]
            self.assertTrue(receipt["mutation_performed"])
            self.assertFalse(receipt["retry_safe"])

    def test_standalone_proved_commit_latches_before_fallback_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_rename = MODULE._rename_file_no_replace_at

            def commit_then_report_error(
                parent_fd: int,
                source_name: str,
                destination_name: str,
            ) -> None:
                original_rename(parent_fd, source_name, destination_name)
                raise OSError(
                    errno.EIO,
                    "simulated commit-then-error file rename",
                )

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_file_no_replace_at",
                    side_effect=commit_then_report_error,
                ),
                mock.patch.object(
                    MODULE,
                    "_descriptor_bound_file_recovery_evidence",
                    side_effect=RuntimeError(
                        "simulated proved-commit evidence failure"
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(destination.is_file())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(
                details["post_publication_phase"],
                "standalone-output-transaction-teardown",
            )
            self.assertIn(
                "post_publication_failure",
                details["recovery_locators"],
            )

    def test_directory_proved_commit_latches_before_fallback_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_rename = MODULE._rename_directory_no_replace_at

            def commit_then_report_error(
                parent_fd: int,
                source_name: str,
                destination_name: str,
            ) -> None:
                original_rename(parent_fd, source_name, destination_name)
                raise OSError(
                    errno.EIO,
                    "simulated commit-then-error directory rename",
                )

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace_at",
                    side_effect=commit_then_report_error,
                ),
                mock.patch.object(
                    MODULE,
                    "_descriptor_bound_directory_recovery_evidence",
                    side_effect=RuntimeError(
                        "simulated proved-commit directory evidence failure"
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(
                    edited,
                    destination,
                    paths=paths,
                )

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(destination.is_dir())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(
                details["post_publication_phase"],
                "patch-stage-transaction-teardown",
            )
            self.assertIn(
                "post_publication_failure",
                details["recovery_locators"],
            )

    def test_directory_commit_latch_precedes_recovery_evidence_failures(
        self,
    ) -> None:
        for artifact_kind in ("snapshot", "patch-stage"):
            with (
                self.subTest(artifact_kind=artifact_kind),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                edited = root / "edited.sqlite"
                self._create_db(edited, value="edited")
                destination = root / artifact_kind
                expected_phase = (
                    "snapshot-transaction-teardown"
                    if artifact_kind == "snapshot"
                    else "patch-stage-transaction-teardown"
                )

                with (
                    mock.patch.object(
                        MODULE,
                        "_verify_installed_directory_path",
                        side_effect=RuntimeError(
                            "simulated terminal directory proof failure"
                        ),
                    ),
                    mock.patch.object(
                        MODULE,
                        "_descriptor_bound_directory_recovery_evidence",
                        side_effect=RuntimeError(
                            "simulated directory fallback evidence failure"
                        ),
                    ),
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    if artifact_kind == "snapshot":
                        MODULE.copy_db(
                            paths,
                            dest=destination,
                            require_notes_quit=True,
                        )
                    else:
                        MODULE.stage_patch(
                            edited,
                            destination,
                            paths=paths,
                        )

                self._assert_safety_code(
                    "destination-install-uncertain",
                    raised,
                )
                self.assertTrue(destination.is_dir())
                details = raised.exception.details
                self.assertTrue(details["mutation_performed"])
                self.assertEqual(details["publication_state"], "uncertain")
                self.assertFalse(details["retry_safe"])
                self.assertEqual(
                    details["cleanup_state"],
                    "preserved-or-incomplete",
                )
                self.assertEqual(
                    details["post_publication_phase"],
                    expected_phase,
                )
                self.assertEqual(
                    details["post_publication_error_type"],
                    "StoreSafetyError",
                )
                self.assertEqual(
                    details["post_publication_error_code"],
                    "prepared-operation-failed",
                )
                self.assertEqual(
                    details["underlying_error_type"],
                    "RuntimeError",
                )
                receipt = details["recovery_locators"]["post_publication_failure"]
                self.assertTrue(receipt["mutation_performed"])
                self.assertFalse(receipt["retry_safe"])

    def test_post_publication_base_exceptions_are_not_overcaught(self) -> None:
        for base_exception in (KeyboardInterrupt(), SystemExit(17)):
            with (
                self.subTest(exception=type(base_exception).__name__),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                destination = root / "recovered.sqlite"
                with (
                    mock.patch.object(
                        MODULE,
                        "_terminal_standalone_sidecar_absence_receipt",
                        side_effect=base_exception,
                    ),
                    self.assertRaises(type(base_exception)),
                ):
                    MODULE.merge_db(
                        source,
                        destination,
                        paths=paths,
                    )
                self.assertTrue(destination.is_file())

    def test_preflight_writeback_binds_backup_live_store_and_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, root / "stage")
                current = live.stat()
                os.utime(
                    live,
                    ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000),
                )
                result = self._preflight_writeback(
                    paths,
                    backup_dir=root / "backup",
                    stage_dir=root / "stage",
                )
        self.assertTrue(result["ready_for_explicit_writeback"])
        self.assertFalse(result["live_mutation_performed"])
        self.assertFalse(
            result["required_whole_store_boundary"]["multi_file_atomic_swap_available"]
        )

    def test_preflight_writeback_rejects_same_bytes_on_replaced_live_object(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, root / "stage")
                replacement = root / "replacement.sqlite"
                shutil.copyfile(live, replacement)
                os.replace(replacement, live)
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._preflight_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
        self._assert_safety_code("baseline-identity-mismatch", raised)

    def test_preflight_writeback_rejects_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            live.chmod(0o600)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, root / "stage")
                live.chmod(0o640)
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._preflight_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
        self._assert_safety_code("baseline-access-policy-mismatch", raised)

    def test_preflight_rejects_noncritical_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=False,
                )
                self._stage_patch(edited, root / "stage")
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._preflight_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
        self._assert_safety_code("backup-not-writeback-grade", raised)

    def test_verify_writeback_accepts_exact_stage_and_rejects_stale_sidecar(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            baseline_mode = live.stat().st_mode & 0o777
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            stage = root / "stage"
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, stage)
                replacement = root / "replacement.sqlite"
                shutil.copyfile(stage / MODULE.NOTE_STORE_MAIN, replacement)
                replacement.chmod(baseline_mode)
                os.replace(replacement, live)
                result = self._verify_writeback(
                    paths,
                    backup_dir=root / "backup",
                    stage_dir=stage,
                )
                self.assertTrue(result["writeback_verified"])
                (paths.group_container / f"{MODULE.NOTE_STORE_MAIN}-wal").write_bytes(
                    b""
                )
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._verify_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=stage,
                    )
        self._assert_safety_code("post-writeback-file-set-mismatch", raised)

    def test_verify_writeback_rejects_in_place_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, root / "stage")
                with (
                    (root / "stage" / MODULE.NOTE_STORE_MAIN).open("rb") as source,
                    live.open("r+b") as destination,
                ):
                    destination.seek(0)
                    destination.write(source.read())
                    destination.truncate()
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._verify_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
        self._assert_safety_code("post-writeback-identity-mismatch", raised)

    def test_verify_writeback_rejects_access_policy_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            live.chmod(0o600)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                self._copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                self._stage_patch(edited, root / "stage")
                replacement = root / "replacement.sqlite"
                shutil.copyfile(root / "stage" / MODULE.NOTE_STORE_MAIN, replacement)
                replacement.chmod(0o640)
                os.replace(replacement, live)
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    self._verify_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
        self._assert_safety_code("post-writeback-access-policy-mismatch", raised)

    def test_recovery_validation_and_publication_use_no_named_temp_directories(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source, value="validated")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="edited")
            outputs = root / "outputs"
            outputs.mkdir()
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = self._stage_patch(edited, root / "stage", paths=paths)

            with mock.patch.object(
                MODULE.tempfile,
                "TemporaryDirectory",
                side_effect=AssertionError("named temporary root used"),
            ):
                recovery = MODULE.validate_database_recovery(source)
                merged = MODULE.merge_db(
                    source,
                    outputs / "merged.sqlite",
                    paths=paths,
                )
                stage_validation = MODULE.validate_patch_stage(
                    Path(stage["stage_dir"]),
                    stage["manifest_creation_receipt"],
                )
                restored = MODULE.recover_snapshot(
                    Path(snapshot["dest"]),
                    outputs / "restored.sqlite",
                    snapshot["manifest_creation_receipt"],
                    paths=paths,
                )

        self.assertEqual(recovery["sqlite_integrity"]["result"], "ok")
        self.assertEqual(merged["output_integrity"]["result"], "ok")
        self.assertEqual(stage_validation["sqlite_validation"]["result"], "ok")
        self.assertEqual(
            restored["recovered"]["output_integrity"]["result"],
            "ok",
        )

    def test_source_context_teardown_after_publication_is_unified_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            destination = root / "merged.sqlite"
            self._create_db(source)
            original_bind = MODULE._bind_source_store

            @contextmanager
            def fail_after_source_yield(
                main_path: Path,
            ) -> Iterator[MODULE._BoundSourceStore]:
                with original_bind(main_path) as store:
                    yield store
                    raise MODULE.StoreSafetyError(
                        "simulated-source-teardown",
                        "simulated source context teardown failure",
                    )

            with (
                mock.patch.object(
                    MODULE,
                    "_bind_source_store",
                    side_effect=fail_after_source_yield,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(destination.is_file())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(details["cleanup_state"], "retained")
            self.assertEqual(
                details["post_publication_error_code"],
                "simulated-source-teardown",
            )
            receipt = details["recovery_locators"]["post_publication_failure"]
            self.assertEqual(receipt["mutation_performed"], True)
            self.assertEqual(receipt["publication_state"], "uncertain")
            self.assertFalse(receipt["retry_safe"])
            self.assertEqual(
                receipt["phase"],
                "source-store-transaction-teardown",
            )

    def test_directory_artifact_scope_teardown_after_publication_is_uncertain(
        self,
    ) -> None:
        for artifact_kind in ("snapshot", "patch-stage"):
            with (
                self.subTest(artifact_kind=artifact_kind),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                paths = self._make_paths(root)
                source = paths.group_container / MODULE.NOTE_STORE_MAIN
                self._create_db(source)
                edited = root / "edited.sqlite"
                self._create_db(edited)
                destination = root / artifact_kind
                original_scope = MODULE._bind_live_safe_destination_parent
                expected_phase = (
                    "snapshot-transaction-teardown"
                    if artifact_kind == "snapshot"
                    else "patch-stage-transaction-teardown"
                )

                @contextmanager
                def fail_after_destination_scope_yield(
                    selected_paths: MODULE.NoteStorePaths,
                    selected_destination: Path,
                ) -> Iterator[MODULE._LiveDestinationScope]:
                    with original_scope(
                        selected_paths,
                        selected_destination,
                    ) as scope:
                        yield scope
                        raise MODULE.StoreSafetyError(
                            "simulated-destination-scope-teardown",
                            "simulated destination context teardown failure",
                        )

                with (
                    mock.patch.object(
                        MODULE,
                        "_bind_live_safe_destination_parent",
                        side_effect=fail_after_destination_scope_yield,
                    ),
                    mock.patch.object(
                        MODULE,
                        "notes_is_running",
                        return_value=False,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    if artifact_kind == "snapshot":
                        MODULE.copy_db(
                            paths,
                            dest=destination,
                            require_notes_quit=True,
                        )
                    else:
                        MODULE.stage_patch(
                            edited,
                            destination,
                            paths=paths,
                        )

                self._assert_safety_code(
                    "destination-install-uncertain",
                    raised,
                )
                self.assertTrue(destination.is_dir())
                details = raised.exception.details
                self.assertTrue(details["mutation_performed"])
                self.assertEqual(details["publication_state"], "uncertain")
                self.assertFalse(details["retry_safe"])
                self.assertEqual(details["cleanup_state"], "retained")
                self.assertEqual(
                    details["post_publication_error_code"],
                    "simulated-destination-scope-teardown",
                )
                receipt = details["recovery_locators"]["post_publication_failure"]
                self.assertEqual(receipt["phase"], expected_phase)

    def test_snapshot_context_teardown_after_recovery_publication_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            source = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = self._copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            destination = root / "recovered.sqlite"
            original_validate = MODULE._validated_snapshot_artifact

            @contextmanager
            def fail_after_snapshot_yield(
                *args: object,
                **kwargs: object,
            ) -> Iterator[MODULE._ValidatedSnapshotArtifact]:
                with original_validate(*args, **kwargs) as artifact:
                    yield artifact
                    raise MODULE.StoreSafetyError(
                        "simulated-snapshot-teardown",
                        "simulated snapshot context teardown failure",
                    )

            with (
                mock.patch.object(
                    MODULE,
                    "_validated_snapshot_artifact",
                    side_effect=fail_after_snapshot_yield,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.recover_snapshot(
                    Path(snapshot["dest"]),
                    destination,
                    snapshot["manifest_creation_receipt"],
                    paths=paths,
                )

            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue(destination.is_file())
            details = raised.exception.details
            self.assertTrue(details["mutation_performed"])
            self.assertEqual(details["publication_state"], "uncertain")
            self.assertFalse(details["retry_safe"])
            self.assertEqual(
                details["post_publication_error_code"],
                "simulated-snapshot-teardown",
            )
            receipt = details["recovery_locators"]["post_publication_failure"]
            self.assertEqual(
                receipt["phase"],
                "snapshot-recovery-transaction-teardown",
            )

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
