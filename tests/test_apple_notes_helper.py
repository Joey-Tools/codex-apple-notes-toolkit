from __future__ import annotations

import builtins
import importlib.util
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".agents/skills/apple-notes-db-guardrails"
SCRIPT_PATH = SKILL_DIR / "scripts/apple_notes_db.py"
SPEC = importlib.util.spec_from_file_location("apple_notes_db", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
WRAPPER_PATH = REPO_ROOT / "scripts/apple_notes_helper.sh"
COMPATIBILITY_SCRIPT = REPO_ROOT / "scripts/apple_notes_helper.py"
HOT_JOURNAL_FIXTURE = REPO_ROOT / "tests/create_hot_rollback_journal.py"


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

    def _create_db(self, path: Path, value: str = "ok") -> None:
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO sample(value) VALUES (?)", (value,))
            conn.commit()

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
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    Path(snapshot["dest"]) / "group.com.apple.notes",
                    MODULE.validate_snapshot,
                    Path(snapshot["dest"]),
                    "snapshot-file-set-mismatch",
                ),
                (
                    stage,
                    MODULE.validate_patch_stage,
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
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("preflight-writeback", result.stdout)

    def test_compatibility_launcher_exports_packaged_api(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "compatibility_helper", COMPATIBILITY_SCRIPT
        )
        assert spec is not None
        assert spec.loader is not None
        compatibility = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = compatibility
        spec.loader.exec_module(compatibility)
        self.assertEqual(compatibility.HELPER_PATH, SCRIPT_PATH)
        self.assertTrue(callable(compatibility.main))
        self.assertEqual(
            compatibility.NoteStorePaths().note_store_files(),
            MODULE.NoteStorePaths().note_store_files(),
        )

    def test_compatibility_python_api_preserves_merged_db_alias(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "compatibility_helper_merge", COMPATIBILITY_SCRIPT
        )
        assert spec is not None
        assert spec.loader is not None
        compatibility = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = compatibility
        spec.loader.exec_module(compatibility)
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
                    result = MODULE.copy_db(
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
            ):
                result = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )

        self.assertEqual(result["sqlite_validation"]["result"], "ok")

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
                result = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )

            self.assertTrue(attacked)
            self.assertEqual(replacement_entries, [])
            self.assertEqual(
                MODULE.validate_snapshot(Path(result["dest"]))["sqlite_validation"][
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
                MODULE.copy_db(
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
                        MODULE.copy_db(
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
                MODULE.copy_db(
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
                MODULE.copy_db(
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
                MODULE.copy_db(
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
                    MODULE.copy_db(
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
            original_discovery = MODULE._discover_database_files
            discovery_count = 0

            def journal_appears(main_path: Path) -> list[Path]:
                nonlocal discovery_count
                discovery_count += 1
                if discovery_count == 2:
                    journal.write_bytes(b"appeared-during-binding")
                return original_discovery(main_path)

            with (
                mock.patch.object(
                    MODULE,
                    "_discover_database_files",
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
                    MODULE.copy_db(
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
                MODULE.copy_db(
                    paths,
                    dest=destination,
                    require_notes_quit=False,
                )
            self._assert_safety_code("destination-exists", raised)
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
                MODULE.stage_patch(edited, destination)
            self._assert_safety_code("destination-exists", raised)
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
                MODULE.copy_db(
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
                MODULE.stage_patch(edited, destination)
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
                MODULE.stage_patch(edited, destination)

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
                result = MODULE.copy_db(
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
            original_scan = MODULE._scan_exact_directory_entries
            attacked = False

            def replace_parent_before_public_scan(
                path: Path,
                expected_types: dict[str, int],
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal attacked
                if not attacked and path == destination:
                    attacked = True
                    root.rename(parked)
                    root.mkdir(mode=0o700)
                return original_scan(path, expected_types, **kwargs)

            try:
                with (
                    mock.patch.object(MODULE, "notes_is_running", return_value=False),
                    mock.patch.object(
                        MODULE,
                        "_scan_exact_directory_entries",
                        side_effect=replace_parent_before_public_scan,
                    ),
                    self.assertRaises(MODULE.StoreSafetyError) as raised,
                ):
                    MODULE.copy_db(
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
                MODULE.copy_db(
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
                result = MODULE.copy_db(
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
                source_uri: str,
                source_path: Path,
            ) -> bytes:
                nonlocal attacked
                attacked = True
                os.replace(wal, parked)
                os.replace(replacement, wal)
                return original_backup(source_uri, source_path)

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
                source_uri: str,
                source_path: Path,
            ) -> bytes:
                nonlocal attacked
                attacked = True
                os.replace(source_dir, parked_dir)
                os.replace(replacement_dir, source_dir)
                try:
                    return original_backup(source_uri, source_path)
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
                source_uri: str,
                source_path: Path,
            ) -> bytes:
                nonlocal attacked
                attacked = True
                os.replace(source_dir, parked_dir)
                os.replace(replacement_dir, source_dir)
                return original_backup(source_uri, source_path)

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

    def test_bound_sqlite_integrity_ignores_path_swap_during_connect(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / MODULE.NOTE_STORE_MAIN
            self._create_db(database)
            replacement = root / "replacement.sqlite"
            replacement.write_bytes(b"not a sqlite database")
            parked = root / "validated.sqlite"
            original_connect = MODULE.sqlite3.connect
            attacked = False

            def connect_with_swap(
                target: object,
                *args: object,
                **kwargs: object,
            ) -> sqlite3.Connection:
                nonlocal attacked
                descriptor_uri = isinstance(target, str) and target.startswith(
                    "file:/dev/fd/"
                )
                if attacked or not descriptor_uri:
                    return original_connect(target, *args, **kwargs)
                attacked = True
                os.replace(database, parked)
                os.replace(replacement, database)
                try:
                    return original_connect(target, *args, **kwargs)
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
                    side_effect=connect_with_swap,
                ),
            ):
                integrity = MODULE._sqlite_integrity(bound)
        self.assertTrue(attacked)
        self.assertEqual(integrity["result"], "ok")

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
            ) -> dict[str, object]:
                nonlocal attacked, moved_prepared, replacement
                if attacked or not isinstance(database, MODULE._BoundRegularFile):
                    return original_integrity(database)
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
                snapshot = MODULE.copy_db(
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
                MODULE.validate_snapshot(Path(snapshot["dest"]))
        self._assert_safety_code("snapshot-content-mismatch", raised)

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
                        snapshot = MODULE.copy_db(
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
                        MODULE.validate_snapshot(snapshot_dir)
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
                    stage = Path(
                        MODULE.stage_patch(edited, root / "stage")["stage_dir"]
                    )
                    database = stage / MODULE.NOTE_STORE_MAIN
                    if attack == "root-identity":
                        replacement = root / "replacement-stage"
                        parked = root / "original-stage"
                        shutil.copytree(stage, replacement)
                        stage.rename(parked)
                        replacement.rename(stage)
                    elif attack == "file-identity":
                        replacement = stage / ".replacement.sqlite"
                        shutil.copy2(database, replacement)
                        os.replace(replacement, database)
                    else:
                        target = stage if attack == "root-access" else database
                        current_mode = MODULE.stat.S_IMODE(target.stat().st_mode)
                        target.chmod(0o750 if current_mode != 0o750 else 0o700)
                    with self.assertRaises(MODULE.StoreSafetyError) as raised:
                        MODULE.validate_patch_stage(stage)
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
                            MODULE.stage_patch(edited, root / "stage")["stage_dir"]
                        )
                        manifest_path = stage / MODULE.PATCH_MANIFEST
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        if receipt_name == "stage_directory":
                            receipt = manifest["creation_receipts"]["stage_directory"]
                            expected_code = "stage-directory-access-policy-mismatch"
                        else:
                            receipt = manifest["database"]
                            expected_code = "patch-file-access-policy-mismatch"
                        receipt["access_policy"][field] += 1
                        manifest_path.write_text(
                            json.dumps(manifest),
                            encoding="utf-8",
                        )
                        with self.assertRaises(MODULE.StoreSafetyError) as raised:
                            MODULE.validate_patch_stage(stage)
                        self._assert_safety_code(expected_code, raised)

    def test_v1_manifests_fail_closed_without_v2_creation_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            stage = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    Path(snapshot["dest"]) / MODULE.SNAPSHOT_MANIFEST,
                    MODULE.validate_snapshot,
                    Path(snapshot["dest"]),
                    "apple-notes-snapshot/v1",
                ),
                (
                    stage / MODULE.PATCH_MANIFEST,
                    MODULE.validate_patch_stage,
                    stage,
                    "apple-notes-patch/v1",
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
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_store = snapshot_dir / "group.com.apple.notes"
            stage = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            for directory in (snapshot_store, stage):
                current = directory.stat()
                os.utime(
                    directory,
                    ns=(
                        current.st_atime_ns,
                        current.st_mtime_ns + 1_000_000_000,
                    ),
                )
            snapshot_validation = MODULE.validate_snapshot(snapshot_dir)
            stage_validation = MODULE.validate_patch_stage(stage)
        self.assertEqual(snapshot_validation["sqlite_validation"]["result"], "ok")
        self.assertEqual(stage_validation["sqlite_validation"]["result"], "ok")

    def test_patch_validation_detects_directory_identity_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            original_integrity = MODULE._sqlite_integrity

            def replace_after_integrity(path: Path) -> dict[str, object]:
                result = original_integrity(path)
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
                MODULE.validate_patch_stage(stage)
        self._assert_safety_code("directory-identity-mismatch", raised)

    def test_patch_validation_detects_directory_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            stage = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            stage.chmod(0o700)
            original_integrity = MODULE._sqlite_integrity

            def chmod_after_integrity(path: Path) -> dict[str, object]:
                result = original_integrity(path)
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
                MODULE.validate_patch_stage(stage)
        self._assert_safety_code("directory-access-policy-mismatch", raised)

    def test_stage_patch_normalizes_and_validates_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited, value="patched")
            result = MODULE.stage_patch(edited, root / "stage")
            stage_dir = Path(result["stage_dir"])
            self.assertEqual(
                {path.name for path in stage_dir.iterdir()},
                {MODULE.NOTE_STORE_MAIN, MODULE.PATCH_MANIFEST},
            )
            validation = MODULE.validate_patch_stage(stage_dir)
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
                result = MODULE.stage_patch(edited, root / "stage")

            self.assertTrue(attacked)
            self.assertEqual(replacement_entries, [])
            self.assertEqual(
                MODULE.validate_patch_stage(Path(result["stage_dir"]))[
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
            MODULE.stage_patch(edited, stage)
            (stage / f"{MODULE.NOTE_STORE_MAIN}-wal").write_bytes(b"")
            with self.assertRaises(MODULE.StoreSafetyError) as raised:
                MODULE.validate_patch_stage(stage)
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
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN,
                    MODULE.validate_snapshot,
                    snapshot_dir,
                    "snapshot-file-identity-mismatch",
                ),
                (
                    stage_dir / MODULE.NOTE_STORE_MAIN,
                    MODULE.validate_patch_stage,
                    stage_dir,
                    "patch-file-identity-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(target=target):
                    original_integrity = MODULE._sqlite_integrity
                    attacked = False

                    def replace_after_integrity(path: Path) -> dict[str, object]:
                        nonlocal attacked
                        result = original_integrity(path)
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
                            "_sqlite_integrity",
                            side_effect=replace_after_integrity,
                        ),
                        self.assertRaises(MODULE.StoreSafetyError) as raised,
                    ):
                        validator(argument)
                    self._assert_safety_code(expected_code, raised)

    def test_validators_detect_file_access_change_during_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN,
                    MODULE.validate_snapshot,
                    snapshot_dir,
                    "snapshot-file-access-policy-mismatch",
                ),
                (
                    stage_dir / MODULE.NOTE_STORE_MAIN,
                    MODULE.validate_patch_stage,
                    stage_dir,
                    "patch-file-access-policy-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(target=target):
                    target.chmod(0o600)
                    original_integrity = MODULE._sqlite_integrity
                    attacked = False

                    def chmod_after_integrity(path: Path) -> dict[str, object]:
                        nonlocal attacked
                        result = original_integrity(path)
                        if not attacked:
                            attacked = True
                            target.chmod(0o640)
                        return result

                    with (
                        mock.patch.object(
                            MODULE,
                            "_sqlite_integrity",
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
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            stage_dir = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            targets = (
                (
                    snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN,
                    MODULE.validate_snapshot,
                    snapshot_dir,
                    "snapshot-content-mismatch",
                ),
                (
                    stage_dir / MODULE.NOTE_STORE_MAIN,
                    MODULE.validate_patch_stage,
                    stage_dir,
                    "patch-content-mismatch",
                ),
            )
            for target, validator, argument, expected_code in targets:
                with self.subTest(target=target):
                    original_integrity = MODULE._sqlite_integrity
                    attacked = False

                    def mutate_after_integrity(path: Path) -> dict[str, object]:
                        nonlocal attacked
                        result = original_integrity(path)
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
                            "_sqlite_integrity",
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
            stage_dir = Path(MODULE.stage_patch(edited, root / "stage")["stage_dir"])
            staged_db = stage_dir / MODULE.NOTE_STORE_MAIN
            original_integrity = MODULE._sqlite_integrity
            touched = False

            def touch_after_integrity(path: Path) -> dict[str, object]:
                nonlocal touched
                result = original_integrity(path)
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
                validation = MODULE.validate_patch_stage(stage_dir)
        transitions = validation["source_integrity"]["database"]["metadata_transitions"]
        self.assertIn("mtime_ns", transitions)

    def test_recover_snapshot_uses_validated_clone_after_source_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="validated")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            snapshot_db = (
                snapshot_dir / "group.com.apple.notes" / MODULE.NOTE_STORE_MAIN
            )
            original_recover = MODULE._recover_validated_clone_to_standalone

            def swap_then_recover(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                replacement = root / "replacement.sqlite"
                self._create_db(replacement, value="replacement")
                os.replace(replacement, snapshot_db)
                return original_recover(recovered_main, out, **kwargs)

            recovered = root / "recovered.sqlite"
            with mock.patch.object(
                MODULE,
                "_recover_validated_clone_to_standalone",
                side_effect=swap_then_recover,
            ):
                MODULE.recover_snapshot(snapshot_dir, recovered)
            with closing(sqlite3.connect(recovered)) as conn:
                recovered_value = conn.execute("SELECT value FROM sample").fetchone()[0]
            with closing(sqlite3.connect(snapshot_db)) as conn:
                current_value = conn.execute("SELECT value FROM sample").fetchone()[0]
        self.assertEqual(recovered_value, "validated")
        self.assertEqual(current_value, "replacement")

    def test_recover_snapshot_preserves_snapshot_source_integrity_receipts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            validation = MODULE.validate_snapshot(snapshot_dir)
            result = MODULE.recover_snapshot(
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
                snapshot = MODULE.copy_db(
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
                MODULE.recover_snapshot(snapshot_dir, recovered)

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
                snapshot = MODULE.copy_db(
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
                MODULE.recover_snapshot(snapshot_dir, recovered)
            self._assert_safety_code(
                "prepared-file-identity-mismatch",
                raised,
            )
            self.assertFalse(recovered.exists())

    def test_recover_snapshot_ignores_wal_injected_beside_validated_artifact(
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
                snapshot = MODULE.copy_db(
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
            with mock.patch.object(
                MODULE,
                "_recover_validated_clone_to_standalone",
                side_effect=inject_wal_then_recover,
            ):
                MODULE.recover_snapshot(snapshot_dir, recovered)
            with closing(sqlite3.connect(recovered)) as conn:
                recovered_value = conn.execute("SELECT value FROM sample").fetchone()[0]
        self.assertTrue(injected)
        self.assertEqual(recovered_value, "validated")

    def test_recover_snapshot_binds_clone_during_connect_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(
                paths.group_container / MODULE.NOTE_STORE_MAIN,
                value="validated",
            )
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                snapshot = MODULE.copy_db(
                    paths,
                    dest=root / "snapshot",
                    require_notes_quit=True,
                )
            snapshot_dir = Path(snapshot["dest"])
            original_recover = MODULE._recover_validated_clone_to_standalone
            original_connect = MODULE.sqlite3.connect
            attacked = False

            def recover_with_connect_swap(
                recovered_main: Path,
                out: Path,
                **kwargs: object,
            ) -> dict[str, object]:
                replacement = recovered_main.with_name("connect-replacement.sqlite")
                parked = recovered_main.with_name("connect-validated.sqlite")
                self._create_db(replacement, value="replacement")

                def connect_with_swap(
                    database: object,
                    *args: object,
                    **connect_kwargs: object,
                ) -> sqlite3.Connection:
                    nonlocal attacked
                    descriptor_uri = isinstance(database, str) and database.startswith(
                        "file:/dev/fd/"
                    )
                    if attacked or (database != recovered_main and not descriptor_uri):
                        return original_connect(
                            database,
                            *args,
                            **connect_kwargs,
                        )
                    attacked = True
                    os.replace(recovered_main, parked)
                    os.replace(replacement, recovered_main)
                    try:
                        return original_connect(
                            database,
                            *args,
                            **connect_kwargs,
                        )
                    finally:
                        os.replace(recovered_main, replacement)
                        os.replace(parked, recovered_main)

                with mock.patch.object(
                    MODULE.sqlite3,
                    "connect",
                    side_effect=connect_with_swap,
                ):
                    return original_recover(recovered_main, out, **kwargs)

            recovered = root / "recovered.sqlite"
            with mock.patch.object(
                MODULE,
                "_recover_validated_clone_to_standalone",
                side_effect=recover_with_connect_swap,
            ):
                MODULE.recover_snapshot(snapshot_dir, recovered)
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
                MODULE.copy_db(
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

    def test_cleanup_preserves_root_swapped_before_recursive_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_listdir = MODULE.os.listdir
            attacked = False
            moved_root: Path | None = None
            replacement_root: Path | None = None

            def reject_publication(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                raise MODULE.StoreSafetyError(
                    "destination-exists",
                    f"simulated publication failure: {source} -> {target}",
                )

            def swap_after_identity_observation(
                directory: object,
            ) -> list[str]:
                nonlocal attacked, moved_root, replacement_root
                if not attacked and isinstance(directory, int):
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
                return original_listdir(directory)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=reject_publication,
                ),
                mock.patch.object(
                    MODULE.os,
                    "listdir",
                    side_effect=swap_after_identity_observation,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(edited, destination)
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
                MODULE.stage_patch(edited, destination)
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

            def reject_publication(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                raise MODULE.StoreSafetyError(
                    "destination-exists",
                    f"simulated publication failure: {source} -> {target}",
                )

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=reject_publication,
                ),
                mock.patch.object(
                    MODULE.os,
                    "listdir",
                    side_effect=OSError(
                        MODULE.errno.EIO,
                        "simulated inventory failure",
                    ),
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(edited, destination)
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
            original_listdir = MODULE.os.listdir
            attacked = False
            moved_prepared: Path | None = None
            replacement: Path | None = None

            def reject_publication(
                source: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                raise MODULE.StoreSafetyError(
                    "destination-exists",
                    f"simulated publication failure: {source} -> {target}",
                )

            def replace_leaf_after_root_binding(
                directory: object,
            ) -> list[str]:
                nonlocal attacked, moved_prepared, replacement
                if not attacked and isinstance(directory, int):
                    attacked = True
                    partial = next(root.glob(".stage.partial-*"))
                    prepared = partial / MODULE.NOTE_STORE_MAIN
                    moved_prepared = prepared.with_name(f"{prepared.name}.owned")
                    prepared.rename(moved_prepared)
                    prepared.write_text("replacement", encoding="utf-8")
                    replacement = prepared
                return original_listdir(directory)

            with (
                mock.patch.object(
                    MODULE,
                    "_publish_directory_no_replace",
                    side_effect=reject_publication,
                ),
                mock.patch.object(
                    MODULE.os,
                    "listdir",
                    side_effect=replace_leaf_after_root_binding,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(edited, destination)
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
                MODULE.stage_patch(edited, destination)
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
                MODULE.stage_patch(edited, destination)
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
                MODULE.copy_db(
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
                MODULE.stage_patch(edited, destination)
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

    def test_preflight_writeback_binds_backup_live_store_and_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            live = paths.group_container / MODULE.NOTE_STORE_MAIN
            self._create_db(live, value="before")
            edited = root / "edited.sqlite"
            self._create_db(edited, value="after")
            with mock.patch.object(MODULE, "notes_is_running", return_value=False):
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                MODULE.stage_patch(edited, root / "stage")
                current = live.stat()
                os.utime(
                    live,
                    ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000),
                )
                result = MODULE.preflight_writeback(
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
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                MODULE.stage_patch(edited, root / "stage")
                replacement = root / "replacement.sqlite"
                shutil.copyfile(live, replacement)
                os.replace(replacement, live)
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE.preflight_writeback(
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
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                MODULE.stage_patch(edited, root / "stage")
                live.chmod(0o640)
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE.preflight_writeback(
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
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=False,
                )
                MODULE.stage_patch(edited, root / "stage")
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE.preflight_writeback(
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
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                MODULE.stage_patch(edited, stage)
                replacement = root / "replacement.sqlite"
                shutil.copyfile(stage / MODULE.NOTE_STORE_MAIN, replacement)
                replacement.chmod(baseline_mode)
                os.replace(replacement, live)
                result = MODULE.verify_writeback(
                    paths,
                    backup_dir=root / "backup",
                    stage_dir=stage,
                )
                self.assertTrue(result["writeback_verified"])
                (paths.group_container / f"{MODULE.NOTE_STORE_MAIN}-wal").write_bytes(
                    b""
                )
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE.verify_writeback(
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
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                MODULE.stage_patch(edited, root / "stage")
                with (
                    (root / "stage" / MODULE.NOTE_STORE_MAIN).open("rb") as source,
                    live.open("r+b") as destination,
                ):
                    destination.seek(0)
                    destination.write(source.read())
                    destination.truncate()
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE.verify_writeback(
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
                MODULE.copy_db(
                    paths,
                    dest=root / "backup",
                    require_notes_quit=True,
                )
                MODULE.stage_patch(edited, root / "stage")
                replacement = root / "replacement.sqlite"
                shutil.copyfile(root / "stage" / MODULE.NOTE_STORE_MAIN, replacement)
                replacement.chmod(0o640)
                os.replace(replacement, live)
                with self.assertRaises(MODULE.StoreSafetyError) as raised:
                    MODULE.verify_writeback(
                        paths,
                        backup_dir=root / "backup",
                        stage_dir=root / "stage",
                    )
        self._assert_safety_code("post-writeback-access-policy-mismatch", raised)

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
