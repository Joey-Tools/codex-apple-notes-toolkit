from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
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
            original_rename = MODULE._rename_directory_no_replace

            def destination_appears(source: Path, target: Path) -> None:
                target.mkdir()
                original_rename(source, target)

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace",
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
            self.assertEqual(list(root.glob(".snapshot.partial-*")), [])

    def test_patch_publication_does_not_replace_directory_appearing_after_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            edited = root / "edited.sqlite"
            self._create_db(edited)
            destination = root / "stage"
            original_rename = MODULE._rename_directory_no_replace

            def destination_appears(source: Path, target: Path) -> None:
                target.mkdir()
                original_rename(source, target)

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace",
                    side_effect=destination_appears,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(edited, destination)
            self._assert_safety_code("destination-exists", raised)
            self.assertEqual(list(destination.iterdir()), [])
            self.assertEqual(list(root.glob(".stage.partial-*")), [])

    def test_snapshot_publication_reports_commit_then_error_as_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = self._make_paths(root)
            self._create_db(paths.group_container / MODULE.NOTE_STORE_MAIN)
            destination = root / "snapshot"
            original_rename = MODULE._rename_directory_no_replace

            def commit_then_error(source: Path, target: Path) -> None:
                original_rename(source, target)
                raise OSError(MODULE.errno.EIO, "simulated post-commit error")

            with (
                mock.patch.object(MODULE, "notes_is_running", return_value=False),
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace",
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
            original_rename = MODULE._rename_directory_no_replace

            def commit_then_error(source: Path, target: Path) -> None:
                original_rename(source, target)
                raise OSError(MODULE.errno.EIO, "simulated post-commit error")

            with (
                mock.patch.object(
                    MODULE,
                    "_rename_directory_no_replace",
                    side_effect=commit_then_error,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.stage_patch(edited, destination)
            self._assert_safety_code("destination-install-uncertain", raised)
            self.assertTrue((destination / MODULE.PATCH_MANIFEST).is_file())
            self.assertEqual(list(root.glob(".stage.partial-*")), [])

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
            self.assertFalse(merged.with_name(f"{merged.name}-wal").exists())
            self.assertFalse(merged.with_name(f"{merged.name}-shm").exists())

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
            self.assertEqual(list(root.glob(".stage.partial-*")), [])

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
            self.assertEqual(list(root.glob(".snapshot.partial-*")), [])

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
            self.assertEqual(list(root.glob(".stage.partial-*")), [])

    def test_single_file_link_then_error_is_uncertain_and_preserves_locators(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_link = MODULE.os.link

            def link_then_error(
                prepared: Path,
                target: Path,
                **kwargs: object,
            ) -> None:
                original_link(prepared, target, **kwargs)
                raise OSError(MODULE.errno.EIO, "simulated link completion error")

            with (
                mock.patch.object(MODULE.os, "link", side_effect=link_then_error),
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
            self.assertTrue(Path(locators["prepared"]).is_file())

    def test_single_file_unlink_failure_reports_committed_cleanup_incomplete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_unlink = MODULE.os.unlink

            def fail_prepared_unlink(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> None:
                candidate = Path(path) if not isinstance(path, int) else None
                if (
                    candidate is not None
                    and candidate.parent == root
                    and candidate.name.startswith(".recovered.sqlite.tmp-")
                ):
                    raise OSError(MODULE.errno.EIO, "simulated unlink failure")
                original_unlink(path, *args, **kwargs)

            with (
                mock.patch.object(
                    MODULE.os,
                    "unlink",
                    side_effect=fail_prepared_unlink,
                ),
                self.assertRaises(MODULE.StoreSafetyError) as raised,
            ):
                MODULE.merge_db(source, destination)
            self._assert_safety_code(
                "destination-install-committed-cleanup-incomplete",
                raised,
            )
            self.assertEqual(
                raised.exception.details["publication_state"],
                "committed",
            )
            self.assertFalse(raised.exception.details["retry_safe"])
            locators = raised.exception.details["recovery_locators"]
            self.assertTrue(Path(locators["destination"]).is_file())
            self.assertTrue(Path(locators["prepared"]).is_file())

    def test_single_file_parent_fsync_failure_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"

            with (
                mock.patch.object(
                    MODULE,
                    "_fsync_directory",
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

    def test_single_file_final_fingerprint_failure_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / MODULE.NOTE_STORE_MAIN
            self._create_db(source)
            destination = root / "recovered.sqlite"
            original_verify = MODULE._verify_bound_regular_file
            destination_checks = 0

            def fail_final_fingerprint(
                bound: object,
                codes: object,
                *,
                path: Path | None = None,
            ) -> dict[str, object]:
                nonlocal destination_checks
                if path == destination:
                    destination_checks += 1
                    if destination_checks == 3:
                        raise MODULE.StoreSafetyError(
                            "prepared-file-revalidation-inconclusive",
                            "simulated final fingerprint failure",
                        )
                return original_verify(bound, codes, path=path)

            with (
                mock.patch.object(
                    MODULE,
                    "_verify_bound_regular_file",
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
