from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
WRAPPER_PATH = REPO_ROOT / "scripts/apple_notes_helper.sh"
EXPECTED_FOLDERS = [
    {"account": "", "folder": "Inbox"},
    {"account": "", "folder": "Daily Notes"},
]
EXPECTED_FOLDERS_JSON = json.dumps(EXPECTED_FOLDERS, ensure_ascii=False, indent=2)


class AppleNotesShellWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self._temporary_path = Path(self._temporary_directory.name)
        self._osascript_marker = self._temporary_path / "osascript-called"

        self._osascript_path = self._write_executable(
            "fake-osascript",
            """#!/bin/sh
if [ -n "${FAKE_OSASCRIPT_MARKER:-}" ]; then
  printf 'called\n' >> "$FAKE_OSASCRIPT_MARKER"
fi
printf '%s' "${FAKE_OSASCRIPT_STDOUT:-}"
printf '%s' "${FAKE_OSASCRIPT_STDERR:-}" >&2
exit "${FAKE_OSASCRIPT_EXIT_CODE:-0}"
""",
        )
        self._write_executable(
            "pgrep",
            """#!/bin/sh
exit "${FAKE_PGREP_EXIT_CODE:-1}"
""",
        )

    def _write_executable(self, name: str, source: str) -> Path:
        path = self._temporary_path / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
        return path

    def _run_wrapper(
        self,
        command: str,
        *arguments: str,
        osascript_stdout: str = "Inbox, Daily Notes\n",
        osascript_stderr: str = "",
        osascript_exit_code: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_OSASCRIPT_EXIT_CODE": str(osascript_exit_code),
                "FAKE_OSASCRIPT_MARKER": str(self._osascript_marker),
                "FAKE_OSASCRIPT_STDERR": osascript_stderr,
                "FAKE_OSASCRIPT_STDOUT": osascript_stdout,
                "FAKE_PGREP_EXIT_CODE": "1",
                "OSASCRIPT_BIN": str(self._osascript_path),
                "PATH": f"{self._temporary_path}{os.pathsep}{environment['PATH']}",
                "PYTHON_BIN": sys.executable,
            }
        )
        return subprocess.run(
            ["bash", str(WRAPPER_PATH), command, *arguments],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_list_folders_preserves_success_output(self) -> None:
        result = self._run_wrapper("list-folders")

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout,
            f'{{\n  "folders": {EXPECTED_FOLDERS_JSON}\n}}\n',
        )
        self.assertEqual(result.stderr, "")

    def test_probe_notes_preserves_success_output(self) -> None:
        result = self._run_wrapper("probe-notes")

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout,
            "{\n"
            '  "notes_running": false,\n'
            '  "automation_ok": true,\n'
            f'  "folders": {EXPECTED_FOLDERS_JSON}\n'
            "}\n",
        )
        self.assertEqual(result.stderr, "")

    def test_list_folders_propagates_osascript_failure(self) -> None:
        result = self._run_wrapper(
            "list-folders",
            osascript_stdout="ignored output",
            osascript_stderr="automation denied\n",
            osascript_exit_code=23,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "automation denied\n")

    def test_probe_notes_propagates_osascript_failure(self) -> None:
        result = self._run_wrapper(
            "probe-notes",
            osascript_stdout="ignored output",
            osascript_stderr="automation denied\n",
            osascript_exit_code=23,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "automation denied\n")

    def test_list_folders_rejects_extra_arguments(self) -> None:
        result = self._run_wrapper("list-folders", "unexpected")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "Unsupported list-folders argument: unexpected\n",
        )
        self.assertFalse(self._osascript_marker.exists())

    def test_probe_notes_rejects_extra_arguments(self) -> None:
        result = self._run_wrapper("probe-notes", "unexpected")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "Unsupported probe-notes argument: unexpected\n",
        )
        self.assertFalse(self._osascript_marker.exists())


if __name__ == "__main__":
    unittest.main()
