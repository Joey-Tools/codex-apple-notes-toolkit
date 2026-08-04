from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SKILL = REPO_ROOT / ".agents" / "skills" / "apple-notes-db-guardrails"


class AppleNotesSkillPackageTests(unittest.TestCase):
    def test_relocated_packaged_supervisor_creates_and_validates_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            copied_skill = root / "relocated-skill"
            shutil.copytree(SOURCE_SKILL, copied_skill)

            group_container = root / "group-container"
            app_container = root / "app-container"
            group_container.mkdir()
            app_container.mkdir()
            edited = root / "edited.sqlite"
            with sqlite3.connect(edited) as connection:
                connection.execute("CREATE TABLE sample(value TEXT)")
                connection.execute("INSERT INTO sample VALUES ('relocated')")

            stage = root / "stage"
            result_file = root / "stage.creation-result.json"
            supervisor = (
                copied_skill / "scripts" / "apple_notes_directory_supervisor.py"
            )
            helper = copied_skill / "scripts" / "apple_notes_db.py"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    str(supervisor),
                    "--helper",
                    str(helper),
                    "--python",
                    sys.executable,
                    "--",
                    "stage-patch",
                    "--group-container",
                    str(group_container),
                    "--app-container",
                    str(app_container),
                    "--src",
                    str(edited),
                    "--dest",
                    str(stage),
                    "--result-file",
                    str(result_file),
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

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(Path(payload["stage_dir"]), stage)
            self.assertEqual(
                (stage / "NoteStore.sqlite").stat().st_mode & 0o777,
                0o600,
            )
            self.assertTrue((stage / "patch-manifest.json").is_file())
            self.assertTrue(result_file.is_file())
            self.assertEqual(
                stat.S_IMODE(os.stat(result_file, follow_symlinks=False).st_mode),
                0o600,
            )
            self.assertEqual(
                list(root.rglob(".apple-notes-create-*")),
                [],
            )


if __name__ == "__main__":
    unittest.main()
