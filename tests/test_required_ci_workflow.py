from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


def top_level_job_ids(workflow: str) -> list[str]:
    in_jobs = False
    job_ids: list[str] = []
    for line in workflow.splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" "):
            break
        if in_jobs and line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            job_ids.append(line[2:-1])
    return job_ids


class RequiredCiWorkflowTests(unittest.TestCase):
    def test_entry_wraps_only_the_required_linux_test(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/required-ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("on:\n  workflow_call:\n", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertEqual(top_level_job_ids(workflow), ["test"])
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn(
            "bash -n scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh",
            workflow,
        )
        self.assertIn(
            "shellcheck scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh",
            workflow,
        )
        self.assertIn(
            "python3 -m unittest discover -s tests -p 'test_*.py'", workflow
        )
        for forbidden in (
            "pull_request:",
            "pull_request_target:",
            "push:",
            "macos-test",
            "macos-latest",
            "secrets.",
            "contents: write",
            "id-" + "token: write",
            "statuses: write",
        ):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
