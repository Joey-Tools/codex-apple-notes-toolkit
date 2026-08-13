from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CALL_TRIGGER = """on:
  workflow_call:

permissions:"""
CHECKOUT_REPOSITORY = "Joey-Tools/codex-apple-notes-toolkit"
REPOSITORY_GUARD = """- name: Reject unexpected repository
        if: ${{ github.repository != 'Joey-Tools/codex-apple-notes-toolkit' }}
        run: exit 1"""
CHECKOUT_BINDING = """- uses: actions/checkout@v4
        with:
          repository: Joey-Tools/codex-apple-notes-toolkit
          ref: ${{ github.sha }}
          persist-credentials: false"""


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


def workflow_steps(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    steps: list[str] = []
    for index, line in enumerate(lines):
        if not line.startswith("      - "):
            continue
        indent = len(line) - len(line.lstrip())
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and (
                candidate_indent < indent
                or (candidate_indent == indent and candidate.lstrip().startswith("- "))
            ):
                break
            end += 1
        steps.append("\n".join(lines[index:end]))
    return steps


def checkout_steps(workflow: str) -> list[str]:
    return [
        step
        for step in workflow_steps(workflow)
        if step.lstrip().startswith("- uses: actions/checkout@")
    ]


class RequiredCiWorkflowTests(unittest.TestCase):
    def test_entry_wraps_only_the_required_linux_test(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/required-ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(REQUIRED_CALL_TRIGGER, workflow)
        self.assertNotIn("workflow_call:\n    inputs:", workflow)
        steps = workflow_steps(workflow)
        checkout_indexes = [
            index
            for index, step in enumerate(steps)
            if step.lstrip().startswith("- uses: actions/checkout@")
        ]
        checkout = checkout_steps(workflow)
        self.assertGreater(len(checkout), 0)
        self.assertTrue(all(CHECKOUT_BINDING in step for step in checkout))
        for step in checkout:
            self.assertEqual(
                [
                    line.strip()
                    for line in step.splitlines()
                    if line.strip().startswith("repository:")
                ],
                [f"repository: {CHECKOUT_REPOSITORY}"],
            )
            self.assertEqual(
                [
                    line.strip()
                    for line in step.splitlines()
                    if line.strip().startswith("ref:")
                ],
                ["ref: ${{ github.sha }}"],
            )
            self.assertEqual(
                [
                    line.strip()
                    for line in step.splitlines()
                    if line.strip().startswith("persist-credentials:")
                ],
                ["persist-credentials: false"],
            )
        guard_indexes = [
            index
            for index, step in enumerate(steps)
            if step.lstrip().startswith("- name: Reject unexpected repository")
        ]
        self.assertEqual(guard_indexes, [index - 1 for index in checkout_indexes])
        self.assertEqual(
            [steps[index].strip() for index in guard_indexes],
            [REPOSITORY_GUARD] * len(checkout),
        )
        self.assertEqual(
            workflow.count(f"repository: {CHECKOUT_REPOSITORY}"), len(checkout)
        )
        self.assertNotIn("repository: ${{ github.repository }}", workflow)
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), len(checkout))
        self.assertEqual(workflow.count("persist-credentials: false"), len(checkout))
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
