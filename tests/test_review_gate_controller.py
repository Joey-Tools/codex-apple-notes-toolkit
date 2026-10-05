from __future__ import annotations

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = REPO_ROOT / ".github/workflows/codex-review-gate-controller.yml"


class ReviewGateControllerTests(unittest.TestCase):
    def test_auto_request_is_opt_in_and_begins_review_at_run_head(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")

        for contract in (
            "  workflow_run:\n    workflows: [Codex Review Gate Verifier]\n    types: [completed]",
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
            "github.event.workflow_run.event == 'pull_request'",
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.conclusion == 'failure'",
            "github.event.workflow_run.pull_requests[0].number",
            "!github.event.workflow_run.pull_requests[1]",
            "CODEX_REVIEW_GATE_AUTO_REQUEST: ${{ vars.CODEX_REVIEW_GATE_AUTO_REQUEST }}",
            "github.event.workflow_run.head_sha",
            "&& 'begin-review' || "
            "github.event_name == 'workflow_run' && 'report-completion'",
            "request_review: ${{ github.event_name == 'workflow_run' && "
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, workflow)

    def test_completion_reporting_is_not_gated_by_auto_request_or_run_outcome(
        self,
    ) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        job_condition = workflow.split("    if: >-\n", 1)[1].split(
            "    runs-on:", 1
        )[0]

        for contract in (
            "github.event.action == 'completed'",
            "github.event.workflow_run.event == 'pull_request'",
            "github.event.workflow_run.path == "
            "'.github/workflows/codex-review-gate.yml'",
            "startsWith(github.event.workflow_run.path, "
            "'.github/workflows/codex-review-gate.yml@')",
            "!github.event.workflow_run.pull_requests[1]",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, job_condition)

        # Successes, reruns, disabled opt-in, and an empty association still
        # reach the diagnostic path; ambiguity remains rejected.
        for request_only_guard in (
            "CODEX_REVIEW_GATE_AUTO_REQUEST",
            "workflow_run.run_attempt",
            "workflow_run.conclusion",
            "workflow_run.pull_requests[0].number",
        ):
            with self.subTest(request_only_guard=request_only_guard):
                self.assertNotIn(request_only_guard, job_condition)

        action_inputs = workflow.split("        with:\n", 1)[1]
        operation = next(
            line.strip()
            for line in action_inputs.splitlines()
            if line.startswith("          operation: ")
        )
        automatic_branch, completion_branch = operation.split(
            " || github.event_name == 'workflow_run' && 'report-completion' ||",
            1,
        )
        automatic_request_guards = (
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.conclusion == 'failure'",
            "github.event.workflow_run.pull_requests[0].number",
            "!github.event.workflow_run.pull_requests[1]",
            "'begin-review'",
        )
        for guard in automatic_request_guards:
            with self.subTest(automatic_request_guard=guard):
                self.assertIn(guard, automatic_branch)
        for request_only_guard in (
            "CODEX_REVIEW_GATE_AUTO_REQUEST",
            "workflow_run.run_attempt",
            "workflow_run.conclusion",
            "pull_requests[0].number",
        ):
            with self.subTest(completion_request_only_guard=request_only_guard):
                self.assertNotIn(request_only_guard, completion_branch)

        self.assertIn(
            "(github.event.workflow_run.pull_requests[0].number || '0')",
            action_inputs,
        )
        self.assertIn(
            "request_review: ${{ github.event_name == 'workflow_run' && "
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
            action_inputs,
        )
        request_review = next(
            line.strip()
            for line in action_inputs.splitlines()
            if line.startswith("          request_review: ")
        )
        for guard in automatic_request_guards[:-1]:
            with self.subTest(request_review_guard=guard):
                self.assertIn(guard, request_review)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && inputs.request_review || false",
            request_review,
        )

    def test_completion_path_guard_rejects_filename_lookalikes(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        job_condition = workflow.split("    if: >-\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        canonical_path = ".github/workflows/codex-review-gate.yml"

        self.assertIn(
            f"github.event.workflow_run.path == '{canonical_path}'",
            job_condition,
        )
        self.assertIn(
            f"startsWith(github.event.workflow_run.path, '{canonical_path}@')",
            job_condition,
        )
        self.assertNotIn(
            f"startsWith(github.event.workflow_run.path, '{canonical_path}')",
            job_condition,
        )


if __name__ == "__main__":
    unittest.main()
