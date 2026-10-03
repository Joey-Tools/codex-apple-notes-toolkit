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
            "github.event_name == 'workflow_run' && 'begin-review'",
            "request_review: ${{ github.event_name == 'workflow_run' ||",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, workflow)


if __name__ == "__main__":
    unittest.main()
