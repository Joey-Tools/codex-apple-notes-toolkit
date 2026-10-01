---
id: 20261001-anm002
title: Opt-In Automatic Codex Review Requests
status: active
created: 2026-10-01
updated: 2026-10-02
branch: codex/daily-skill-friction-2026-10-01-codex-apple-notes-toolkit-auto-codex-review-controller
pr:
supersedes: []
superseded_by:
---

# Opt-In Automatic Codex Review Requests

## Summary

- Extend the v2 controller to start a Codex review after an eligible verifier
  failure when the automatic-request variable is enabled.

## Current State

- The controller accepts only a first-attempt failed pull-request verifier run
  with one associated pull request, and begins review at the run head.
- Automatic requests remain opt-in; this change does not enable a repository or
  organization variable.
- The earlier head-SHA finding is not adopted: `workflow_run.head_sha` is the
  verifier's pull-request head, while the synthetic merge SHA is `github.sha`.

## Next Steps

- Confirm the pilot's initial-head and subsequent-commit request evidence before
  expanding the organization variable cohort.

## Evidence

- `.github/workflows/codex-review-gate-controller.yml`.
- Regression contract: `tests/test_review_gate_controller.py`.
