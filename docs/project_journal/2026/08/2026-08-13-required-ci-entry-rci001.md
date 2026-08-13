---
id: 20260813-rci001
title: Required CI Reusable Entry
status: completed
created: 2026-08-13
updated: 2026-08-13
branch: codex/daily-skill-friction-20260813-codex-apple-notes-toolkit-codex-review-v2
pr:
supersedes: []
superseded_by:
---

# Required CI Reusable Entry

## Summary
- Added a reusable required-CI entry that preserves the existing required Linux test without promoting the diagnostic macOS matrix.

## Current State
- `.github/workflows/required-ci.yml` is callable only through `workflow_call`, uses read-only contents permission, and runs the existing shell syntax, shellcheck, and unit-test closure.
- The existing event-driven `.github/workflows/ci.yml` remains unchanged for rollout canaries.

## Next Steps
- None in this repository slice.

## Evidence
- `python3 -m unittest tests.test_required_ci_workflow`
- `python3 -m unittest discover -s tests -p 'test_*.py'`
