---
id: 20260724-andb001
title: Apple Notes Publication And Creator Failure Hardening
status: completed
created: 2026-07-24
updated: 2026-07-24
branch: codex/apple-db-hardening
pr:
supersedes: []
superseded_by:
---

# Apple Notes Publication And Creator Failure Hardening

## Summary

- Closed three fail-closed gaps in untrusted leaf opening, post-rename publication classification, and identity-bound directory creation failure recovery.

## Current State

- All existing untrusted regular-file leaf opens combine `O_NOFOLLOW` and `O_NONBLOCK`, then reject non-regular or replaced descriptors.
- Successful or proved-committed file and directory renames set one monotonic commit latch before terminal or fallback evidence construction.
- Trusted directory creators can transfer create-then-fail evidence through a structured exception; unstructured failures conservatively report possible mutation and inconclusive cleanup.
- Recovery-detail merging keeps mutation, retry, cleanup, and locator conclusions conservative.

## Next Steps

- No additional work is authorized in this local-only batch; do not push, open a PR, merge, or start a reviewer.

## Evidence

- Base commit: `393a87d57d3e6e03d625a384b8fbb16a2538df58`
- Targeted adversarial tests: `python3 -m unittest <eight focused test cases>` (`8` tests passed)
- Full repository suite: `python3 -m unittest tests.test_apple_notes_helper` (`201` tests passed)
- Static checks: `ruff check`, `ruff format --check`, and `python3 -m py_compile`
- Skill validation: `codex_skill_validate.py .agents/skills/apple-notes-db-guardrails`
- Journal validation: `project_journal.py validate --repo <worktree>`
