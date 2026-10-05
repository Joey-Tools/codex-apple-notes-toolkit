---
id: 20261005-anm003
title: Diagnostic Completion Controller
status: completed
created: 2026-10-05
updated: 2026-10-05
branch: codex/completion-report-v217
pr:
supersedes: []
superseded_by:
---

# Diagnostic Completion Controller

## Summary

- Synchronize the installed v2 controller with the canonical v2.1.7 diagnostic completion route while preserving the existing automatic-review guardrails.

## Current State

- Before runner allocation, the controller admits only completed pull-request runs of the canonical verifier workflow, using its exact path or that path followed by @ and a workflow ref. Zero or one associated pull request is accepted; multiple associations are rejected. An empty association passes the 0 sentinel to the runtime's separately verified fallback.
- Only CODEX_REVIEW_GATE_AUTO_REQUEST=true, attempt 1, failure, and one associated pull request select begin-review and an automatic review request. Other eligible completions select report-completion, including successful runs, reruns, and runs when automatic requests are disabled.
- report-completion updates diagnostic state only; it does not rerun or dispatch workflows, request a review, scan provider findings, or write the required check. The canonical verifier check remains the merge authority.
- Event subscriptions, permissions, concurrency, runner selection, verifier workflow, CODEOWNERS, GitHub variables, and rulesets are unchanged. This implementation does not provide live settings or canary evidence.

## Next Steps

- No controller implementation follow-up is required. Any live canary or operational state must be established from separate evidence.

## Evidence

- Consumer baseline: 8fe07a19e1a78c7f397475060e736d9f0caad46e.
- Canonical source: 7e1069c6a6f4c4b319b1c5f33da262ee97460242; source PR #101 is merged and runtime v2.1.7 is published. Controller SHA-256: 2499fa48ec6a474f1509329ac3ce37c3e62914356de28cba60d02791fed78c0f.
- cmp against the canonical controller, source bootstrap --prepare-worktree dry run, actionlint v1.7.12 on verifier and controller, and git diff --check passed.
- timeout 120s python3 -B -m unittest tests.test_review_gate_controller passed (3 tests).
