---
id: 20260918-crgv2a
title: Codex Review Gate v2 Handoff
status: active
created: 2026-09-18
updated: 2026-09-18
branch: codex/organization-v2-handoff
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Handoff

## Summary

- Install the canonical v2 verifier and controller while retaining the v1
  required status through a temporary legacy bridge.
- Protect the review-gate control plane with `@JoeyTeng` CODEOWNERS entries.

## Current State

- Pull request events produce the new `codex/github-review-gate` check through
  `JoeyTeng/codex-review-gate-action@v2`.
- Bot issue-comment events and exact-head manual dispatches can reconcile or
  begin a review through the controller workflow.
- The legacy bridge continues to produce `codex/review-gate`; this repository
  change does not modify either organization ruleset.

## Next Steps

- Keep the legacy bridge until the complete consumer cohort can produce the v2
  check and the coordinated organization ruleset cutover is complete.
- Remove the bridge only in the later explicit cleanup phase.

## Evidence

- Canonical handoff implementation: https://github.com/Joey-Tools/codex-review-gate/pull/51
