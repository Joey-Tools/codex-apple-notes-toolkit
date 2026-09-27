---
id: 20260918-crgv2a
title: Codex Review Gate v2 Handoff
status: completed
created: 2026-09-18
updated: 2026-09-27
branch: wip/remove-v1-bridge-apple
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Handoff

## Summary

- Complete the receipt-bound v2 cutover by removing the temporary v1 legacy
  bridge after the full consumer cohort passed the post-cutover audit.
- Protect the review-gate control plane with `@JoeyTeng` CODEOWNERS entries.

## Current State

- Pull request events produce the required `codex/github-review-gate` check
  through `JoeyTeng/codex-review-gate-action@v2`.
- Bot issue-comment events and exact-head manual dispatches can reconcile or
  begin a review through the controller workflow.
- No repository workflow invokes the v1 reusable workflow or produces the
  retired `codex/review-gate` status.

## Next Steps

- No follow-up is required for this handoff. Future v2 workflow changes remain
  independent review-gate control-plane changes.

## Evidence

- Canonical handoff implementation: https://github.com/Joey-Tools/codex-review-gate/pull/51
- Post-cutover audit receipt: `9a8b38f2188a14168423a07639d6662c87e198fe2dd12041f67fc224f363817e`.
