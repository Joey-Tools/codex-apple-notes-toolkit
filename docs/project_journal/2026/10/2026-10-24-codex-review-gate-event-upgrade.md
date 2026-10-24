---
id: 20261024-cgan01
title: Codex Review Gate Event Upgrade
status: completed
created: 2026-10-24
updated: 2026-10-24
branch: wip/review-gate-stacked-retarget
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate Event Upgrade

## Summary

- 完成 consumer workflow 对 stacked（堆叠 PR）事件和真实 base-ref 编辑的支持，并隔离非 base-ref 编辑触发的 ignored run。

## Current State

- 两份 consumer workflow 与 canonical v2.2.12 verifier/controller 成对文件逐字节一致；保留浮动 `@v2`、请求 token、自动请求及限制配置变量，并维持默认 hosted runner。
- 本地 canonical 字节比对、静态 controller 测试（3 项）与 `git diff --check` 通过。GitHub CI 和 PR review 仍是独立 PR 门槛；本记录不声称已运行 live canary。

## Next Steps

- 无额外本地工作；按独立 PR 流程完成远端验证。

## Evidence

- `.github/workflows/codex-review-gate.yml`
- `.github/workflows/codex-review-gate-controller.yml`
- `tests/test_review_gate_controller.py`
