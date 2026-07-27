---
id: 20260724-andb001
title: Apple Notes Publication And Creator Failure Hardening
status: completed
created: 2026-07-24
updated: 2026-07-27
branch: codex/apple-db-hardening
pr:
supersedes: []
superseded_by:
---

# Apple Notes Publication And Creator Failure Hardening

## Summary

- Closed three fail-closed gaps in untrusted leaf opening, post-rename publication classification, and identity-bound directory creation failure recovery.
- Closed the follow-up production gap by adding a packaged inherited-supervisor creator protocol and conservative malformed-result ownership handling.
- Closed the final fresh-review gaps in anonymous recovered-image binding, exact SQLite header normalization, and structured native SQLite cleanup.

## Current State

- All existing untrusted regular-file leaf opens combine `O_NOFOLLOW` and `O_NONBLOCK`, then reject non-regular or replaced descriptors.
- Successful or proved-committed file and directory renames set one monotonic commit latch before terminal or fallback evidence construction.
- Trusted directory creators can transfer create-then-fail evidence through a structured exception; unstructured failures conservatively report possible mutation and inconclusive cleanup.
- `copy-db`, `merge-db`, `recover-snapshot`, and `stage-patch` accept an inherited connected supervisor FD and exchange parent/created directory descriptors with request-bound `SCM_RIGHTS` messages.
- `None`, unexpected mappings or objects, missing fields, and wrong field types are classified after possible creation; recoverable FDs are evidence-captured and closed, and locator/cleanup conclusions merge conservatively.
- Supervisor provider details now pass a bounded closed schema before merging; malformed nested locators cannot remove a received FD from cleanup ownership, and any evidence-construction failure closes all received descriptors before emitting a fixed conservative locator.
- Provider response and recovery-evidence strings now reject lone surrogates before retention, while ASCII-escaped CLI JSON remains writable to strict UTF-8 stdout.
- Provider `publication_state` is retained only as an unverified provider-scoped claim; post-request transport failures derive top-level `publication_state: uncertain` from local evidence.
- Recovery-detail merging keeps mutation, retry, cleanup, and locator conclusions conservative.
- Standalone recovery now descriptor-binds its private `.tmp-*` database before the second source revalidation and routes source, receipt, integrity, and durability failures through one retained-file recovery path.
- SQLite no longer reopens anonymous Linux `O_TMPFILE` objects through `/dev/fd`; native read-only deserialization consumes only bytes reread from the held descriptor, with descriptor and SQLite-buffer checks around every integrity or backup boundary.
- WAL recovery normalizes header read/write versions only after applying the committed frame prefix, then binds those exact normalized bytes as the anonymous descriptor content authority.
- Native SQLite teardown closes the connection before freeing its input buffer and retains the allocation with explicit cleanup evidence if close is unproved.
- Anonymous recovery pre-binds the accepted payload length, SHA-256, and `0600` policy before writing, then requires two consecutive same-descriptor readbacks before establishing the baseline.
- SQLite header versions accept only exact `1/1` passthrough or exact `2/2` normalization to `1/1`; mixed and invalid pairs fail before deserialization.
- Ordinary native runtime and `ctypes` failures retain structured input/backup cleanup evidence. Backup finish, serialized-buffer free, and destination close are independently attempted when safe, while process-control exceptions remain untranslated.
- If consumer and terminal revalidation both fail, revalidation remains the primary cause and the consumer failure is retained as structured secondary evidence.

## Next Steps

- No additional work is authorized after this final local-only follow-up; do not push, open a PR, or merge.

## Evidence

- Base commit: `393a87d57d3e6e03d625a384b8fbb16a2538df58`
- Fresh-review follow-up base: `fdd702dcd774a8331c0505d5d9da4b04c7245d18`
- Transport-evidence follow-up base: `2c6f77c798e7d57e52f359ca3efec5a86b883e39`
- Unicode/publication-authority follow-up base: `f133f57da4d9a1559bf4dc1b73574494868b00b2`
- Standalone temp-backup follow-up base: `9b06f7dbb52f1447845c9b3a47c22efd1bbf2259`
- Linux descriptor-reopen follow-up base: `48e0869ca19f7b905ebbfbbd7cf0dcd9a4e271fc`
- Final fresh-review safety follow-up base: `0206b99509fda94b005cb5dc0408a6ebc3cc551d`
- Hosted Linux failure evidence: GitHub Actions run `30126900959`, job `89592422565`, head `48e0869ca19f7b905ebbfbbd7cf0dcd9a4e271fc` (`182` `unable to open database file` occurrences rooted at anonymous descriptor URI consumption)
- Targeted adversarial tests: `python3 -m unittest <eight focused test cases>` (`8` tests passed)
- Supervisor/malformed-result tests: `python3 -m unittest <four focused test cases>` (`4` tests passed)
- Malformed provider-locator transport test: `python3 -m unittest tests.test_apple_notes_helper.AppleNotesHelperTests.test_supervisor_malformed_provider_locators_never_leak_received_fd` (`1` test with normal-merge and forced-merge-failure subtests passed)
- Surrogate transport and strict-output tests: `python3 -m unittest <two focused test cases>` (`2` tests passed)
- Standalone temp-backup regression tests: Python `3.14.3`, `python3 -B -m unittest <seven focused test cases>` (`7` tests passed, including identity/content/access-policy adversarial subtests and an mtime-only negative control)
- Descriptor-deserialization regressions: Python `3.14.x`, `python3 -B -m unittest <six focused test cases>` (`6` tests passed, including simulated Linux `O_TMPFILE` reopen failure, descriptor/buffer adversarial mutations, native cleanup, namespace swap, and invalid WAL-header version)
- Native Linux validation availability: Apple Container was installed but had no default kernel; starting it required a separately authorized kernel download, so this local-only gate used the deterministic pseudo-path-reopen failure regression and left hosted Linux rerun to the next pushed head
- Python compatibility regressions: system Python `3.9.6`, `python3 -B -m unittest <five focused test cases>` (`5` tests passed)
- Final safety regressions: Homebrew Python `3.14.3`, `python3 -B -m unittest <ten focused test cases>` (`10` tests passed)
- Final Python compatibility regressions: system Python `3.9.6`, `python3 -B -m unittest <ten focused test cases>` (`10` tests passed)
- Full repository suite before final runtime selection: Python `3.14.2`, `python3 -B -m unittest tests.test_apple_notes_helper` (`216` tests passed outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe)
- Final full repository suite: Homebrew Python `3.14.3` (highest compatible installed runtime), `python3 -B -m unittest tests.test_apple_notes_helper` (`217` tests passed outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe)
- Final fresh-review full repository suite: Homebrew Python `3.14.3`, `python3 -B -m unittest tests.test_apple_notes_helper` (`225` tests passed outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe)
- Static checks: full-repository `ruff check`; changed-file `ruff format --check`; `python3 -m py_compile`; CI-scoped `bash -n` and `shellcheck`; and `git diff --check`
- Skill validation: isolated `quick_validate.py` with `PyYAML` (`Skill is valid!`; direct local validation lacked that dependency)
- Final skill validation: `codex_skill_validate.py .agents/skills/apple-notes-db-guardrails` (`Skill is valid!`)
- Final post-fix read-only full-diff review: no findings
- Journal validation: `project_journal.py validate --repo <worktree>`
