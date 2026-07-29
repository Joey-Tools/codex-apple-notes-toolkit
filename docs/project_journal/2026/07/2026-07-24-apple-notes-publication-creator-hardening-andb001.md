---
id: 20260724-andb001
title: Apple Notes Publication And Creator Failure Hardening
status: completed
created: 2026-07-24
updated: 2026-07-29
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
- Closed the formal single-review gaps in shell-redirection receipt creation, post-write access-policy baselines, and ctypes row-callback exception propagation.
- Closed the final formal follow-up gaps in cross-root creator-result alias binding, post-result-commit teardown classification, and standalone pre-write access-policy binding.
- Closed the final safety-resumption gaps in creator-result artifact creation-receipt binding and simultaneous SQLite callback/revalidation failure evidence.
- Closed the post-open descriptor-relative source error-classification gap so
  disappearance, unreadability, and other revalidation uncertainty remain
  stable probe results instead of escaping as `unexpected-error`.
- Closed the remaining bound-file, wrapped-directory, and post-close probe
  taxonomy gaps so causal OS failures remain missing, unreadable, or
  inconclusive while only proved property comparisons report mismatches.
- Closed the terminal live-store boundary after all file hashes so persistent
  late WAL/rollback-journal membership and held-parent replacement cannot
  escape the writeback baseline.
- Closed the artifact-directory translation gap so snapshot and patch-stage
  scans retain their caller-specific identity, access-policy, and
  revalidation codes.
- Closed the absent-live Darwin root-alias overlap gap so `/tmp` and
  `/private/tmp` forms are compared in both directions before any component
  binding or creation.
- Closed the creator-result ordering gap so `copy-db` and `stage-patch`
  complete independent zero-write artifact/result destination preflights
  before any parent creator, then defer result-parent creation until artifact
  publication succeeds.
- Closed the retained-preflight teardown gap so a late artifact/result
  destination-scope failure cannot overwrite already committed publication
  receipts with a false zero-write claim.
- Closed the destination-parent component latch gap so a successful
  no-replace directory install retains its exact receipt and all previously
  installed component identities across later validation and teardown
  failures.
- Closed the live-source directory final-exit gap so the generic component
  context cannot leak `prepared-directory-*` after source-specific terminal
  validation.

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
- `copy-db` and `stage-patch` now expose `--result-file`, which binds an artifact-external parent, rejects every existing leaf, creates a descriptor-relative no-follow temporary file exclusively, enforces effective UID/GID and mode `0600`, and fsyncs an atomic no-replace publication.
- Copied database files and JSON temporary files bind their exact identity and full access policy before writing, then revalidate that creation baseline around consecutive content readbacks and every publication/name boundary.
- Creator result publication carries a trusted Darwin alias only when the artifact and result use the same exact registry pair; cross-root paths bind independently.
- Creator result publication now binds the reopened artifact parent, root, exact directory membership, and every file's identity/access policy/SHA-256/size to the successful creation tree receipt, keeps those descriptors through result publication, and revalidates the full tree after commit.
- A terminal result-file receipt is latched as committed before later scope teardown, so post-yield failures retain the artifact mutation, exact receipt, and non-retryable classification.
- Standalone recovery files correct and bind effective UID/GID, mode `0600`, flags, identity, and the descriptor-relative leaf before the first sensitive write, then revalidate that baseline at the post-write boundary.
- Native SQLite row callbacks capture their first `BaseException` inside the ctypes boundary and abort `sqlite3_exec`; ordinary failures keep their cause and cleanup evidence, while `KeyboardInterrupt` and `SystemExit` are re-raised after input teardown.
- Ordinary SQLite row-callback failures are classified before terminal buffer/binding revalidation; a simultaneous revalidation failure remains primary while structured secondary evidence retains the callback and nested `sqlite_callback_failure`.
- Descriptor-relative source opens now map post-open descriptor, name, and
  held-parent revalidation failures through the shared source taxonomy:
  `source-missing-after-read`, `source-revalidation-unreadable`, or
  `source-revalidation-inconclusive`. The access probe retains those codes in
  the affected file record.
- Bound source files apply that taxonomy across descriptor stat, path stat, and
  repeated hashing while still closing the opened descriptor on every failure.
  Held source-directory translation inspects wrapped OS causes before generic
  prepared-directory codes, and the probe's post-close parent check now stays
  inside the affected file result.
- After all bound source files complete terminal double hashing, the helper
  revalidates the held parent chain, rescans only the reserved
  main/WAL/SHM/rollback-journal names, compares them with the binding baseline,
  and returns a final post-scan directory receipt. Persistent late sidecars or
  parent replacement fail closed; unrelated transient child churn remains
  benign when the selected properties stay stable.
- Snapshot and patch-stage directory validation now translates lower scan-time
  identity, access-policy, membership, and I/O failures with the exact codes
  supplied by the artifact caller instead of generic `directory-*` codes.
- Live-safe destination preflight now compares every destination requested /
  registry-canonical form against every requested / registry-canonical live
  container form before binding or creating any component. An absent live
  leaf therefore remains protected across `/tmp` and `/private/tmp`, while
  alias retargeting or same-target replacement still fails closed through the
  held alias identity and access-policy proof before the creator can run.
- Creator commands now hold separate artifact and result nearest-ancestor,
  missing-suffix, absent-leaf, live-container, and trusted-alias proofs. The
  artifact proof is revalidated after the result proof completes, so
  replacement between the two read-only windows fails with zero creator
  calls.
- Result-parent creation is a post-artifact commit phase. A shared missing
  parent prefix may advance only through exact object-identity and
  access-policy matches against the artifact's retained no-replace component
  creation receipts; the original trusted-alias object remains the
  authorization boundary.
- Pre-creator failures report `mutation_performed: false`. Failures after
  artifact or result-parent creation conservatively retain both
  `mutation_performed: true` and `artifact_mutation_performed: true` where
  applicable.
- The zero-write preflight wrapper now marks only failures before its first
  held proof as non-mutating. Creator commands latch the successful artifact
  payload and result destination across the original preflight contexts:
  artifact-only teardown failures retain the descriptor-bound artifact
  recovery locator, while result-committed failures retain both that artifact
  identity and the exact result-file SHA-256/size/identity receipt.
- A directory component's exact creator-held installation receipt is prepared
  before rename and latched in the first state update after a successful
  no-replace install. Parent creation then preserves every latched component
  receipt through next-component checks, post-install validation, yielded
  consumer errors, post-yield validation, and descriptor teardown, always
  reporting mutation and a non-retryable result.
- The complete live-source binding lifecycle now owns the underlying generic
  directory context's final exit. Missing, permission, other stat, proved
  identity, and proved access-policy failures in that final window remain
  stable `source-*` classifications for fingerprint, copy, and merge.

## Next Steps

- Parent may publish the signed follow-up, rerun the PR review gate, and handle
  the existing GitHub Codex thread; this worktree does not push or mutate PR
  state.
- The Claude lane is waived only until `2026-08-01 00:00 Asia/Shanghai` and is
  not counted as completed review evidence.

## Evidence

- Base commit: `393a87d57d3e6e03d625a384b8fbb16a2538df58`
- Fresh-review follow-up base: `fdd702dcd774a8331c0505d5d9da4b04c7245d18`
- Transport-evidence follow-up base: `2c6f77c798e7d57e52f359ca3efec5a86b883e39`
- Unicode/publication-authority follow-up base: `f133f57da4d9a1559bf4dc1b73574494868b00b2`
- Standalone temp-backup follow-up base: `9b06f7dbb52f1447845c9b3a47c22efd1bbf2259`
- Linux descriptor-reopen follow-up base: `48e0869ca19f7b905ebbfbbd7cf0dcd9a4e271fc`
- Final fresh-review safety follow-up base: `0206b99509fda94b005cb5dc0408a6ebc3cc551d`
- Formal single-review follow-up base: `06b45f4eb3ab01027eb1d70314196b0ff74f0083`
- Final formal-review follow-up base: `6590340811403af7b796b61dea5bb4a824fac2fc`
- Final safety-resumption base: `95ec4d293179c59c9ea10934fef454f9a9d744a6`
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
- Formal single-review follow-up full suite: Homebrew Python `3.14.3`, `/opt/homebrew/bin/python3.14 -B -m unittest tests.test_apple_notes_helper` (`234` tests passed outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe)
- Formal single-review Python compatibility suite: system Python `3.9.6`, `/usr/bin/python3 -B -m unittest tests.test_apple_notes_helper` (`234` tests passed outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe)
- Formal follow-up regressions cover safe copy/stage result-file packaging, existing-file/symlink/non-external rejection, restrictive-umask mode enforcement, creation/write-phase `chmod` races, and ordinary/process-control ctypes callback failures.
- Final formal-review regressions: Python `3.14.3` and `3.9.6`, six focused tests passed for `/Users`/`/tmp` and distinct-registry-pair creator results, committed-receipt post-yield failure mapping, standalone inherited-group correction, and creation/write-boundary policy drift.
- Final formal-review full suites: Homebrew Python `3.14.3` and system Python `3.9.6` each passed all `239` tests outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe.
- Final safety-resumption regressions: Python `3.14.3` and `3.9.6` passed pre-bind artifact replacement, post-result-commit in-place content mutation, and simultaneous callback plus terminal buffer/binding failure cases.
- Final safety-resumption full suites: Homebrew Python `3.14.3` and system Python `3.9.6` each passed all `243` tests outside the nested sandbox required by the fixed `/usr/bin/pgrep` probe.
- Post-open source-classification regressions: two focused tests passed on
  Python `3.14.3` and system Python `3.9.6`, covering open-then-disappear,
  post-open permission/EIO, descriptor `fstat`, held-parent revalidation, and
  `probe-db-access` result preservation.
- Final post-open source-classification full suites: Python `3.14.3` and system
  Python `3.9.6` each passed all `245` tests. The fixed `/usr/bin/pgrep`
  supervisor case was rerun outside the nested sandbox because sandboxed
  process-table access returned an intentionally inconclusive probe result.
- Final causal source-taxonomy regressions: Python `3.14.3` and `3.9.6` each
  passed nine focused tests covering post-open descriptor/path errno mapping
  and close, wrapped directory causes versus proved identity mismatch, and
  post-close probe parent failures retained per file.
- Final causal source-taxonomy full suites: Python `3.14.3` and `3.9.6` each
  passed all `249` tests outside the nested sandbox required by the fixed
  `/usr/bin/pgrep` probe.
- Terminal live-store and artifact-directory regressions: Python `3.14.3` and
  system Python `3.9.6` each passed nine focused tests covering persistent WAL,
  persistent rollback journal, persistent held-parent replacement, benign
  unrelated transient churn, and real scan-time identity/access-policy/EIO
  translation for snapshot and patch-stage callers.
- Terminal-boundary full suites: Python `3.14.3` and system Python `3.9.6`
  each passed all `253` tests outside the nested sandbox required by the fixed
  `/usr/bin/pgrep` probe.
- Static checks: full-repository `ruff check`; changed-file `ruff format --check`; `python3 -m py_compile`; CI-scoped `bash -n` and `shellcheck`; and `git diff --check`
- Formal follow-up static checks: full-repository `ruff check .`; changed-Python `ruff format --check`; Python `3.14.3` and `3.9.6` `py_compile`; `bash -n` and `shellcheck` over both shell scripts; and `git diff --check`
- Final formal-review static checks: full-repository Ruff `0.13.2`; changed-Python format check; Python `3.14.3` and `3.9.6` bytecode compilation; `bash -n` and ShellCheck over both shell scripts; and `git diff --check`.
- Final safety-resumption static checks: full-repository Ruff `0.13.2`; changed-Python format check; Python `3.14.3` and `3.9.6` bytecode compilation; `bash -n` and ShellCheck `0.11.0` over both shell scripts; and `git diff --check`.
- Post-open source-classification static checks: Ruff check/format, Python
  `3.14.3` and `3.9.6` bytecode compilation with a task-scoped cache,
  `git diff --check`, and isolated `quick_validate.py` with cached `PyYAML`.
- Final causal source-taxonomy static checks: full-repository Ruff `0.13.2`;
  changed-Python format check; Python `3.14.3` and `3.9.6` bytecode
  compilation with task-scoped caches; `bash -n`; ShellCheck `0.11.0`; and
  `git diff --check`.
- Terminal-boundary static checks: full-repository Ruff `0.13.2`; changed
  Python format check; Python `3.14.3` and `3.9.6` bytecode compilation with
  separate task-scoped caches; `bash -n`; ShellCheck `0.11.0`; skill and
  project-journal validators; and `git diff --check`.
- GitHub Codex root-alias follow-up base:
  `2ce9735b06133914a1a88b148469f3a8f399b6be`.
- Root-alias zero-write regressions: Python `3.14.3` and system Python `3.9.6`
  each passed the two focused tests covering absent `/tmp` /
  `/private/tmp` live containers in both directions plus pre-creation alias
  retargeting and same-target replacement. The tests prove the live binder and
  identity-bound directory creator were not called for lexical overlap, and
  prove the creator was not called after alias identity drift.
- Root-alias full suites: Python `3.14.3` and system Python `3.9.6` each passed
  all `255` tests outside the nested sandbox required by the fixed
  `/usr/bin/pgrep` process-state probe.
- Root-alias static checks: full-repository Ruff `0.13.2`; changed Python
  format check; Python `3.14.3` and `3.9.6` bytecode compilation with separate
  task-scoped caches; `bash -n`; ShellCheck `0.11.0`; and `git diff --check`.
- Root-alias skill validation: the installed wrapper could not import local
  `PyYAML`; the documented isolated `uv run --with pyyaml` fallback returned
  `Skill is valid!`. Project-journal validation also passed.
- Zero-write creator-destination follow-up base:
  `169a164d8d03563699728effc1ce68cc13e41307`.
- Zero-write creator-destination regressions cover copy/stage artifact
  existence, Notes-running, live overlap, result/artifact containment,
  replacement between the two preflights, missing result-parent preservation,
  shared artifact-created parent prefixes, and post-artifact result-commit
  mutation evidence.
- Zero-write creator-destination full suites: Homebrew Python `3.14.3` and
  system Python `3.9.6` each passed all `259` tests outside the nested sandbox
  required by the fixed `/usr/bin/pgrep` process-state probe.
- Zero-write creator-destination static gates: full-repository Ruff `0.13.2`;
  changed-Python format check; Python `3.14.3` and `3.9.6` bytecode
  compilation with separate task-scoped caches; `bash -n`; ShellCheck
  `0.11.0`; skill and project-journal validators; and `git diff --check`.
- Retained-preflight teardown follow-up base:
  `6fc7bd89d08205f6c66786374645a8d38ca640e4`.
- Retained-preflight teardown regressions: Homebrew Python `3.14.3` and
  system Python `3.9.6` each passed four focused tests covering artifact-only
  and result-committed original-preflight exit failures plus the existing
  result-scope teardown and pre-result-commit mutation paths.
- Retained-preflight teardown full suites: Homebrew Python `3.14.3` and
  system Python `3.9.6` each passed all `261` tests outside the nested sandbox
  required by the fixed `/usr/bin/pgrep` process-state probe.
- Retained-preflight teardown static gates: full-repository Ruff `0.13.2`;
  changed-Python format check; Python `3.14.3` and `3.9.6` bytecode
  compilation with separate task-scoped caches; `bash -n`; ShellCheck
  `0.11.0`; skill and project-journal validators; and `git diff --check`.
- Directory-install/source-final-exit follow-up base:
  `bc19e5d19c8a0e02366b706410a34874bd15e1b8`.
- Directory-install/source-final-exit focused regressions: Homebrew Python
  `3.14.3` and system Python `3.9.6` each passed ten focused tests. Coverage
  includes install-success followed by scope failure, multi-component
  post-install and post-yield failures with exact receipts, and final-window
  missing, unreadable, EIO, identity, and access-policy classifications across
  fingerprint, copy, and merge.
- Directory-install/source-final-exit full suites: Homebrew Python `3.14.3`
  and system Python `3.9.6` each passed all `265` tests outside the nested
  sandbox required by the fixed `/usr/bin/pgrep` process-state probe.
- Directory-install/source-final-exit static gates: full-repository Ruff
  `0.13.2`; changed-Python format check; Python `3.14.3` and `3.9.6` bytecode
  compilation with separate task-scoped caches; `bash -n`; ShellCheck
  `0.11.0`; isolated skill validation with `PyYAML`; project-journal
  validation; and `git diff --check`.
- Skill validation: isolated `quick_validate.py` with `PyYAML` (`Skill is valid!`; direct local validation lacked that dependency)
- Final skill validation: `codex_skill_validate.py .agents/skills/apple-notes-db-guardrails` (`Skill is valid!`)
- Formal follow-up skill validation: `codex_skill_validate.py .agents/skills/apple-notes-db-guardrails` (`Skill is valid!`)
- Final formal-review skill validation: `codex_skill_validate.py .agents/skills/apple-notes-db-guardrails` (`Skill is valid!`)
- Final safety-resumption skill validation: isolated `quick_validate.py` with cached `PyYAML` (`Skill is valid!`; direct Homebrew Python validation lacked `yaml`)
- Final causal source-taxonomy skill validation:
  `codex_skill_validate.py .agents/skills/apple-notes-db-guardrails`
  (`Skill is valid!`).
- Final post-fix read-only full-diff review: no findings
- Journal validation: `project_journal.py validate --repo <worktree>`
- Formal follow-up journal validation: `project_journal.py validate --repo <worktree>` (`Project journal validation passed.`)
- Final formal-review journal validation: `project_journal.py validate --repo <worktree>` (`Project journal validation passed.`)
- Final safety-resumption journal validation: `project_journal.py validate --repo <worktree>` (`Project journal validation passed.`)
- Final causal source-taxonomy journal validation:
  `project_journal.py validate --repo <worktree>`
  (`Project journal validation passed.`).
