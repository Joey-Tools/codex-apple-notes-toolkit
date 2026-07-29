# Project State

## Current State

- Apple Notes database reads bind untrusted leaves with no-follow, nonblocking opens before regular-file and identity validation.
- Live-container inputs are frozen to lexical absolute paths from one captured working directory before preflight.
- `merge-db` and `stage-patch` freeze relative sources and every output from one API/CLI-entry CWD snapshot.
- `merge-db` defaults copied-snapshot outputs outside the snapshot and rejects lexical, canonical-alias, or descriptor ancestry overlap.
- Copy, validation, recovery, and writeback APIs/CLIs freeze each related artifact, receipt, output, and container path set from one entry CWD before probes or callbacks.
- Prepared/artifact directory scans reject unexpected raw names before `stat` and enforce 64-entry and 4-KiB raw-name limits per pass.
- Retained-partial inventory lazily stops at the 65th descriptor-relative entry or 4-KiB aggregate raw-name ceiling, and supervisor emptiness checks consume at most one entry.
- Darwin access policy tracks only immutable, append-only, Data Vault, restricted, and no-unlink flags; other raw file flags remain metadata evidence.
- Manifest and external-receipt JSON parsing has fixed nesting and integer-digit limits with stable safety-error classifications.
- File and directory publication use a monotonic commit latch before post-rename evidence work.
- Write-producing wrapper commands automatically launch the packaged supervisor while retaining the inherited-FD interface for stronger external authorities.
- The legacy Python compatibility entrypoint is import-safe, retains its public exports, and routes every write-producing CLI command through that same supervisor.
- Required-quit snapshots recheck Notes at the final pre-rename and immediate post-publication boundaries; a late restart quarantines the exact published object and cannot produce a writeback-grade receipt.
- Snapshot and patch creator CLIs can atomically publish owner-only external result files without shell redirection.
- Cross-root creator result files bind their artifact and result alias scopes independently, and committed result receipts survive late scope teardown failures.
- Newly created copied, JSON, and standalone files retain a pre-write identity and access-policy baseline through content and publication validation.
- Structured, malformed, unstructured, and transport-evidence-construction creator failures retain conservative recovery evidence and close every owned or received FD.
- Per-workstream implementation and validation records live under `docs/project_journal/`.

## Recovery Pointers

- Current hardening workstream: `docs/project_journal/2026/07/2026-07-24-apple-notes-publication-creator-hardening-andb001.md`

## Global Blockers

- None.
