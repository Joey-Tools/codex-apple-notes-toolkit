# Project State

## Current State

- Apple Notes database reads bind untrusted leaves with no-follow, nonblocking opens before regular-file and identity validation.
- Live-container inputs are frozen to lexical absolute paths from one captured working directory before preflight.
- `merge-db` and `stage-patch` freeze relative sources and every output from one API/CLI-entry CWD snapshot.
- Prepared/artifact directory scans reject unexpected raw names before `stat` and enforce 64-entry and 4-KiB raw-name limits per pass.
- Darwin access policy tracks only immutable, append-only, Data Vault, restricted, and no-unlink flags; other raw file flags remain metadata evidence.
- Manifest and external-receipt JSON parsing has fixed nesting and integer-digit limits with stable safety-error classifications.
- File and directory publication use a monotonic commit latch before post-rename evidence work.
- Write-producing wrapper commands automatically launch the packaged supervisor while retaining the inherited-FD interface for stronger external authorities.
- Snapshot and patch creator CLIs can atomically publish owner-only external result files without shell redirection.
- Cross-root creator result files bind their artifact and result alias scopes independently, and committed result receipts survive late scope teardown failures.
- Newly created copied, JSON, and standalone files retain a pre-write identity and access-policy baseline through content and publication validation.
- Structured, malformed, unstructured, and transport-evidence-construction creator failures retain conservative recovery evidence and close every owned or received FD.
- Per-workstream implementation and validation records live under `docs/project_journal/`.

## Recovery Pointers

- Current hardening workstream: `docs/project_journal/2026/07/2026-07-24-apple-notes-publication-creator-hardening-andb001.md`

## Global Blockers

- None.
