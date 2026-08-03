# Project State

## Current State

- Apple Notes database reads bind untrusted leaves with no-follow, nonblocking opens before regular-file and identity validation.
- Regular-file binding proves one identity and access policy across the pre-open path, opened descriptor, and immediate post-open path before hashing.
- Live-container inputs are frozen to lexical absolute paths from one captured working directory before preflight.
- `merge-db` and `stage-patch` freeze relative sources and every output from one API/CLI-entry CWD snapshot.
- `merge-db` defaults copied-snapshot outputs outside the snapshot and rejects lexical, canonical-alias, or descriptor ancestry overlap.
- Copy, validation, recovery, and writeback APIs/CLIs freeze each related artifact, receipt, output, and container path set from one entry CWD before probes or callbacks.
- Prepared/artifact directory scans reject unexpected raw names before `stat` and enforce 64-entry and 4-KiB raw-name limits per pass.
- Retained-partial inventory lazily stops at the 65th descriptor-relative entry or 4-KiB aggregate raw-name ceiling.
- Darwin access policy tracks only immutable, append-only, Data Vault, restricted, and no-unlink flags; other raw file flags remain metadata evidence.
- Manifest and external-receipt JSON parsing has fixed nesting and integer-digit limits with stable safety-error classifications.
- File and directory publication use a monotonic commit latch before post-rename evidence work.
- Write-producing wrapper commands automatically launch the packaged cooperative same-UID directory supervisor. It creates a randomized private name descriptor-relatively, binds the returned directory, parent, and public name before transferring the directory FD, and fails conservatively without claiming isolation from a malicious same-UID peer.
- The legacy Python compatibility entrypoint is import-safe, retains its public exports, and routes every write-producing CLI command through that same supervisor.
- Required-quit snapshots recheck Notes at the final pre-rename and immediate post-publication boundaries; a late restart quarantines the exact published object and cannot produce a writeback-grade receipt.
- A visible quarantine rename is not reported as verified or retained until directory policy, parent durability, complete-tree, and terminal-alias proofs all succeed.
- Snapshot and patch creator CLIs can atomically publish owner-only external result files without shell redirection.
- Artifact, standalone, and creator-result writers now define their zero-write
  linearization point at the final held-parent/public-name revalidation
  immediately before the first `.partial-*` or `.tmp-*` creator can run.
- Snapshot v4 binds the live NoteStore root, terminal directory identity and
  access policy, complete canonical component chain, no-symlink policy, and
  registered Darwin alias receipt from the same held source capture used for
  the database files.
- Writeback preflight and verification keep the snapshot, patch stage, and
  live source bindings open through one joint comparison and Notes probe, then
  fully revalidate all three immediately before the success point;
  descriptor teardown is close-only and their receipts are point-in-time
  evidence rather than authorization for a later write.
- Exactly anchored snapshot v3 artifacts remain read-only validation/recovery
  inputs but are never writeback-grade or implicitly upgraded to v4; v3/v4
  hybrids are rejected, normalized results expose authoritative schema/grade,
  and the v4 gate runs before stage/live validation.
- `note-tags` holds the configured live store alongside its standalone input
  and rejects an external hard link to live `NoteStore.sqlite`, while live
  WAL/SHM membership remains under revalidation.
- CI preserves the required Ubuntu `test` context and adds full native macOS
  discovery on Python 3.9 and current 3.x.
- Cross-root creator result files bind their artifact and result alias scopes independently, and committed result receipts survive late scope teardown failures.
- Newly created copied, JSON, and standalone files retain a pre-write identity and access-policy baseline through content and publication validation.
- Structured, malformed, unstructured, and transport-evidence-construction creator failures retain conservative recovery evidence and close every owned or received FD.
- Per-workstream implementation and validation records live under `docs/project_journal/`.

## Recovery Pointers

- Current hardening workstream: `docs/project_journal/2026/07/2026-07-24-apple-notes-publication-creator-hardening-andb001.md`

## Global Blockers

- No canonical runtime blocker. Private-overlay packaging must consume this
  repository's landed source instead of owning a second helper copy.
