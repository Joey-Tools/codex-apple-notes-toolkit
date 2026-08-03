---
name: apple-notes-db-guardrails
description: Safely audit, snapshot, validate, recover, stage, preflight, or verify Apple Notes NoteStore databases on macOS. Use when probing TCC or Full Disk Access for NoteStore.sqlite; inspecting SQLite/WAL/SHM/rollback-journal state; creating or validating a task-scoped snapshot; preparing a standalone analysis database or patch stage; or guarding whole-store writeback and recovery.
---

# Apple Notes DB Guardrails

## Resolve The Packaged Runtime

Treat the directory containing this file as `SKILL_DIR`. Use only the packaged
runtime; do not reconstruct a repository-root path or copy the helper into
another skill.

- Read-only probe, validation, preflight, verification, and query commands use
  `python3 "$SKILL_DIR/scripts/apple_notes_db.py" ...`.
- Commands that create an output directory or standalone database use the
  packaged supervisor:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- <command> ...
```

Read [references/safety-contract.md](references/safety-contract.md) before any
write-producing command, recovery, patch/writeback work, or interpretation of
a publication/retry failure. It is the authority for protected properties,
SQLite/WAL handling, receipts, and failure classes.

## Authorization And Phase Boundary

Default to read-only audit work. The helper never replaces the live Notes
store. It creates snapshots, standalone recovery databases, and patch stages;
it provides preflight and post-writeback verification around separately
authorized replacement mechanics.

A patch/writeback phase requires all of the following:

1. Notes remains quit.
2. A fresh writeback-grade snapshot exists.
3. The proposed database is normalized into a sidecar-free patch stage.
4. Read-only `preflight-writeback` passes.
5. Joey explicitly approves the exact live-store replacement mechanics.
6. `verify-writeback` runs immediately while Notes remains quit.

`ready_for_explicit_writeback: true` is a safety preflight result, not
authorization and not proof that a multi-file atomic swap exists.

## Probe Access

Run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" probe-db-access
```

Record whether the source is the live container or a Joey-provided copy.
Distinguish missing, unreadable, replaced, access-policy mismatch, and
inconclusive results. If macOS TCC or Full Disk Access blocks the live store,
stop and ask for the permission or a task-scoped copy produced by an authorized
terminal. Do not reinterpret an access failure as absence.

For a stable live-store fingerprint without copying:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" fingerprint-db
```

## Capture A Snapshot

Use a unique task-scoped destination and keep the result receipt outside the
snapshot tree:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- copy-db \
  --dest /private/tmp/<task-snapshot> \
  --result-file /private/tmp/<task-snapshot>.creation-result.json
```

For critical analysis, exact absence/count claims, patch planning, or a
writeback baseline, quit Notes first and require that state throughout capture:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- copy-db \
  --dest /private/tmp/<task-backup> \
  --require-notes-quit \
  --result-file /private/tmp/<task-backup>.creation-result.json
```

Treat a snapshot captured while Notes is running as tentative. Do not use it
for a writeback baseline or exact absence/count conclusions.

Keep `snapshot-manifest.json` with the copied store and preserve the successful
creation-result JSON independently. The external receipt anchors creation-time
identity, content, access policy, and manifest bytes; it is not a signature or
MAC. If the same actor can rewrite both artifact and receipt, creation-time
authenticity is not established.

The packaged supervisor creates randomized owner-private staging directories,
returns a continuously held descriptor, and the helper revalidates that object
before and after no-replace installation. This protects the selected object
identity, bytes, and access policy under a cooperative same-UID model. It does
not isolate against a hostile debugger or racer running as the same UID.

## Validate And Recover

Before relying on an older snapshot, run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" validate-snapshot \
  --snapshot-dir /private/tmp/<task-backup> \
  --manifest-creation-receipt-file \
    /private/tmp/<task-backup>.creation-result.json
```

Validation must bind the artifact root, manifest, declared database members,
and external receipt through the same held descriptor graph. A rollback journal
is not guessed away; treat it as an explicit recovery blocker. Timestamp-only
changes do not fail when object identity, content, and access policy remain
stable.

Prefer manifest-driven recovery:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- recover-snapshot \
  --snapshot-dir /private/tmp/<task-snapshot> \
  --out /private/tmp/<task-snapshot>-analysis.sqlite \
  --manifest-creation-receipt-file \
    /private/tmp/<task-snapshot>.creation-result.json
```

Use `merge-db` only for a copied database that has no snapshot manifest:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- merge-db \
  --src /private/tmp/<copy>/group.com.apple.notes/NoteStore.sqlite
```

Run queries only against a validated, recovered standalone database, never the
live container:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" note-tags \
  --db /private/tmp/<task-snapshot>-analysis.sqlite \
  --title '<exact note title>'
```

Recovery consumes the held main/WAL/SHM set, produces a sidecar-free database,
and requires full SQLite integrity validation before publication. It does not
make a live cross-file snapshot transactional; authoritative recovery still
requires Notes to remain quit.

## Stage And Preflight A Patch

Prepare edits only on a copied or recovered database. Normalize the edited
database into a new patch stage:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- stage-patch \
  --src /private/tmp/<edited>/NoteStore-edited.sqlite \
  --dest /private/tmp/<task-patch-stage> \
  --result-file /private/tmp/<task-patch-stage>.creation-result.json
```

The stage may contain only `NoteStore.sqlite` and `patch-manifest.json`. Validate
it independently when needed:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" validate-patch-stage \
  --stage-dir /private/tmp/<task-patch-stage> \
  --manifest-creation-receipt-file \
    /private/tmp/<task-patch-stage>.creation-result.json
```

While Notes remains quit, bind the live store, backup, and stage:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" preflight-writeback \
  --backup-dir /private/tmp/<task-backup> \
  --stage-dir /private/tmp/<task-patch-stage> \
  --backup-manifest-creation-receipt-file \
    /private/tmp/<task-backup>.creation-result.json \
  --stage-manifest-creation-receipt-file \
    /private/tmp/<task-patch-stage>.creation-result.json
```

The backup must use snapshot v4 and bind the complete live source directory
chain. Success is point-in-time evidence from one joint backup/stage/live
revalidation while all descriptors remain held; it does not authorize a later
write or remove the need for a fresh write transaction boundary.

Present the exact whole-store replacement and recovery plan before requesting
write authorization.

## Verify A Completed Writeback

Keep Notes quit and run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" verify-writeback \
  --backup-dir /private/tmp/<task-backup> \
  --stage-dir /private/tmp/<task-patch-stage> \
  --backup-manifest-creation-receipt-file \
    /private/tmp/<task-backup>.creation-result.json \
  --stage-manifest-creation-receipt-file \
    /private/tmp/<task-patch-stage>.creation-result.json
```

Require the live main database to be a new object matching the staged bytes,
preserve the baseline access policy, require stale WAL/SHM files to be absent,
and require full SQLite integrity success. Keep the fresh pre-write backup until
Joey accepts the result.

## Failure Handling

- Never retry or clean by pathname when publication is `committed` or
  `uncertain`; preserve every recovery locator.
- Treat missing, unreadable, identity mismatch, content mismatch, access-policy
  mismatch, and inconclusive revalidation as distinct outcomes.
- Do not delete a retained partial or quarantine unless its descriptor-bound
  identity and the governing recovery contract authorize that exact cleanup.
- A failed Notes-state probe is `unknown`, never evidence that Notes is quit.
- Keep artifact and result-receipt destinations separate.

## Report

State:

- the authorization source and exact task-scoped paths;
- whether Notes was quit for every critical step;
- snapshot classification and SQLite integrity result;
- WAL/SHM/rollback-journal interpretation;
- read-only findings separately from patch/writeback actions;
- each missing, unreadable, mismatched, or inconclusive gate by exact code;
- where external snapshot/stage receipts were preserved; and
- that preflight and verification do not make multi-file writeback atomic.
