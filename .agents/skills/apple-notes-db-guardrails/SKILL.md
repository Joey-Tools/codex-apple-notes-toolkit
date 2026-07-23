---
name: apple-notes-db-guardrails
description: Safely audit, copy, recover, stage, or verify Apple Notes container databases on macOS. Use when probing TCC or Full Disk Access for `NoteStore.sqlite`, inspecting Notes SQLite/WAL/SHM state, creating a validated `/tmp` snapshot, preparing a database patch, or guarding a whole-store writeback and recovery.
---

# Apple Notes DB Guardrails

## Resolve The Packaged Helper

Treat the directory containing this `SKILL.md` as `SKILL_DIR`.
Invoke `python3 "$SKILL_DIR/scripts/apple_notes_db.py" ...`.
Do not reconstruct a repository-root path or copy the helper into another skill.

Read [references/safety-contract.md](references/safety-contract.md) before planning any patch,
writeback, or recovery.

## Keep Audit And Patch Phases Separate

Default to read-only audit work.
Do not mutate the live Notes container with this helper; it intentionally provides staging,
preflight, and post-writeback verification rather than a live replacement command.

Treat a patch or writeback as a new phase that requires:

1. Notes to remain quit.
2. A fresh writeback-grade snapshot.
3. A sidecar-free staged database.
4. A clean read-only writeback preflight.
5. Joey's explicit approval of the exact change and replacement mechanics.
6. Immediate post-writeback verification while Notes remains quit.

## Probe Authorization

Run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" probe-db-access
```

Distinguish a missing path from an unreadable path or failed revalidation.
If TCC blocks access, stop and ask Joey to grant the required macOS permission or provide a
task-scoped copy from a privileged terminal.

Record whether the authoritative source is the live container or a Joey-provided copy.

## Capture A Read-Only Snapshot

Use a unique task-scoped destination:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" copy-db --dest /tmp/<task-snapshot>
```

Treat a snapshot captured while Notes is running as tentative.
Do not use it for absence claims, exact counts, patch planning, or writeback.

For critical analysis or a writeback baseline, quit Notes first and run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" copy-db \
  --dest /tmp/<task-backup> \
  --require-notes-quit
```

Keep `snapshot-manifest.json` with the copied file set.
Snapshot publication is atomic and no-replace on supported macOS/Linux filesystems.
If publication reports `destination-install-uncertain`, preserve the reported paths, do not retry
into that destination, and inspect whether the prepared directory committed.
Use `validate-snapshot` before relying on an older snapshot:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" validate-snapshot \
  --snapshot-dir /tmp/<task-backup>
```

## Recover For Analysis

Prefer `recover-snapshot` when a manifest is available:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" recover-snapshot \
  --snapshot-dir /tmp/<task-snapshot> \
  --out /tmp/<task-snapshot>/NoteStore-analysis.sqlite
```

Use `merge-db` only for a copied database file without a snapshot manifest:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" merge-db \
  --src /tmp/<copy>/NoteStore.sqlite \
  --out /tmp/<copy>/NoteStore-analysis.sqlite
```

Run queries against the recovered standalone database, never against the live container.

## Stage And Preflight A Patch

Prepare edits only on a copied or recovered database.
Normalize the edited database into a new patch stage:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" stage-patch \
  --src /tmp/<edited>/NoteStore-edited.sqlite \
  --dest /tmp/<task-patch-stage>
```

Require the stage to contain only `NoteStore.sqlite` and `patch-manifest.json`.
Validation examines every no-follow directory entry and rejects extra directories, FIFOs, and
symlinks as well as extra regular files.

While Notes remains quit, bind the live store, fresh backup, and stage:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" preflight-writeback \
  --backup-dir /tmp/<task-backup> \
  --stage-dir /tmp/<task-patch-stage>
```

Do not treat `ready_for_explicit_writeback: true` as authorization or as proof that a multi-file
atomic swap exists.
Present the planned whole-store replacement and recovery path to Joey and wait for explicit
confirmation.

## Verify A Completed Writeback

Keep Notes quit and run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" verify-writeback \
  --backup-dir /tmp/<task-backup> \
  --stage-dir /tmp/<task-patch-stage>
```

Require the live main database to be a new object that matches the staged bytes, preserve the
baseline access policy, require stale WAL/SHM files to be absent, and require SQLite
`PRAGMA integrity_check` to pass.
Keep the fresh pre-write backup until Joey accepts the result.

## Report

State:

- the authorization source and exact task-scoped paths;
- whether Notes was quit for every critical step;
- snapshot classification and SQLite integrity result;
- WAL/SHM recovery interpretation;
- read-only findings separately from patch/writeback actions;
- any missing, unreadable, mismatched, or inconclusive gate by its exact error code;
- that preflight and verification do not make multi-file writeback atomic.
