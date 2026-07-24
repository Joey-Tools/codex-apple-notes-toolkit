---
name: apple-notes-db-guardrails
description: Safely audit, copy, recover, stage, or verify Apple Notes container databases on macOS. Use when probing TCC or Full Disk Access for `NoteStore.sqlite`, inspecting Notes SQLite/WAL/SHM/rollback-journal state, creating a validated `/tmp` snapshot, preparing a database patch, or guarding a whole-store writeback and recovery.
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
The helper binds the private partial directory, its nested `group.com.apple.notes` store, and their
parents at creation. It verifies every prepared file against its creation receipt, fsyncs copied
files, then fsyncs the held nested-store and snapshot-root descriptors bottom-up before the
descriptor-relative rename. It fsyncs the held publication-parent descriptor and performs terminal
descriptor-relative revalidation. Sidecar classification and SQLite integrity checking consume
that same receipt-bound copied store through held descriptors; the manifest reuses those exact
results instead of reopening the copied path. Each live source is terminally rehashed through the
same held descriptor; descriptor and pathname identity/access policy are checked around that hash,
while `mtime`, `ctime`, and link-count transitions remain recorded metadata rather than mutation
signals. It never reopens a parent pathname for durability.
On an ordinary pre-publication failure, the helper
preserves the partial tree and attaches a creation-receipt-matched namespace locator plus a bounded
no-follow sensitive-file inventory to the original error. If the root is replaced or inventory is
inconclusive, the original error remains primary and reports the separate receipt failure.
An individual file writer also retains its failed output: it never follows a separate `stat` with
an `unlink`, because the namespace leaf could be replaced between those syscalls. The error carries
the held parent/file descriptor receipt, point-in-time namespace observations, `cleanup_state:
retained`, and `retry_safe: false`.
An otherwise unclassified runtime failure becomes `prepared-operation-failed`, retains the
underlying exception as its cause, and carries the same recovery details.
If publication reports `destination-install-uncertain`, preserve the reported paths, do not retry
into that destination, and inspect whether the prepared directory committed. A post-rename
uncertain result includes a descriptor-bound destination receipt with parent/directory identity,
access policy, and exact nested directory/file tree receipts. That receipt remains the recovery
locator if an ancestor path was permanently replaced before the descriptors closed.
For a directory rename that is proved not to have committed, inspect
`publication_state: uncommitted` and `retry_safe`. The latter is true only after the held parent,
prepared root, complete directory membership, manifest bytes, every prepared file's
identity/SHA-256/size/access policy, and a terminal absent target observation all revalidate.
Target appearance, tree drift, or inconclusive terminal evidence keeps `retry_safe: false` (and
uses `publication_state: uncertain` when commit/non-commit itself cannot be proved). The outer
retained-partial receipt augments these fields and locators without discarding them.
If the exact held prepared root already occupies the destination before the helper's own rename
syscall, treat the install as uncertain and preserve the descriptor-bound destination/tree receipt
rather than describing it as uncommitted.
Use `validate-snapshot` before relying on an older snapshot:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" validate-snapshot \
  --snapshot-dir /tmp/<task-backup>
```

Validation requires the v2 manifest's creation-time root/store/file identity and access-policy
receipts, then holds the manifest and every declared database-file descriptor through
recovery-clone creation, SQLite integrity checking, and terminal revalidation. Object replacement,
byte mutation, and access-policy change have distinct failure codes; timestamp-only changes do not
fail when the protected properties remain stable.

## Recover For Analysis

Prefer `recover-snapshot` when a manifest is available:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" recover-snapshot \
  --snapshot-dir /tmp/<task-snapshot> \
  --out /tmp/<task-snapshot>-analysis.sqlite
```

`recover-snapshot` consumes the private clone produced by that exact validation pass. It never
reopens the mutable snapshot paths after validation. Its recovery result carries the snapshot
manifest and database-file identity, SHA-256, size, and access-policy receipts from that validation
context rather than replacing them with only the SQLite integrity result.
The output must be a sibling of, never a member of, the snapshot tree. The helper rejects
object-identity overlap before it can create an output parent: it binds the snapshot root and the
output's nearest existing ancestor, then traverses `..` through held descriptors and compares
directory device/inode identity. This catches case-insensitive macOS spellings and symlink aliases
without trusting path string case. Missing safe output-parent components are created and rebound
relative to that proved ancestor, preserving the snapshot's exact root member set for later
validation.
The recovery step binds the clone directory, main database, and present WAL through held
descriptors, then revalidates object identity, content, access policy, and directory membership
against the clone's creation receipt before and after SQLite consumption. The receipt covers the
created directory, every copied main/WAL/SHM object, and the exact name/type membership, so a
replacement or injected entry between copying, sidecar inspection, and later recovery binding
fails closed. Recovery applies the checksum-valid committed WAL prefix to the held main-database
bytes and gives SQLite only an anonymous descriptor-backed recovered image. SQLite never reopens
the mutable main, WAL, SHM, or directory pathname.
Initial discovery also detects `NoteStore.sqlite-journal` without following links. Any present
rollback journal is descriptor-bound and then rejected as `rollback-journal-present`; if it cannot
be bound as one stable regular file, the same reason code is returned as inconclusive. Recovery
never guesses whether SQLite had finished rollback or whether journal pages remain authoritative.
The native SQLite backup API writes first to an in-memory database; serialized database bytes are
then written directly to the exclusively created output descriptor. Full integrity checking opens
the prepared standalone file through that same held descriptor. Before writing, the standalone
writer binds the serialized payload's expected SHA-256, byte length, and `0600` mode. It accepts a
creation receipt only after two consecutive same-descriptor readbacks plus size, access-policy,
and descriptor-relative pathname identity/access checks all match that pre-bound expectation.
Once a sidecar-free standalone image has been validated and bound, later backup copies only that
held image. A newly injected adjacent WAL is neither discovered nor trusted.
An ephemeral namespace replace-and-restore during SQLite backup may not be reported, but it cannot
redirect the bytes SQLite consumes. Persistent missing, replacement, content, access-policy, or
directory-membership changes fail before output publication. This does not make a live
cross-file snapshot transactional; authoritative recovery still requires Notes to remain quit.

Use `merge-db` only for a copied database file without a snapshot manifest:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" merge-db \
  --src /tmp/<copy>/NoteStore.sqlite \
  --out /tmp/<copy>/NoteStore-analysis.sqlite
```

`merge-db` JSON and the compatibility Python launcher expose both `standalone_db` and the legacy
`merged_db` alias for the same output path.

Run queries against the recovered standalone database, never against the live container.
For single-file publication failures, inspect `details.publication_state`,
`details.retry_safe`, and `details.recovery_locators`. Never retry when the state is `committed` or
`uncertain`; preserve every reported locator. Publication atomically renames the prepared leaf
within its bound private parent with no replacement; it does not create and later unlink a private
hard link. A prepared pathname is reported as verified only while both its parent and leaf still
match their creation receipts. Otherwise the locator is explicitly unverified and includes the
creation-time object and parent identities. After descriptor-relative durability and fingerprint
checks, the helper also binds the public parent pathname and leaf one final time. A persistent
ancestor replacement is therefore `destination-install-uncertain`; its details include a
descriptor-bound destination receipt with parent/leaf identity, SHA-256, size, and access policy
even when the display path no longer resolves to that object.
A rename failure is retry-safe only after the still-held parent and prepared-file descriptors
revalidate parent/leaf identity, two SHA-256 reads, size, and access policy against the creation
receipt, followed by a terminal no-follow destination observation through that same parent
descriptor. In-place byte or mode drift, an appearing destination, or unavailable terminal
destination evidence makes `retry_safe: false`, even when the source inode remains named and an
earlier destination observation was absent.

The packaged helper remains compatible with Python 3.9. Do not use newer runtime-only call
arguments, such as `zip(..., strict=True)`, without adding a consistent minimum-version gate.

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
