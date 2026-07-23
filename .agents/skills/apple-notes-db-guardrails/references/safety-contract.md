# Apple Notes Store Safety Contract

## Contents

- [Protected Properties](#protected-properties)
- [Format Authorities](#format-authorities)
- [Stable Descriptor Capture](#stable-descriptor-capture)
- [SQLite, WAL, And SHM Roles](#sqlite-wal-and-shm-roles)
- [Integrity And Recovery](#integrity-and-recovery)
- [Snapshot And Stage Publication](#snapshot-and-stage-publication)
- [Patch And Writeback Boundary](#patch-and-writeback-boundary)
- [Failure Classes](#failure-classes)
- [Non-Guarantees](#non-guarantees)

## Format Authorities

Use SQLite's [database file format](https://sqlite.org/fileformat2.html#walformat) for WAL header,
frame, salt, and rolling-checksum semantics.
Use SQLite's [WAL-mode file format](https://sqlite.org/walformat.html) for WAL-index/SHM layout,
native byte order, recovery, and SHM's non-durable role.

## Protected Properties

Protect three properties independently:

1. **Object identity**: bind the opened regular file to device, inode, and file type, then require
   the pathname to resolve to that same object after the read.
2. **Content stability**: hash the same opened descriptor twice and require equal SHA-256 and size.
3. **Access policy**: require mode, owner, group, and platform file flags to remain unchanged.

For the snapshot store directory and patch-stage directory, bind object identity and access policy
in the same way. Treat the complete no-follow entry name/type map as directory content: an extra
directory, FIFO, socket, device, or symlink—including a broken symlink—is a file-set mismatch.
Scan the directory twice through opened descriptors. Do not infer mutation from directory `mtime`
alone when identity, access policy, and both name/type scans remain stable.

Record `mtime`, `ctime`, and link-count transitions, but do not classify those transitions alone as
content or access-policy mutation. A metadata-only transition is acceptable only when the
descriptor stays bound to the same object, both byte hashes match, size is stable, and the selected
access-policy signals are unchanged.

Treat these outcomes separately:

- missing before or after the read;
- permission or revalidation failure;
- object replacement;
- content mismatch;
- access-policy mismatch;
- SQLite/WAL/SHM file-set membership change.

Do not collapse unreadable, failed revalidation, missing, and mismatched into one result.

## Stable Descriptor Capture

Discover the main database and sidecar membership, open every present regular file without
following symlinks, and hold all descriptors through capture.

For each file:

1. Compare pre-open path identity with the opened descriptor.
2. Copy or hash from that descriptor.
3. Rewind and hash the same descriptor again.
4. Compare descriptor identity, content stability, and access policy.
5. Re-resolve the path without following symlinks and compare object identity.

Recheck the main/WAL/SHM membership after all files have been processed.

This sequence detects ordinary replacement and mutation races. It does not create a cross-file
transactional snapshot while Notes is writing. Require Notes to stay quit for exact analysis,
writeback baselines, and any recovery decision that must be authoritative.

## SQLite, WAL, And SHM Roles

Treat `NoteStore.sqlite` as the main database.
Treat a valid non-empty `NoteStore.sqlite-wal` as durable state that may contain committed pages not
yet checkpointed into the main database.
Validate the WAL header checksum, page size, frame boundaries, per-frame salts, and rolling frame
checksums before recovery.
Follow SQLite recovery semantics by using only the checksum-valid frame prefix through its last
commit frame and reporting any ignored tail.
Reject a copy when same-generation SHM says an invalid WAL frame was already committed.

Treat `NoteStore.sqlite-shm` as a derived WAL-index cache, not as authoritative durable content.
Inspect its duplicate headers and report whether they match the copied WAL.
Do not fail recovery solely because SHM is absent or stale.
Instead, preserve the raw SHM in the evidence snapshot, omit it from the isolated recovery clone,
and let SQLite rebuild the WAL index from the main database and valid WAL.

Reject an invalid WAL even when the main database alone opens successfully.
Ignoring a malformed or mismatched WAL can silently discard committed Notes changes.

## Integrity And Recovery

Run recovery only in a task-scoped working copy.
Never let SQLite checkpoint or rebuild sidecars against the live Notes container or the raw evidence
snapshot.

Run full `PRAGMA integrity_check` after opening the recovery clone.
When producing an analysis database or patch stage, use SQLite's backup API to create a standalone
database, normalize it to non-WAL journal mode, close it, and run full `PRAGMA integrity_check`
again.

Use the following recovery boundary:

- authoritative input: main database plus a valid, non-empty WAL when present;
- derived input: SHM, preserved as evidence but omitted from recovery;
- output: one standalone SQLite database with no WAL or SHM.

Keep the original snapshot manifest and raw file set until the task is complete.

## Snapshot And Stage Publication

Publish a completed snapshot or patch stage from its private partial directory with an atomic
no-replace operation: `renamex_np(..., RENAME_EXCL)` on macOS or
`renameat2(..., RENAME_NOREPLACE)` on Linux. If the platform primitive is unavailable, fail closed
instead of falling back to a check-then-rename sequence. An existing destination, including an
empty directory that appeared after an earlier check, must remain untouched.

After any publication error, compare the private source and destination namespaces with the
prepared directory's object identity. Report a proved pre-existing destination as
`destination-exists`, a proved uncommitted failure as `destination-install-failed`, and a
commit-then-error or any namespace state that cannot prove commit/non-commit as
`destination-install-uncertain`. Preserve an uncertain path for inspection and do not retry into
the same destination.

## Patch And Writeback Boundary

Keep patch preparation separate from live replacement.
`stage-patch` and `preflight-writeback` are read-only with respect to the live container.

A writeback-grade backup must:

- be captured with `--require-notes-quit`;
- record that Notes was not running;
- still match its copied-file hashes;
- recover successfully with full SQLite integrity;
- bind the current live file set to the same source object identities, bytes, and access policies.

A patch stage must contain only:

- `NoteStore.sqlite`;
- `patch-manifest.json`.

Never install a staged main database beside an old live WAL or SHM.
Treat replacement of the main name and removal of live sidecar names as one whole-store semantic
boundary, even though the filesystem offers no true multi-file atomic swap.

Before any live mutation, present the exact replacement and rollback mechanics to Joey and wait for
explicit approval.
Keep Notes quit across preflight, replacement, rollback if needed, and immediate verification.
Retain the validated raw backup until Joey accepts the result.

If the replacement mechanics cannot make recovery from interruption clear, stop rather than
improvising.
Restore the complete pre-write namespace from the validated backup boundary; never restore only a
main database while mixing it with sidecars from another state.

After replacement, require:

- live main-database object identity differs from the baseline object;
- live bytes equal the staged database;
- live mode, owner, group, and file flags equal the baseline access policy;
- live WAL and SHM names are absent before Notes restarts;
- full SQLite integrity succeeds from an isolated verification clone.

## Failure Classes

The helper emits stable error codes, including:

- `source-missing`, `source-missing-after-read`;
- `source-unreadable`, `source-revalidation-unreadable`;
- `source-revalidation-inconclusive`;
- `source-identity-mismatch`, `source-content-mismatch`;
- `source-access-policy-mismatch`;
- `store-file-set-mismatch`;
- `directory-identity-mismatch`, `directory-access-policy-mismatch`;
- `directory-scan-inconclusive`;
- `wal-invalid`, `sqlite-integrity-failed`;
- `wal-shm-commit-mismatch`;
- `notes-started-during-capture`, `notes-started-during-preflight`;
- `notes-started-during-verification`;
- `snapshot-content-mismatch`, `snapshot-file-set-mismatch`;
- `backup-not-writeback-grade`, `baseline-identity-mismatch`;
- `baseline-content-mismatch`, `baseline-access-policy-mismatch`;
- `patch-file-set-mismatch`, `patch-content-mismatch`;
- `destination-exists`, `destination-install-failed`;
- `destination-install-uncertain`;
- `post-writeback-identity-mismatch`, `post-writeback-file-set-mismatch`;
- `post-writeback-content-mismatch`, `post-writeback-access-policy-mismatch`.

Preserve the exact code in reports and automation.
Do not reinterpret a safety error as an empty result.

## Non-Guarantees

The helper does not:

- grant TCC or Full Disk Access;
- prove Notes remained quit between process-state probes;
- create a transactional cross-file snapshot while Notes is running;
- make a main/WAL/SHM filesystem replacement atomic;
- mutate the live Notes store;
- validate every macOS ACL, extended attribute, File Provider policy, or external process;
- replace a case-specific rollback plan and Joey's explicit writeback approval.
