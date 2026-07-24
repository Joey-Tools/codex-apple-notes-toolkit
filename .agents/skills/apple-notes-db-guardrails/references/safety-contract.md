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

For `validate-snapshot` and patch-stage validation, hold the manifest and every declared regular
file descriptor through recovery-clone creation, WAL/SHM inspection, SQLite integrity checking,
directory revalidation, and the terminal protected-property check. A same-byte inode replacement
is an identity mismatch; a mode/owner/group/flags change is an access-policy mismatch; an in-place
byte change is a content mismatch. Do not accept a fresh pathname open as proof about the object
that supplied earlier validation evidence.
The v2 snapshot and patch manifests must persist creation-time identity and access-policy receipts
for their root directories and database files; snapshots also persist the nested store-directory
receipt. Validators compare all receipt fields before consuming SQLite bytes and reject v1
manifests rather than silently applying the weaker contract.

Treat these outcomes separately:

- missing before or after the read;
- permission or revalidation failure;
- object replacement;
- content mismatch;
- access-policy mismatch;
- SQLite/WAL/SHM/rollback-journal file-set membership change.

Do not collapse unreadable, failed revalidation, missing, and mismatched into one result.
Map generic descriptor/path/hash revalidation failures such as `EIO` or `ESTALE` to
`source-revalidation-inconclusive`; do not let them escape as `unexpected-error`. Continue to map
`FileNotFoundError` to missing-after-read and `PermissionError` to revalidation-unreadable, while
identity, content, and access-policy comparison failures keep their dedicated codes.

## Stable Descriptor Capture

Discover the main database and sidecar membership, open every present regular file without
following symlinks, and hold all descriptors through capture.

For each file:

1. Compare pre-open path identity with the opened descriptor.
2. Copy or hash from that descriptor.
3. Rewind and hash the same descriptor again.
4. Compare descriptor identity, content stability, and access policy.
5. Re-resolve the path without following symlinks and compare object identity.

Recheck the main/WAL/SHM/rollback-journal membership after all files have been processed.
A present `NoteStore.sqlite-journal` is not an ignorable sidecar. Open it without following links,
bind and hash the same descriptor twice, then fail closed with `rollback-journal-present` before
copy or recovery. A symlink, non-regular entry, unreadable journal, or unstable journal returns the
same reason with `binding_status: inconclusive`. Only SQLite may decide whether a hot DELETE or
PERSIST journal must roll the main database back.

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
Reject a copy when trusted same-generation SHM says an invalid WAL frame was already committed.

Treat `NoteStore.sqlite-shm` as a derived WAL-index cache, not as authoritative durable content.
Parse WAL-index integers only in the current host's native byte order and validate each header
checksum in that order. A header may prove a committed frame only when both 48-byte copies are
individually checksum-valid and byte-for-byte identical, match the WAL generation, and bind
`mxFrame`, `aFrameCksum`, and `nPage` to that exact complete physical WAL commit frame. If any part
of that proof is absent—including foreign-endian input, an out-of-range frame, a non-commit frame,
or mismatched frame checksum/page count—report `derived-rebuild-required`; never upgrade
unrelated or incomplete SHM evidence to `wal-shm-commit-mismatch`.
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
Bind the private recovery directory first, then open the main database and present WAL relative to
that held directory descriptor. Keep the directory, main, and WAL descriptors open across byte
capture and SQLite backup. Before and after SQLite consumption, require:

- the directory descriptor and pathname to identify the same directory object with the same mode,
  owner, group, and platform flags;
- two descriptor-relative directory scans to retain the exact name/type map captured at binding;
- the main and WAL descriptor identities, SHA-256 values, sizes, and access policies to remain
  stable and to match their descriptor-relative names; and
- any WAL classified as authoritative by the validated recovery evidence to remain present.

Create and retain a recovery-clone receipt before releasing the creation-time directory
descriptor. Bind that receipt to the created directory identity/access policy, every copied
main/WAL/SHM identity/SHA-256/size/access policy, and the exact directory name/type map. Inspect
WAL and derived SHM bytes only through the receipt-bound copied descriptors. Every later recovery
binding must match this creation receipt before consuming bytes. Persistent directory or file
replacement, byte or access-policy mutation, and entry addition/removal between copy, sidecar
inspection, and later binding therefore fail closed.

The initial snapshot copy follows the same rule before writing its manifest: immediately bind the
copied store relative to the already held nested-directory descriptor, compare every file with the
capture-time identity/SHA-256/size/access-policy receipt, classify sidecars, and run recovery
integrity through those held descriptors. Reuse those exact results in the manifest. Do not
separately reopen copied paths for sidecar or SQLite validation; a same-UID swap-and-restore must
either be irrelevant to descriptor consumption or fail receipt revalidation.

Parse and apply the checksum-valid WAL frames through the last commit frame to the stable held
main-database bytes. Use that commit frame's database-size field as the final page count. Reject a
page-size mismatch, invalid commit boundary, or database growth that cannot be bounded by the main
database plus the committed frame count.
The WAL header stores page size as an unsigned 32-bit value. Accept `65536` directly; reject `1`
instead of applying the SQLite database-header 16-bit `1 => 65536` sentinel rule to WAL bytes.
Write the recovered image to an anonymous temporary regular-file descriptor and open only that
descriptor through a read-only, immutable SQLite URI. Revalidate the anonymous descriptor before
and after the native backup. SQLite never receives or reopens the mutable main, WAL, or containing
directory pathname, so a replace-then-restore namespace race during SQLite open cannot substitute
different source bytes.
Run the native SQLite backup API into an in-memory destination, serialize that database, and write
the bytes directly to the exclusively created output descriptor. Never ask SQLite to reopen the
mutable output pathname. Bind the completed output and run `PRAGMA integrity_check` through its
read-only descriptor URI; replacing and restoring the output pathname during either write or
integrity validation must not redirect those operations.

Treat a validated sidecar-free standalone file as a different source profile from a recovery
store. Its later backup reads and revalidates only the already held main-file descriptor, builds
another anonymous image from those exact bytes, and never scans its containing directory for a
new WAL, SHM, or rollback journal. An adjacent sidecar injected after standalone validation cannot
be admitted into the final backup.

The protected recovery property is that SQLite consumes exactly the image derived from the
creation-receipt-bound main descriptor plus the last committed checksum-valid WAL prefix.
Persistent missing, unreadable, replaced, content-mutated, access-policy-mutated, or
directory-membership-mutated input fails before the output path is created or published. An
ephemeral namespace replacement restored before terminal revalidation may not be reported; it
cannot alter the already captured descriptor bytes or redirect SQLite's anonymous input. This
mechanism still does not provide a transactional cross-file snapshot while another process writes.
Require Notes to stay quit whenever the result must be authoritative.

Use the following recovery boundary:

- authoritative input: main database plus a valid, non-empty WAL when present;
- derived input: SHM, preserved as evidence but omitted from recovery;
- output: one standalone SQLite database with no WAL or SHM.

Keep the original snapshot manifest and raw file set until the task is complete.

`recover-snapshot` must consume the private recovery clone produced by its exact successful
validation context. Do not reopen the original snapshot main/WAL/SHM paths between validation and
recovery. The validation artifact exposes the clone and evidence, not the held source descriptors,
and its private lifetime covers the complete standalone backup operation. Preserve that artifact's
manifest and database-file identity, SHA-256, size, and access-policy receipts in the recovery
result; SQLite integrity output supplements rather than replaces source-integrity evidence.
Reject a recovery output that is lexically within, or resolves through existing symlinks within,
the snapshot directory before creating the output parent. Keep the standalone output as a snapshot
sibling so recovery cannot add a member to the exact validated snapshot root.

## Snapshot And Stage Publication

Publish a completed snapshot or patch stage from its private partial directory with an atomic
no-replace operation: `renamex_np(..., RENAME_EXCL)` on macOS or
`renameat2(..., RENAME_NOREPLACE)` on Linux. If the platform primitive is unavailable, fail closed
instead of falling back to a check-then-rename sequence. An existing destination, including an
empty directory that appeared after an earlier check, must remain untouched.

Create the partial root through a parent directory descriptor, immediately bind the root and parent
descriptors, then create and bind the nested `group.com.apple.notes` store relative to that held
root. Hold all three descriptors, identities, and access policies through publication. Bind every
prepared regular file and compare it with its creation receipt: exact identity, SHA-256, size, and
access policy. Parse the installed manifest and require it to equal the in-memory payload. Verify
the exact no-follow root and nested name/type sets plus every held file immediately before rename.
After each copied file has been fsynced, fsync the held nested-store descriptor and then the held
snapshot-root descriptor; revalidate their receipts and exact membership between those bottom-up
durability steps. Rename the source/destination names relative to the held publication parent,
fsync that same parent descriptor, and terminally revalidate the installed root relative to it.
Never reopen the parent pathname between rename and durability. A temporary parent-path
replacement therefore cannot redirect publication evidence, while identity or access-policy
changes on the held parent fail separately.
Create copied database files, standalone recovery files, and manifest temporary files exclusively
relative to those held directory descriptors. Perform their name-based validation through the same
descriptors; never reconstruct a full pathname for those operations.
On writer failure, retain the created file and report the held parent/file descriptor identities,
access policies, content status, and point-in-time namespace observations. Do not attempt automatic
name-based cleanup: even descriptor-relative `stat(name)` followed by `unlink(name)` has a
replacement window and cannot protect deletion target identity. Mark the retained output
`retry_safe: false`; any later destructive action must independently rebind and match the reported
object.

After any publication error, compare the private source and destination namespaces with the
prepared directory's object identity. Report a proved pre-existing destination as
`destination-exists`, a proved uncommitted failure as `destination-install-failed`, and a
commit-then-error or any namespace state that cannot prove commit/non-commit as
`destination-install-uncertain`. Preserve an uncertain path for inspection and do not retry into
the same destination.

Before the publication descriptors close, record a descriptor-bound recovery locator for any
post-rename uncertain directory. It binds the held publication parent and destination directory
identity/access policy plus the exact root/nested name-type maps and regular-file
identity/SHA-256/size/access-policy receipts. Revalidate that tree through the held root, nested
directory, and regular-file descriptors after rename. If final public-parent pathname validation
fails because an ancestor was permanently replaced, report `destination-install-uncertain` with
that descriptor receipt; the display path alone is not the recovery locator.
If source or destination namespace observation is unavailable, still report
`publication_state: uncertain`, `retry_safe: false`, and descriptor-bound parent/prepared-root plus
last-verified target-tree evidence. Mark unavailable namespace evidence as inconclusive instead of
omitting the recovery locator.

Standalone database publication uses an atomic no-replace rename from a descriptor-bound private
file. Bind the creation-time private parent and operate on the exact source and destination leaf
names relative to that descriptor. The rename consumes the prepared name, so there is no later
path-based unlink window. If the prepared name is replaced immediately before the syscall, the
replacement may move to the destination but must survive; the held object mismatch makes the
result uncertain rather than successful.
Every rename, parent fsync, and final fingerprint error must be classified:

- `uncommitted`: publication is proved not to have committed; `retry_safe` is true only when the
  destination is absent and the held parent plus prepared-file descriptors revalidate identity,
  two SHA-256 reads, size, and access policy against their creation receipts;
- `uncertain`: the destination may be committed or its durability/final fingerprint is not proved.

Return `publication_state`, `retry_safe`, and `recovery_locators` in error details. Never encourage
a retry for `uncertain`. Include a verified prepared pathname only when its current parent and leaf
match their creation receipts. Otherwise emit an explicitly unverified locator containing the
recorded path, device/inode/file type, and parent identity. After the descriptor-relative parent
fsync and terminal leaf fingerprint, reopen the public parent pathname only for a final identity and
access-policy proof, and require its leaf to identify the prepared object. This pathname check does
not provide durability. A persistent parent-path replacement is `destination-install-uncertain`;
while the held parent is still open, attach a descriptor-bound recovery locator containing the
actual parent/leaf identities, access policies, SHA-256, and size even if the display path now
names another namespace.
Source-name identity plus destination absence alone never makes a failed rename retry-safe.
In-place byte, size, or access-policy drift retains the failed artifact but changes the result to
`uncertain` with `retry_safe: false`.

Pre-publication failure handling protects deletion target identity by deleting nothing through a
mutable pathname. While the creation-time root and parent descriptors are still open, revalidate
the exact root relative to the held parent and scan a bounded sensitive-file inventory twice
without following child links. Preserve the complete partial tree and attach `cleanup_state:
retained`, the verified root/parent identities, exact namespace, and inventory to the original
error. If the root is missing, replaced, over the inventory bounds, or cannot be revalidated,
preserve the current namespace, keep the original error primary, and attach a separate
`cleanup_error_code` plus recovery locators. Access-policy changes remain distinct validation
failures; mtime, ctime, and directory link-count behavior are not deletion-identity signals.
Wrap an unclassified ordinary runtime failure as `prepared-operation-failed`, preserve the
underlying exception as `__cause__`, and include its type/errno with the retained-partial receipt.

The wrapper invokes generic `python3`, and the helper supports Python 3.9. Keep runtime API calls
within that compatibility floor unless the wrapper, documentation, and tests adopt a newer
minimum together.

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
- `wal-invalid`, `sqlite-recovery-failed`, `sqlite-integrity-failed`;
- `wal-shm-commit-mismatch`;
- `notes-started-during-capture`, `notes-started-during-preflight`;
- `notes-started-during-verification`;
- `snapshot-content-mismatch`, `snapshot-file-set-mismatch`;
- `snapshot-directory-identity-mismatch`;
- `snapshot-directory-access-policy-mismatch`;
- `snapshot-file-identity-mismatch`, `snapshot-file-access-policy-mismatch`;
- `snapshot-file-revalidation-inconclusive`;
- `backup-not-writeback-grade`, `baseline-identity-mismatch`;
- `baseline-content-mismatch`, `baseline-access-policy-mismatch`;
- `patch-file-set-mismatch`, `patch-content-mismatch`;
- `stage-directory-identity-mismatch`;
- `stage-directory-access-policy-mismatch`;
- `patch-file-identity-mismatch`, `patch-file-access-policy-mismatch`;
- `patch-file-revalidation-inconclusive`;
- `prepared-directory-identity-mismatch`;
- `prepared-directory-missing`;
- `prepared-directory-access-policy-mismatch`;
- `prepared-directory-revalidation-inconclusive`;
- `prepared-file-identity-mismatch`, `prepared-file-content-mismatch`;
- `prepared-file-access-policy-mismatch`, `prepared-file-revalidation-inconclusive`;
- `prepared-file-missing`, `prepared-file-set-mismatch`;
- `prepared-manifest-mismatch`;
- `destination-exists`, `destination-install-failed`;
- `destination-install-uncertain`;
- `recovery-output-inside-snapshot`, `recovery-output-scope-inconclusive`;
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
- bound peak memory independently of recovered database size; native backup and serialization keep
  a complete recovered image in memory;
- replace a case-specific rollback plan and Joey's explicit writeback approval.
