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

Protect five properties independently:

1. **Object identity**: bind the opened regular file to device, inode, and file type, then require
   the pathname to resolve to that same object after the read.
2. **Content stability**: hash the same opened descriptor twice and require equal SHA-256 and size.
3. **Access policy**: require mode, owner, group, and platform file flags to remain unchanged.
4. **Path-component identity**: open each absolute directory component no-follow relative to its
   already-held parent and reject every symlink/reparse point except an explicitly registered
   Darwin root-alias object.
5. **Notes process-state authority**: accept only a closed, validated result from the fixed
   `/usr/bin/pgrep -x Notes` probe; unknown state never authorizes writeback readiness.

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
The v3 snapshot and patch manifests persist creation-time identity and access-policy receipts for
their root directories and database files; snapshots also persist the nested store-directory
receipt. Their successful creator results separately return an
`apple-notes-manifest-creation-receipt/v1` object containing the manifest's exact SHA-256, size,
identity, and access policy. The caller must preserve that result outside the artifact. Validators
bind the artifact root once before loading the external receipt. The receipt externality proof and
read, exact root scan, manifest open/read, nested-store binding, declared-file binding,
recovery-clone capture, SQLite integrity check, and terminal scans must reuse that same held root
object or child descriptors opened relative to it. No artifact consumer may reopen the root
pathname after the receipt load. Compare the external receipt with the descriptor-relative held
manifest before parsing or trusting any manifest field. Reject v1/v2 manifests and missing
receipts rather than silently deriving an anchor from current artifact bytes.

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

Before releasing any live-source descriptor, hash that same descriptor once more and compare the
receipt's SHA-256 and size plus descriptor/path identity and access policy both before and after
that terminal hash. Record any `mtime`, `ctime`, or link-count transition in the returned receipt,
but do not fail on those metadata signals alone when identity, bytes, and access policy remain
stable. The terminal pathname access-policy comparison is required even when the descriptor's
policy still matches an earlier observation.

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
Bind the serialized payload's expected SHA-256, exact length, and `0600` mode before creating or
writing the output. After `fchmod` and `fsync`, require two consecutive same-descriptor hashes to
match that pre-bound digest; around each hash compare descriptor and descriptor-relative pathname
identity, size, and full access policy with the creation receipt. Never derive the receipt digest
or length from bytes first observed after a competing writer could have changed the output.

Treat a validated sidecar-free standalone file as a different source profile from a recovery
store. Its later backup reads and revalidates only the already held main-file descriptor, builds
another anonymous image from those exact bytes, and never scans its containing directory for a
new WAL, SHM, or rollback journal. An adjacent sidecar injected after standalone validation cannot
be admitted into the final backup.

After standalone main-file publication, parent fsync, terminal main-file rehash, and the initial
public-path proof, retain the output-parent descriptor and perform two complete no-follow namespace
passes for the final output's `-wal`, `-shm`, and `-journal` names. `FileNotFoundError` is absent;
any successful stat is present regardless of file type; `PermissionError` is unreadable; every
other `OSError` is unverifiable. All three names must be absent in both passes. After both passes,
rebind the public parent pathname, require its identity and access policy to match the still-held
parent, and re-prove the public main name's identity, SHA-256, size, and access policy through that
rebound parent before returning success. Because the main file is already published, any
non-absent or inconclusive sidecar observation, unreadable public path, persistent parent
replacement, or public-main mismatch is `destination-install-uncertain`, never an uncommitted or
successful result. Preserve the strong descriptor-bound main receipt and point-in-time sidecar
observations, but do not call an unbound sidecar display path a verified recovery locator.
For snapshot recovery, keep the output-parent scope and held snapshot artifact in the same
transaction until their final revalidations finish. Once the public-main receipt has succeeded,
translate every later output-parent, ancestor-chain, snapshot-directory, manifest, or snapshot-file
identity/content/access-policy failure to `destination-install-uncertain`. Preserve
`publication_state: uncertain`, `retry_safe: false`, the descriptor-bound parent/main
identity/SHA-256/size/access-policy locator, and the underlying machine reason.

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
Before that validation context can allocate a temporary directory or create a recovery clone, bind
the snapshot root read-only, prove output/snapshot separation, and acquire the shared live-safe
destination guard. Direct group/app outputs, reserved store components, and symlink aliases into a
live container must fail before any temporary directory, clone, SQLite backup, or standalone
writer is invoked. Retain the snapshot and destination bindings through final publication
revalidation.
Before creating any recovery-output parent, bind the snapshot root and the output path's nearest
existing directory ancestor. Starting from the held output-ancestor descriptor, open only `..`
relative to each descriptor and compare every directory `(st_dev, st_ino)` with the held snapshot
root. Reject any match as `recovery-output-inside-snapshot`; pathname spelling, Unicode/case
normalization, and symlink aliases are not overlap evidence. Create missing safe parent components
relative to the proved ancestor with no-follow opens, bind the final output parent, and repeat the
descriptor ancestry proof. Keep the standalone output as a snapshot sibling so recovery cannot add
a member to the exact validated snapshot root.

## Snapshot And Stage Publication

Publish a completed snapshot or patch stage from its private partial directory with an atomic
no-replace operation: `renamex_np(..., RENAME_EXCL)` on macOS or
`renameat2(..., RENAME_NOREPLACE)` on Linux. If the platform primitive is unavailable, fail closed
instead of falling back to a check-then-rename sequence. An existing destination, including an
empty directory that appeared after an earlier check, must remain untouched.

Before `copy-db`, `merge-db`, `recover-snapshot`, or `stage-patch` creates any destination-parent
component or output, enter one shared live-container guard. Compare case-folded NFD path components
against both Apple Notes live-container paths and bind those live containers plus the nearest
existing destination ancestor. Traverse from the filesystem root through every existing component
with descriptor-relative no-follow `stat`/`open`, retaining each parent/child identity and access
policy. For an initially absent live container, retain its nearest existing ancestor plus exact
missing suffix and fail if the first missing component appears. Reject either direction of
normalized ancestor/descendant overlap.
A lexical normalized overlap or a descriptor-ancestor identity match proves
`snapshot-destination-inside-live-container`; an unavailable, replaced, or access-policy-mutated
binding is `snapshot-destination-scope-inconclusive`. Reject `NoteStore.sqlite`,
`NoteStore.sqlite-wal`, `NoteStore.sqlite-shm`, and `NoteStore.sqlite-journal` as destination path
components even when the corresponding live sidecar is absent. This guard precedes the first
mkdir, file creation, partial, backup, manifest/receipt, helper output, or rename. Hold and
revalidate live-container and destination-ancestor object identity, location scope, and access
policy through publication. Use that same nearest-ancestor/component binding for descriptor-relative
parent creation, creator receipts, publication, and terminal revalidation; an unexpected
`FileExistsError` for a formerly missing component is a race, not permission to adopt it.
Directory child-entry churn is not itself content mutation outside those reserved names.

Darwin root aliases are an explicit, exact registry rather than a general symlink exception:
`/tmp -> /private/tmp`, `/var -> /private/var`, and `/etc -> /private/etc`. Bind the alias parent,
the no-follow alias entry identity/access policy, the exact link text, the followed canonical
target, and the canonical target parent before descending. Use the canonical target descriptors
for all mutation, and revalidate both alias and canonical namespaces before each write and at
terminal boundaries. Reject unregistered symlinks, case-only spellings, NFC/NFD variants,
retargeting, replacement, and mocked ABA observations before mutation. Carry the same live alias
binding object through derived prepared directories/files, same-root manifest-receipt parent
binding, creator-result scope evidence, directory/file installation checks, standalone public
parent rebind, and all final scans. A later boundary may bind a canonical descendant while that
object is held, but may not reopen the public alias raw or silently create a replacement alias
authorization.
Successful snapshot/stage creator results expose
`manifest_creation_destination_scope`, `terminal_destination_scope`, and
`descriptor_bound_destination`; standalone merge/recovery results expose the terminal scope and
descriptor/public-path receipts with the same alias evidence.

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
After the manifest is durably written, return its exact creation receipt in the successful
`copy-db` or `stage-patch` result. The result file is a separate caller-owned authority and must be
stored outside the published artifact, preferably as a sibling created under `umask 077`. A
consumer may supply either that complete creator result or the nested
`manifest_creation_receipt`; it may not self-bootstrap a receipt from the current manifest.
Before loading a CLI receipt file, bind its parent and the artifact root and traverse descriptor
ancestors to prove the receipt is outside the artifact. Bind the receipt as a no-follow regular
file, enforce the manifest-size bound, and require stable descriptor reads. Keep that exact
artifact-root binding alive after the receipt read and use it for every later root operation; bind
nested directories and regular files only relative to that root. A consumer must not load the
receipt, release or ignore its root binding, and then reopen the artifact pathname.
When artifact and receipt share a trusted Darwin alias, the receipt-parent binding must reuse the
artifact's held alias object and revalidate the public alias entry plus canonical target before and
after reading.
Receipt-parent binding never leaks the generic prepared-directory taxonomy: a missing parent is
`manifest-creation-receipt-missing`, a permission-denied parent is
`manifest-creation-receipt-unreadable`, and symlink, identity/access-policy, open, or other
revalidation failures are `manifest-creation-receipt-scope-inconclusive`.

Normalize every public snapshot/stage path once with lexical `abspath` semantics and derive the
artifact root, manifest, nested store/database, and external receipt from that absolute policy.
Do not use `resolve()` or another symlink-following canonicalizer. Relative API and CLI inputs must
therefore share one absolute parent policy while component binding still rejects alias, symlink,
and replacement races.
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

Every proved uncommitted directory publication failure, including an unrelated target that appears
before the no-replace rename can commit, carries `publication_state: uncommitted` and an explicit
`retry_safe`. If the exact held prepared root is instead already observed at the destination before
the local rename syscall, classify the installation as `uncertain` and retain a descriptor-bound
destination/tree receipt. Set `retry_safe: true` only after descriptor-bound revalidation proves
the held parent/root identity and access policy, the complete prepared tree membership, manifest
payload, every file's identity/SHA-256/size/access policy, and a terminal no-follow target
observation of `absent`. A present unrelated target or prepared-tree/content/access drift is still
uncommitted when the namespace proves that fact, but is not retry-safe; unavailable or
contradictory terminal namespace evidence is `publication_state: uncertain`. When the outer
retained-partial handler adds cleanup and inventory evidence, merge its locators without replacing
these publication fields or the complete-tree retry receipt.

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
Once the no-replace rename is known to have committed, catch every ordinary `Exception` from later
descriptor stat/read, parent fsync, receipt construction, tree scan, or public-path revalidation
and return `destination-install-uncertain`, `publication_state: uncertain`, and `retry_safe:
false`. This includes raw `ENOENT`, `EACCES`, `EIO`, and unexpected runtime exceptions. If a
terminal receipt itself cannot be completed, retain last-verified descriptor-bound
parent/prepared-root evidence and mark the sub-check inconclusive. Do not catch `BaseException`;
`KeyboardInterrupt` and `SystemExit` retain process-control semantics.

Standalone database publication uses an atomic no-replace rename from a descriptor-bound private
file. Bind the creation-time private parent and operate on the exact source and destination leaf
names relative to that descriptor. The rename consumes the prepared name, so there is no later
path-based unlink window. If the prepared name is replaced immediately before the syscall, the
replacement may move to the destination but must survive; the held object mismatch makes the
result uncertain rather than successful.
Every rename, parent fsync, and final fingerprint error must be classified:

- `uncommitted`: publication is proved not to have committed; `retry_safe` is true only when the
  destination is absent and the held parent plus prepared-file descriptors revalidate identity,
  two SHA-256 reads, size, and access policy against their creation receipts, and a terminal
  descriptor-relative no-follow observation through that same parent still proves the destination
  absent;
- `uncertain`: the destination may be committed or its durability/final fingerprint is not proved.

After commit, the uncertain classification also covers every ordinary exception from terminal
sidecar absence checks, descriptor-bound receipt construction, and public parent/main
revalidation. A failed terminal evidence sub-check never falls back to a pre-publication
`prepared-operation-failed` result.

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
`uncertain` with `retry_safe: false`. If the destination appears during prepared-file hashing,
classify it as `destination-exists`, keep publication `uncommitted`, and set `retry_safe: false`;
if terminal destination observation is unavailable, classify publication as `uncertain`.

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

The Notes process-state gate launches only `/usr/bin/pgrep -x Notes` with stdin closed, a minimal
fixed environment, a new process session, and a finite hard deadline. On timeout, terminate and
reap the entire process group, escalating from `SIGTERM` to `SIGKILL` after a bounded grace period.
Only return code `0` with one or more positive decimal PID lines means running. Only return code
`1` with empty stdout and stderr means quit. Exec/collection failure, timeout, stderr, malformed
PID output, an output/exit mismatch, or any other return code is `notes-state-unknown`; preflight
and verification must stop rather than treating unknown as quit.

Keep patch preparation separate from live replacement.
`stage-patch` and `preflight-writeback` are read-only with respect to the live container.

A writeback-grade backup must:

- be captured with `--require-notes-quit`;
- retain its successful artifact-external manifest creation receipt;
- record that Notes was not running;
- still match its copied-file hashes;
- recover successfully with full SQLite integrity;
- bind the current live file set to the same source object identities, bytes, and access policies.

A patch stage must contain only:

- `NoteStore.sqlite`;
- `patch-manifest.json`.

It must also retain its successful artifact-external manifest creation receipt. Preflight and
post-writeback verification require both the backup and stage receipts before consuming either
manifest.

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
- `snapshot-destination-inside-live-container`;
- `snapshot-destination-reserved-store-path`;
- `snapshot-destination-scope-inconclusive`;
- `manifest-creation-receipt-required`, `manifest-creation-receipt-invalid`;
- `manifest-creation-receipt-missing`, `manifest-creation-receipt-too-large`;
- `manifest-creation-receipt-not-external`;
- `manifest-creation-receipt-scope-inconclusive`;
- `manifest-creation-receipt-unreadable`;
- `manifest-creation-receipt-revalidation-unreadable`;
- `manifest-creation-receipt-file-identity-mismatch`;
- `manifest-creation-receipt-file-content-mismatch`;
- `manifest-creation-receipt-file-access-policy-mismatch`;
- `manifest-creation-receipt-file-revalidation-inconclusive`;
- `manifest-creation-receipt-identity-mismatch`;
- `manifest-creation-receipt-content-mismatch`;
- `manifest-creation-receipt-access-policy-mismatch`;
- `standalone-output-sidecar-present`;
- `standalone-output-sidecar-unreadable`;
- `standalone-output-sidecar-revalidation-inconclusive`;
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
- prevent a same-UID process from mutating an object immediately after the final descriptor/path
  comparison; the bounded revalidation window detects observed races but is not a filesystem lock;
- prevent a same-UID process from creating or changing a standalone sidecar immediately after the
  last terminal sidecar observation;
- authenticate an unsigned external manifest receipt when the same actor can also rewrite that
  receipt file; the anchor is trustworthy only while independently preserved by the caller;
- bound peak memory independently of recovered database size; native backup and serialization keep
  a complete recovered image in memory;
- replace a case-specific rollback plan and Joey's explicit writeback approval.
