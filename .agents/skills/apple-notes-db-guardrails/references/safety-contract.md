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
3. **Access policy**: require mode, owner, group, and Darwin flags that enforce
   immutable, append-only, Data Vault, restricted, or no-unlink behavior to
   remain unchanged. Raw `st_flags` outside that mask are metadata evidence.
4. **Path-component identity**: open each absolute directory component no-follow relative to its
   already-held parent and reject every symlink/reparse point except an explicitly registered
   Darwin root-alias object.
5. **Notes process-state authority**: accept only a closed, validated result from the fixed
   `/usr/bin/pgrep -x Notes` probe; unknown state never authorizes writeback readiness.

For the snapshot store directory and patch-stage directory, bind object identity and access policy
in the same way. Treat the complete no-follow entry name/type map as directory content: an extra
directory, FIFO, socket, device, or symlink—including a broken symlink—is a file-set mismatch.
Give each scan the exact small expected raw-name namespace. Reject the first
unexpected raw name before calling `stat` or retaining it. Each pass has a
hard limit of 64 entries and 4 KiB of aggregate raw name bytes; reject
duplicate raw names, decoded-name collisions, invalid round trips, and any
limit overflow as a file-set mismatch. Scan the directory twice through opened
descriptors and compare both raw-name/type and decoded-name/type maps. Do not
infer mutation from directory `mtime` alone when identity, access policy, and
both bounded scans remain stable.
At every point in those scans, translate lower prepared-directory identity, access-policy,
membership, and revalidation failures into the exact snapshot or patch-stage codes selected by the
caller. Generic `directory-*` or `prepared-directory-*` codes must not escape an artifact-specific
validation boundary.

Record `mtime`, `ctime`, and link-count transitions, but do not classify those transitions alone as
content or access-policy mutation. A metadata-only transition is acceptable only when the
descriptor stays bound to the same object, both byte hashes match, size is stable, and the selected
access-policy signals are unchanged.

For `validate-snapshot` and patch-stage validation, hold the manifest and every declared regular
file descriptor through recovery-payload construction, WAL/SHM inspection, SQLite integrity checking,
directory revalidation, and the terminal protected-property check. A same-byte inode replacement
is an identity mismatch; a mode/owner/group or access-controlling flag change is
an access-policy mismatch; an in-place byte change is a content mismatch.
Hidden, no-dump, opaque, compression, tracking, archived, firmlink, and File
Provider/dataless flag transitions are reported as metadata when the protected
properties stay stable. Do not accept a fresh pathname open as proof about the
object that supplied earlier validation evidence.
The v3 snapshot and patch manifests persist creation-time identity and access-policy receipts for
their root directories and database files; snapshots also persist the nested store-directory
receipt. Their successful creator results separately return an
`apple-notes-manifest-creation-receipt/v1` object containing the manifest's exact SHA-256, size,
identity, and access policy. The caller must preserve that result outside the artifact. Validators
bind the artifact root once before loading the external receipt. The receipt externality proof and
read, exact root scan, manifest open/read, nested-store binding, declared-file binding,
recovery-payload construction, SQLite integrity check, and terminal scans must reuse that same held root
object or child descriptors opened relative to it. No artifact consumer may reopen the root
pathname after the receipt load. Compare the external receipt with the descriptor-relative held
manifest before parsing or trusting any manifest field. Reject v1/v2 manifests and missing
receipts rather than silently deriving an anchor from current artifact bytes.
After that anchor check, require snapshot `files` to be a non-empty JSON array of exact objects and
validate every `basename` as an exact string in the closed NoteStore allowlist before constructing
any set, mapping, hash key, or path from those values. A list, object, null, boolean, unsupported
string, duplicate, or missing main database entry is stable `manifest-invalid`; never let an
unhashable manifest value escape as `unexpected-error`, and never echo its potentially large
representation into the error.

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
Apply that source mapping to post-open descriptor, descriptor-relative path, content-hash, and
held-parent checks. Apply it before open as well: a discovered member's dedicated re-stat and the
bound regular-file helper's descriptor-relative pre-open `stat` or `open` use the same source
classifier. This source-specific rule must not change a snapshot, patch, or prepared-file caller's
own inconclusive code. A rollback journal keeps the top-level `rollback-journal-present` policy
result while its structured `reason_code` records the source-specific missing, unreadable, or
inconclusive cause. When a generic prepared-directory error wraps an OS error, inspect its explicit
cause chain before interpreting the outer code: `ENOENT` is missing, `EACCES`/`EPERM` is
unreadable, and another OS error is inconclusive. Only an identity or access-policy comparison
failure without a causal OS error is a proved mismatch. For `probe-db-access`, enumerate each
container through its held descriptor with a complete 64-entry/4-KiB aggregate raw-name cap, sort
only that bounded set, and retain at most five names. Limit overflow stops iteration and records
that container as revalidation-inconclusive. Keep each container's enter, sample, terminal check,
and component-chain exit inside its own result boundary. A successful sample establishes the
post-read boundary: translate failure from the following explicit namespace check or later generic
component-chain exit to the corresponding source class without treating it as initial absence or
aborting the whole probe. Close each opened file descriptor first and keep the final held-parent
check inside that file's result boundary; failure leaves the file unreadable with the same source
classification rather than aborting the whole probe with a prepared-directory error. If the
initial group-container bind fails before a binding exists, keep `prepared-directory-missing` as
ordinary absence, but propagate initial permission failure as `container-unreadable` and other
I/O uncertainty as `container-revalidation-inconclusive` to every dependent NoteStore file row;
an app-container-only failure must not affect those group-derived rows. Retain the group-container
binding until all dependent NoteStore file rows have been inspected. If its final context exit
then fails, set every dependent row `readable: false`, replace its error with that terminal source
classification, and remove `size`, `identity`, and `access_policy`; no file row may retain authority
after its parent source boundary becomes invalid. Carry group/app roles as explicit control state,
not `Path` equality. If both configured paths are equal, open and close both role contexts exactly
once and retain only the first role's group binding through dependent file inspection.
Keep the underlying generic directory context inside one source-owned enter/body/exit lifecycle.
After the source body and source-specific terminal revalidation succeed, translate any generic
component-chain exit failure from the caught evidence without re-probing a mutable namespace.
`ENOENT`, `EACCES`/`EPERM`, another stat error, a cause-free identity comparison, and a cause-free
access-policy comparison remain respectively missing-after-read, revalidation-unreadable,
revalidation-inconclusive, source-identity-mismatch, and source-access-policy-mismatch. Copy and
merge wrappers may add mutation/publication evidence, but they must retain that source code as the
underlying failure instead of exposing a `prepared-directory-*` code.

## Stable Descriptor Capture

Bind the complete group-container path once, one no-follow component at a time, and retain that
single component chain for the complete NoteStore transaction. Discover main/WAL/SHM/
rollback-journal membership, open every present regular file, hash/copy bytes, and perform final
membership and protected-property revalidation only relative to the held group-container
descriptor. No
source operation may restart from a full pathname or bind a second parent authority. Hold all
component and file descriptors through capture.
Open every existing untrusted regular-file leaf with
`O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`, then require the opened descriptor to remain the
same regular object observed before open. `O_NOFOLLOW` rejects a symlink substitution;
`O_NONBLOCK` ensures that a FIFO or blocking-device substitution cannot prevent the post-open
`fstat` from rejecting its file type. Directory opens and exclusive new-file creation have
separate flag contracts and are not substitutes for this leaf rule.

For each file:

1. Compare pre-open path identity and access policy with the opened descriptor.
2. Immediately re-resolve the descriptor-relative path without following
   symlinks and require all three observations—pre-open path, opened
   descriptor, and post-open path—to retain the same identity and access
   policy. Never adopt the opened or post-open policy as a new baseline.
3. Copy or hash from that descriptor only after the three-way open-boundary
   proof succeeds.
4. Rewind and hash the same descriptor again.
5. Compare descriptor identity, content stability, and access policy.
6. Re-resolve the path without following symlinks and compare object identity.

Before releasing any live-source descriptor, hash that same descriptor once more and compare the
receipt's SHA-256 and size plus descriptor/path identity and access policy both before and after
that terminal hash. Record any `mtime`, `ctime`, or link-count transition in the returned receipt,
but do not fail on those metadata signals alone when identity, bytes, and access policy remain
stable. The terminal pathname access-policy comparison is required even when the descriptor's
policy still matches an earlier observation.

Recheck the main/WAL/SHM/rollback-journal membership only after every bound file has completed its
terminal double hash. Bracket that reserved-name scan with complete held-parent directory-chain
revalidation, compare the result with the binding-time baseline, and use the post-scan directory
receipt as the terminal authority. A persistent late WAL or rollback journal, or a parent
replacement that persists through this boundary, fails closed. Transient unrelated child-entry
churn and its directory timestamp effects remain benign when directory identity, access policy,
reserved membership, and every bound file's identity, content, and access policy remain stable.
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
Instead, preserve the raw SHM in the evidence snapshot, omit it from the authoritative anonymous
recovery payload, and let SQLite rebuild the WAL index from the main database and valid WAL.

Reject an invalid WAL even when the main database alone opens successfully.
Ignoring a malformed or mismatched WAL can silently discard committed Notes changes.

## Integrity And Recovery

Run recovery only inside a task-scoped held-descriptor transaction.
Never let SQLite checkpoint or rebuild sidecars against the live Notes container or the raw
evidence snapshot.

Run full `PRAGMA integrity_check` against the anonymous recovered image.
When producing an analysis database or patch stage, use SQLite's backup API to create a standalone
database, normalize it to non-WAL journal mode, close it, and run full `PRAGMA integrity_check`
again.
Bind the live source or validated snapshot store once, then open the main database and present
WAL/SHM only relative to that held directory descriptor. Keep the complete parent-component
chain, store directory, main, WAL, and SHM descriptors open across byte capture, integrity, and
SQLite backup. Before and after SQLite consumption, require:

- the directory descriptor and pathname to identify the same directory object
  with the same mode, owner, group, and Darwin access-controlling flag mask;
- two descriptor-relative directory scans to retain the exact name/type map captured at binding;
- the main and WAL descriptor identities, SHA-256 values, sizes, and access policies to remain
  stable and to match their descriptor-relative names; and
- any WAL classified as authoritative by the validated recovery evidence to remain present.

Retain the initial directory/file identity, SHA-256, size, access-policy, and exact name/type
membership receipts on those same descriptors. Inspect WAL and derived SHM bytes only through the
held files. Revalidate those receipts before and after payload construction, integrity checking,
backup, and context teardown. Do not create a named recovery-clone directory or release the held
source authority and later rebind it. Persistent directory or file replacement, byte or
access-policy mutation, and entry addition/removal between binding, sidecar inspection, and later
consumption therefore fail closed.

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
Write the recovered image to an anonymous temporary regular-file descriptor, then reread only that
same receipt-matched descriptor into a native SQLite allocation. Deserialize the allocation with
`SQLITE_DESERIALIZE_READONLY`. Revalidate descriptor identity, two content hashes, size, and access
policy plus the exact deserialized-buffer SHA-256 before and after every native integrity query or
backup boundary. SQLite never receives or reopens the mutable main, WAL, containing directory,
`/dev/fd`, or `/proc/self/fd` pathname, so a replace-then-restore namespace race cannot substitute
different source bytes.
On Linux, `tempfile.TemporaryFile` may use `O_TMPFILE`. A separate `open("/dev/fd/<fd>")` can
succeed while SQLite VFS full-path processing of the anonymous inode still fails, so a descriptor
reopen probe is neither a portability gate nor an input-binding proof. The native read-only
deserialization path is required on Linux and macOS; a missing `sqlite3_deserialize`,
`sqlite3_malloc64`, query, backup, or serialize interface fails closed under the calling SQLite
error class.
SQLite cannot deserialize a WAL-mode header directly. For an exact SQLite database header, byte
18 is the write version and byte 19 is the read version. Preserve only the exact rollback pair
`1/1`; only after checksum-valid committed WAL frames have been applied, normalize the exact WAL
pair `2/2` to `1/1`. Reject mixed and invalid version pairs before deserialization. Write the
accepted bytes into the anonymous descriptor and bind its receipt, so normalization becomes the
explicit descriptor content authority rather than an unverified post-capture mutation.
Close the native SQLite connection before releasing its allocation. Every ordinary native runtime
or `ctypes` failure must retain the calling SQLite error class and attach bounded
`sqlite_input_cleanup` evidence. If connection close is not proved, retain the allocation instead
of risking a use-after-free. The anonymous file descriptor remains owned by its context and is
closed without a pathname cleanup step. When a consumer failure is superseded by a terminal input
revalidation failure, keep the revalidation as the primary cause and record the consumer failure
as structured secondary evidence. A `sqlite3_exec` row callback must catch its first
`BaseException` inside the ctypes boundary, return a nonzero abort code, free SQLite's returned
error string, and then classify and latch an ordinary callback failure with its original cause
before either terminal buffer or descriptor-binding revalidation. If either revalidation also
fails, keep that revalidation primary and preserve the classified callback plus its nested
`sqlite_callback_failure` as `sqlite_input_secondary_failure`. Do not translate
`KeyboardInterrupt` or `SystemExit`; when either is captured in the callback or observed elsewhere
before teardown begins, abort the native query, run the safe input cleanup first, and then re-raise
the original process-control exception.
Run the native SQLite backup API into an in-memory destination, serialize that database, and write
the bytes directly to the exclusively created output descriptor. Never ask SQLite to reopen the
mutable output pathname. Bind the completed output, reread that exact descriptor into the same
read-only deserialization path, and run `PRAGMA integrity_check` there; replacing and restoring
the output pathname during either write or integrity validation must not redirect those
operations.
For backup failures, attach `sqlite_backup_cleanup` and independently attempt each still-safe
backup-finish, serialized-buffer-free, and destination-close step even when another cleanup step
fails. Attempt each owned release at most once; an exception that makes release state ambiguous
must remain incomplete rather than risking a double finish, double free, use-after-free, or false
cleanup claim.
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

`recover-snapshot` must consume the exact held snapshot store produced by its successful validation
context. Do not reopen the original snapshot main/WAL/SHM paths between validation and recovery.
The validation artifact exposes held store operations and evidence whose lifetime covers the
complete standalone backup operation. Preserve its manifest and database-file identity, SHA-256,
size, and access-policy receipts in the recovery result; SQLite integrity output supplements
rather than replaces source-integrity evidence.
Before that validation context can build recovery bytes, bind the snapshot root read-only, prove
output/snapshot separation, and acquire the shared live-safe destination guard. Direct group/app
outputs, reserved store components, and symlink aliases into a live container must fail before
payload construction, SQLite backup, or a standalone writer. Do not allocate a named temporary or
recovery-clone directory; use only in-memory payloads and anonymous temporary file descriptors.
Retain the snapshot and destination bindings through final publication revalidation.
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
component or output, enter one shared live-container guard. First expand the destination and every
Apple Notes live-container path into distinct requested and exact registered-canonical alias forms.
Construct both live-container inputs as lexical absolute paths against one
captured working directory before the guard starts. Never re-resolve a relative
container after preflight; the fixed paths are the only values persisted in
`source_root`, returned as `live_source_root`, or used for equality.
For `merge-db` and `stage-patch`, the public API and CLI boundary uses that
same one-shot rule for `src` and every output path, including the optional
stage result file. Freeze them before any destination preflight and use the
frozen source in manifests and terminal results. A CWD change after preflight
must not retarget the database that can later reach writeback.
Every other public multi-path API follows the same command-snapshot contract:
freeze a copy destination before the Notes-state probe; freeze an artifact root
and external receipt together for validation; freeze snapshot, receipt,
standalone output, and live containers together for recovery; and freeze
backup, patch stage, and both receipt files together for writeback preflight or
verification. The CLI captures CWD before argument parsing and dispatch, then
passes that exact value to internal API helpers. No probe, descriptor-binding
callback, or nested validator may cause one related relative path to be
reinterpreted against a later CWD.
Compare the complete cross-product with case-folded NFD path components and reject either direction
of normalized ancestor/descendant overlap before binding a component or invoking the directory
creator. Thus an absent `/tmp/live` protects `/private/tmp/live/...`, and an absent
`/private/tmp/live` protects `/tmp/live/...`, without relying on the live leaf already existing or
on a post-creation revalidation. Then bind both live containers plus the nearest existing
destination ancestor. Traverse from the filesystem root through every existing component with
descriptor-relative no-follow `stat`/`open`, retaining each parent/child identity and access
policy. For an initially absent live container, retain its nearest existing ancestor plus exact
missing suffix and fail if the first missing component appears.
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

`copy-db` and `stage-patch` have two coordinated destinations when
`--result-file` is present. Before any identity-bound directory creator,
`mkdir`, partial, or output creation, complete a zero-write command preflight:
run the Notes-state gate where applicable; prove that the artifact leaf is
absent and outside the live containers; prove normalized requested/canonical
artifact-result separation in both directions; and independently bind the
result's live-container scope, trusted alias, nearest existing ancestor,
missing suffix, and absent leaf. Hold both proofs concurrently and revalidate
the artifact proof only after the result proof has completed. Replacement,
alias retargeting, access-policy drift, a newly present unproved component, or
unavailable evidence between those two proofs fails before either creator may
run.

When a direct public output API was not supplied a held creator preflight, it
must acquire the same zero-write proof and call the descriptor-bound absent-leaf
assertion before committing the destination parent or creating a private
partial. A destination that appears after an earlier lexical check is
`destination-exists`; it must not cause the helper to create and retain a
partial first.
After the parent commit returns a `_LiveDestinationScope`, perform one final
descriptor-relative scope and formal-leaf absence revalidation immediately
before calling the `.partial-*` creator. This is the artifact zero-write
linearization point. Parent components created by the earlier commit retain
their own mutation/receipt classification, but a failure here must prove that
no artifact partial creator ran.

After both proofs succeed, commit the artifact destination first. A missing
result parent remains absent until artifact publication succeeds. Artifact
parent creation may legitimately create a prefix shared with the result
parent; advance the held result proof across that prefix only when every newly
present component exactly matches the artifact's retained no-replace creation
receipt for object identity and access policy. Never adopt a newly observed
component as a fresh baseline. Only then may the result-parent commit invoke a
creator. Before each creator boundary, revalidate the corresponding held
ancestor, live-container, alias, missing-component, and containment evidence.
A pre-creator failure reports `mutation_performed: false`. Once either commit
crosses a creator boundary, merge errors conservatively so no successful or
uncertain parent/artifact mutation is omitted; a result transaction attempted
after artifact publication also reports `artifact_mutation_performed: true`
and `mutation_performed: true`.

Never `mkdir` a missing destination component or private-partial target name directly from the DB
worker. Under the already-held parent, require the packaged or caller-supplied supervisor to
allocate an unpredictable `.apple-notes-create-<128-bit-random>` directory with mode `0700`, open
that name with `O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, and return the continuously held
descriptor plus an `apple-notes-identity-bound-directory-creation/v2` proof. The proof binds the
creation method, explicit threat model, parent/directory identity, and access policy. The packaged
creator uses `mkdirat-randomized-openat-nofollow-revalidate` under a cooperative same-UID model:
random-name creation, no-follow open, and FD/name/parent revalidation protect against accidental
replacement and persistent drift, but do not claim isolation from a hostile same-UID process that
can race or debug the supervisor. `namespace_race_excluded_by_model: true` is valid only inside
that stated cooperative model. A stronger privileged or atomic creator may declare its own
non-empty method and threat model through the same v2 proof.

The packaged production launcher creates an already-connected `AF_UNIX`/`SOCK_DGRAM` socketpair,
forks the bundled supervisor service, and launches the DB helper with the client descriptor
supplied as `--directory-creator-fd`; it never discovers or reconnects to a mutable socket
pathname. The shell wrapper and the legacy-compatible Python executable both
select this launcher automatically for write-producing commands unless the
caller already supplied a stronger inherited supervisor channel. Once the
compatibility wrapper source is already executing, it must capture the fixed
supervisor source through a lexical-absolute regular-file descriptor using
`O_NOFOLLOW`, `O_NONBLOCK`, and `O_CLOEXEC`; bind identity and complete access
policy across pre-open path / descriptor / terminal path, enforce `1..2 MiB`,
and require two identical complete reads. Compile-exec only those captured bytes;
do not use `SourceFileLoader`, write source-tree bytecode, or reopen the
supervisor path. The captured supervisor module owns the only helper capture
and helper module used by the compatibility API, parent/service protocol, and
worker. Read-only and explicit-supervisor-FD commands dispatch through that
already captured helper. Write-producing commands call that same supervisor
module's `run_supervised`. For each creation, send one bounded
`apple-notes-directory-creator-request/v2` datagram and the already-held parent descriptor with
`SCM_RIGHTS`. Bind the request nonce, operation, prefix, mode, effective UID, parent identity, and
parent access policy. Accept only one bounded `apple-notes-directory-creator-response/v2`
datagram with the same nonce. A status `created` response requires exactly one returned descriptor,
a canonical staging basename, and the v2 creation proof. The packaged service is a practical
creation authority for the cooperative same-UID model: it revalidates the held parent, uses a
CSPRNG basename, calls descriptor-relative `mkdir`, immediately opens no-follow, and compares the
FD/name/parent identity and access policy before returning the FD with `SCM_RIGHTS`. Any failure
after `mkdir` preserves the randomized name, transfers an available descriptor, and reports a
structured uncertain recovery locator; it never performs name-based cleanup. The protocol retains
the exact closed `unavailable-before-create` response for a creator that can prove it did not enter
the mutation boundary. The client accepts that no-mutation claim only through canonical typed JSON
equality; bool-as-int, unknown keys, any descriptor, basename, proof, or other near-match is a
conservative possible-mutation transport failure.
Before forking the service or spawning the independent-session worker, the launcher blocks
`SIGHUP`, `SIGINT`, and `SIGTERM` and installs non-raising first-signal latches. Worker creation
must use a close-all-except primitive after the child snapshot, never a parent-side open-FD
inventory followed by per-FD close actions. Before either child exists, the
already captured supervisor module must have captured the fixed packaged
helper from a lexical-absolute no-follow, nonblocking, close-on-exec
regular-file descriptor. Bind one object identity and complete access policy
across the pre-open path, descriptor, and terminal path; accept only `1..2
MiB`; require two identical complete reads around descriptor/path
revalidation. Do not treat timestamps as content authority. Reject every
non-packaged `--helper` path before capture, module execution, service fork, or
worker spawn. Load the parent/service protocol module and deliver worker source
from this exact same immutable capture.

The packaged CPython launcher therefore uses
`subprocess.Popen(close_fds=True, pass_fds=(client_fd, source_read_fd),
start_new_session=True)`, with no `preexec_fn`; the second descriptor is an
anonymous launch-only pipe, not a helper pathname. The parent frames the
captured source with fixed magic, unsigned length, and SHA-256 and writes it
nonblocking under a hard deadline and byte ceiling. Its fixed
`python -I -B -S -c` bootstrap comes from already-loaded parent memory, reads
the exact frame concurrently, rejects invalid magic, metadata, truncation,
digest mismatch, or trailing bytes, then closes the source descriptor before
restoring the exact selected child signal defaults/mask. It compiles the
captured bytes with the recorded path used only as diagnostic display metadata;
it never reopens either helper or supervisor pathname. At helper execution,
only the supervisor channel plus standard descriptors remain. These source
capture properties begin after the compatibility wrapper itself is already
executing: they neither authenticate nor revalidate that already-running
wrapper object, and they do not defend process memory from a malicious
same-UID debugger or `ptrace` peer. A descriptor
made inheritable immediately before the fork is either absent from the child
snapshot or closed in the child before its first exec. Delivery
timeout/BrokenPipe closes both pipe ends and triggers bounded worker
termination and reap. The PID becomes parent-owned while the parent mask is
still closed. Also block `SIGCHLD` and temporarily
replace its parent disposition with `SIG_DFL` before either child exists, so inherited `SIG_IGN`
cannot auto-reap the raw-waitpid children. The worker must receive default `SIGHUP`, `SIGINT`,
`SIGTERM`, and `SIGCHLD`; keep parent `SIGCHLD` blocked until worker and service status collection
finishes, then restore the caller's exact disposition and mask. If `waitpid` still reports
`ECHILD`, treat the service as already terminal but fail the launcher because its status is
unavailable; map unavailable worker status to conservative exit code `1`. Neither condition may
escape the cleanup boundary or authorize signaling a possibly reused PID. The service restores
its original handlers/mask after fork. The parent may then restore its termination-signal mask,
but it retains the non-raising latches through bounded worker/service kill, drain, and reap. Later
termination signals cannot replace the first signal or interrupt cleanup. At the terminal
boundary, block again, consume at most one snapshot of pending managed signals, restore the
original handlers/mask, and re-deliver the first signal so teardown remains bounded even under a
signal storm.
Validate the returned descriptor/name/proof again inside the helper. No configured channel or a
non-socket/wrong socket type detected before the first send attempt is a proved no-mutation
`directory-creation-identity-inconclusive`; after entering the request-send boundary, send or
receive failure, timeout, truncation, malformed JSON, nonce/schema/status mismatch, or
descriptor-count error is possibly post-mutation and must retain every received FD until
conservative evidence is captured.
Treat provider `details` as untrusted protocol input even after JSON decoding. Normalize only the
documented boolean, bounded-string, state-enum, and bounded closed-JSON locator fields; reject
unknown or malformed nested locator containers with an explicit normalization receipt. Build and
merge the complete transport failure receipt while all SCM_RIGHTS descriptors remain in the
cleanup-owned list, then explicitly transfer at most the first evidence FD into the structured
failure. If normalization internals, receipt construction, or conservative merge raises an
ordinary exception, close every received descriptor before returning a fixed transport locator
with `mutation_performed: true`, `retry_safe: false`, inconclusive cleanup, no transferred FD, and
the evidence-construction failure type. Never re-enter the same untrusted merge after removing an
FD from cleanup ownership.
Require every retained provider response schema/basename, proof key/string, documented details
string, unknown details field name, and recovery-locator key/string to contain only Unicode scalar
values and encode with strict UTF-8. Reject lone surrogates with fixed normalization reasons; never
copy them into recovery details. Keep any provider `publication_state` only as an unverified claim
inside the provider-scoped normalization locator. It is not local namespace evidence and must not
participate in top-level recovery-detail merging. A post-request transport failure therefore sets
top-level `publication_state: uncertain` unless a separate local namespace proof establishes
another state. Serialize CLI JSON with ASCII escaping so an unexpected surrogate cannot suppress
the structured error on strict UTF-8 stdout.

A creator that raises after entering its mutation boundary must use
`_IdentityBoundDirectoryCreationFailure` and transfer the created staging basename, open
descriptor, creation-time stat, provider proof, and provider recovery details. Descriptor
ownership transfers to the helper. The helper treats the handoff proof as unvalidated, captures
bounded point-in-time evidence through the transferred descriptor and held parent, closes the
descriptor after evidence capture, preserves the created namespace, and reports
`creation-identity-inconclusive`, `mutation_performed: true`, and `retry_safe: false`. Provider
details merge conservatively: mutation is ORed, retry safety is ANDed, cleanup takes the worst
state, and locator keys are preserved. An unstructured creator exception cannot prove that no
directory was created; classify mutation and cleanup as conservative/inconclusive rather than
claiming `mutation_performed: false`.
A creator call that returns normally has already crossed the same possible-mutation boundary.
Normalize and validate the whole return value before reading fields as trusted: `None`, a mapping
or unexpected object, missing attributes, wrong field types, an FD aliasing the held parent, and
invalid semantic proof are failures after possible creation. Safely extract a bounded staging
basename and any separately transferred integer FD without closing the held parent. Capture
point-in-time descriptor/namespace evidence, close every recoverable transferred or ancillary FD,
set `mutation_performed: true`, `retry_safe: false`, and worst-case cleanup, then preserve the
union of malformed-result, creator-failure, and created-directory-install locators. Never let an
attribute error escape into a `not-needed` cleanup result or leak a returned FD.

Validate the creator-returned descriptor against its staging name before using it. Install that
held object at the target basename only with the platform's atomic no-replace directory rename,
then verify the target name against the retained descriptor before and after the carried scope
revalidation. Metadata-only changes are evidence, not object or access-policy changes;
replacement, disappearance, or mode/owner/group/access-controlling-flag drift
fails closed. If the proof, name, or descriptor cannot be reconciled, retain
point-in-time provider/name evidence but label the protected property
`creation-identity-inconclusive`; never sign a replacement as
`transaction-created-object-identity`. If atomic no-replace is unsupported,
stop rather than reverting to direct `mkdir(target)` or check-then-rename.
Build the exact component install receipt from the creator-held parent/object/proof before the
rename, but latch it as installed only in the first state update after the no-replace rename
returns. Before any subsequent scope revalidation, register that receipt with the parent
component transaction. Every ordinary failure after one or more installs—including the next
component's precheck, post-install chain validation, yielded consumer failure, post-yield
validation, and descriptor teardown—must merge every latched component receipt, report
`mutation_performed: true`, preserve or worsen cleanup evidence, and force `retry_safe: false`.
The outer parent scope must derive mutation from those details even when the component context
never yielded.
After the installed target passes the carried scope and descriptor/name checks, fsync the exact
held parent directory before returning the installation or creating the next missing component,
then revalidate the installed target once more. The protected property is directory-entry
durability; the final fsync of a later populated private output directory is a distinct boundary
and cannot substitute for it. A parent-fsync failure after the no-replace rename proves that the
name installation mutated the namespace and returned successfully, but does not prove persistence
across a crash. Preserve the exact install and created-object recovery identities, report
the committed internal name installation in `directory_component_commit`, mark
directory-entry durability `unverified`, force `retry_safe: false`, and stop before every later
component. That component-scoped receipt must not set top-level
`publication_state: committed` before the enclosing artifact's own publication rename. When the
component belongs to an unpublished private partial root, the enclosing transaction must still
retain and merge the partial root's descriptor-bound locator and sensitive inventory while
preserving the failed component's exact recovery identity. A failure before the no-replace rename
must not acquire that committed-name classification or a successful durability receipt.

On creation collision or any post-creation failure, retain the created descriptor evidence plus
point-in-time staging/target observations. Do not `stat(name)` and then `rmdir(name)`: there is no
portable directory unlink that atomically binds removal to the observed identity. Automatic
cleanup is therefore allowed only through a future identity-bound primitive; otherwise report
`preserved-no-identity-safe-directory-unlink` and the exact structured recovery locator.

Darwin root aliases are an explicit, exact registry rather than a general symlink exception:
`/tmp -> /private/tmp`, `/var -> /private/var`, and `/etc -> /private/etc`. Bind the alias parent,
the no-follow alias entry identity/access policy, the exact link text, the followed canonical
target, and the canonical target parent before descending. Use the canonical target descriptors
for all mutation, and revalidate both alias and canonical namespaces before the first destination
component creation, before each later write, and at terminal boundaries. Reject unregistered
symlinks, case-only spellings, NFC/NFD variants, retargeting, replacement, and mocked ABA
observations before mutation. An initially absent live descendant still carries this held alias
object, so same-target alias replacement or retargeting fails closed before its destination
creator can run. Carry the same live alias binding object through derived prepared
directories/files, same-root manifest-receipt parent binding, creator-result scope evidence,
directory/file installation checks, standalone public parent rebind, and all final scans. A later
boundary may bind a canonical descendant while that object is held, but may not reopen the public
alias raw or silently create a replacement alias authorization. Carry a trusted alias object into
another binding only when both paths resolve through the same exact registry pair. If artifact and
external result/receipt paths use different registry pairs, or only one uses a registered alias,
bind the other path independently and keep both alias/root proofs separate.
Successful snapshot/stage creator results expose
`manifest_creation_destination_scope`, `terminal_destination_scope`, and
`descriptor_bound_destination`; standalone merge/recovery results expose the terminal scope and
descriptor/public-path receipts with the same alias evidence.

Create and bind the partial root through the randomized staging/no-replace protocol above, then
create and bind the nested `group.com.apple.notes` store with the same protocol relative to that
held root. Hold the parent/root/nested descriptors, identities, access policies, and
creation-install receipts through publication. Bind every
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
descriptors; never reconstruct a full pathname for those operations. Immediately after each
exclusive file creation and before writing bytes, enforce and bind the expected effective
UID/GID, mode `0600`, the Darwin access-controlling flag mask, object identity,
and descriptor-relative no-follow name. Preserve raw `st_flags` separately as
metadata. Compare the complete creation-bound access policy and identity after
the write, around consecutive readbacks, immediately before publication, after
the name transition, and after parent durability. A post-write stat is never
allowed to establish a new access-policy baseline.
After the manifest is durably written, return its exact creation receipt in the successful
`copy-db` or `stage-patch` result. The result file is a separate caller-owned authority and must be
stored outside the published artifact. Use the packaged `--result-file` interface rather than
shell redirection: before artifact creation it performs only the zero-write external-parent,
missing-suffix, live-container, alias, absent-leaf, and artifact-containment proof described
above. It creates no missing result parent at that stage. After artifact publication succeeds, it
commits the held result-parent scope, rejects every pre-existing leaf including symlinks, creates
an unpredictable descriptor-relative temporary regular file with
`O_NOFOLLOW|O_CREAT|O_EXCL`, enforces exact effective owner/group and mode `0600` before writing,
performs stable content readback, fsyncs the file, publishes with an atomic no-replace rename,
fsyncs the held parent, and terminally revalidates the external name and artifact separation.
Pass a result-scope callback into the atomic JSON writer and invoke it after
the writer's ordinary parent check but immediately before the
`.RESULT.tmp-*` `O_EXCL` open. The callback must revalidate the committed scope
and descriptor-relative public result leaf; its failure is the result
zero-write linearization point and leaves no temporary result object.
Before the result write begins, bind the reopened artifact to the successful
creator payload's `descriptor_bound_destination` and exact prepared-tree creation receipt rather
than accepting the reopened object as a new baseline. Require the held parent and artifact root
identity/access policy, every exact directory membership, and every file identity/access
policy/SHA-256/size to match that receipt; require the manifest entry to match the separately
returned `manifest_creation_receipt`. Hold those descriptors through result publication and
revalidate the complete receipt-bound tree immediately after the result commit. A pre-bind
directory replacement or in-place content mutation must fail without publishing stale creator
evidence. Once the no-replace result-file writer returns its terminal receipt, latch that exact
receipt as committed before any later artifact, result-scope, post-yield, or context-teardown
validation. Every later ordinary failure remains
`result-file-publication-failed` and reports `artifact_mutation_performed: true`,
`result_file_publication_state: committed`, `retry_safe: false`, and the exact result-file
receipt. Do not let a late scope error erase or downgrade that committed evidence. A consumer may
supply either that complete creator result or the nested
`manifest_creation_receipt`; it may not self-bootstrap a receipt from the current manifest.
The creator command also holds its original zero-write artifact/result destination preflights
until all requested publication work completes. The preflight wrapper may add
`mutation_performed: false` only when its raw context fails before returning the first held
proof. A later teardown failure is failed revalidation of the selected object-identity,
access-policy, alias, or live-containment properties; it is not evidence that publication did
not occur. After the artifact payload latches its successful no-replace receipt, an
artifact-only teardown failure is `destination-install-uncertain` with
`artifact_publication_state: committed`, `mutation_performed: true`, `retry_safe: false`, and
the descriptor-bound artifact recovery locator. If the external result receipt was also
latched, the same teardown failure remains `result-file-publication-failed` with both the
artifact recovery identity and exact committed result-file receipt.
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

Normalize every public snapshot/stage path set once with lexical `abspath`
semantics from one captured CWD. Derive the artifact root, manifest, nested
store/database, external receipt, recovery output, and writeback inputs from
that absolute policy. Do not use `resolve()` or another symlink-following
canonicalizer. Relative API and CLI inputs must therefore share one absolute
command policy while component binding still rejects alias, symlink, and
replacement races.
Before consuming either a manifest or external receipt, scan the decoded JSON
text with fixed nesting and integer-digit limits, then parse with the same
bounded integer hook on every supported Python runtime. Map limit `ValueError`
and decoder `RecursionError` to `manifest-invalid` for manifests and
`manifest-creation-receipt-invalid` for external receipts; neither may escape
as `unexpected-error`.
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
descriptor stat/read, parent fsync, receipt construction, tree scan, public-path revalidation,
post-yield validation, or context-manager teardown. Return
`destination-install-uncertain`, `mutation_performed: true`,
`publication_state: uncertain`, and `retry_safe: false`. Attach one
`apple-notes-post-publication-failure/v1` locator containing the terminal phase, underlying machine
code/type, destination, and descriptor-bound destination evidence when available. Conservative
recovery-detail merging must OR `mutation_performed`, never turn false retry evidence true, and
never downgrade `uncertain` publication or incomplete cleanup. This includes raw `ENOENT`,
`EACCES`, `EIO`, and unexpected runtime exceptions. If a terminal receipt itself cannot be
completed, retain last-verified descriptor-bound parent/prepared-root evidence and mark the
sub-check inconclusive. Do not catch `BaseException`; `KeyboardInterrupt` and `SystemExit` retain
process-control semantics.
Set one monotonic commit latch as the first action after a successful no-replace rename returns.
When the rename syscall reports an error but descriptor-relative namespace evidence proves that
the exact prepared object occupies the destination, set the same latch before building any
recovery receipt. The enclosing post-publication guard and low-level publisher share that latch.
After the minimum namespace observations needed to prove a commit, no further terminal namespace
observation, durability check, tree/file receipt, or fallback evidence builder runs before the
latch. Later code may add descriptor evidence but must never clear the commit fact.

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

When `merge-db` receives the canonical copied-snapshot main-file layout, infer
and bind that snapshot root. Its default output must be an unpredictable
owner-private sibling outside the root, not a member created beside
`NoteStore.sqlite`. Before creating an explicit or default output, reject
requested/registered-canonical lexical containment in either direction, then
prove through held directory descriptors that the output ancestor neither is
nor resolves inside the snapshot root. Keep both bindings through publication
and terminal revalidation. Proved overlap is
`merge-output-inside-snapshot`; unavailable or contradictory containment
evidence is `merge-output-scope-inconclusive`. This protects exact snapshot
membership and the snapshot root's object identity; ordinary child-entry
metadata churn outside that protected tree is not a mismatch.

Immediately after `source_backup` creates a private standalone `.tmp-*` database, bind that leaf
relative to the already-held output-parent descriptor and compare its identity, SHA-256, size, and
access policy with the creation receipt. Keep the same bound descriptor open across the
creation-receipt comparison, second source revalidation, SQLite integrity check, terminal
prepared-file revalidation, and pre-publication durability step. A classified safety failure in
that interval
retains its original code; an ordinary runtime failure becomes `prepared-operation-failed` with
the original exception as its cause. Both outcomes retain the sensitive object, set
`retry_safe: false`, and attach a descriptor-bound prepared-file locator plus point-in-time
namespace observations. Receipt-mismatch evidence must distinguish the creation receipt from the
rebound descriptor and current namespace; never sign a replacement, in-place content mutation, or
access-policy drift as the created object. If rebinding itself fails, retain an explicitly unbound
creation-receipt locator with `cleanup_state: preserved-or-incomplete`. If retention evidence
construction fails, keep the original failure primary and emit fixed inconclusive
creation/descriptor/parent evidence. Do not delete by name when the leaf may have been replaced or
moved.

The `source_backup` contract must carry a final-public-name callback through
the standalone payload writer. Invoke it immediately before the actual
`.OUT.tmp-*` `O_EXCL` open, after any potentially long payload preparation,
and descriptor-relatively revalidate the held parent plus `OUT`, `OUT-wal`,
`OUT-shm`, and `OUT-journal`. This is the standalone zero-write linearization
point; a failure creates no temporary output and retains cleanup evidence as a
separate concern rather than inventing a created-file receipt.

Pre-publication failure handling protects deletion target identity by deleting nothing through a
mutable pathname. While the creation-time root and parent descriptors are still open, revalidate
the exact root relative to the held parent and scan a bounded sensitive-file inventory twice
without following child links. Enumerate lazily through held descriptors, stop
before metadata lookup for the 65th entry, and apply a 4 KiB aggregate raw-name
ceiling across the complete recursive pass; sort only the at-most-64 admitted
names. Preserve the complete partial tree and attach `cleanup_state: retained`,
`mutation_performed: true`, the verified root/parent identities, exact
namespace, and inventory to the original error. The mutation conclusion
overrides an earlier false claim because the helper-created partial may already
contain copied NoteStore bytes. If the root is missing, replaced, over the
inventory bounds, or cannot be revalidated, preserve the current namespace,
keep the original error primary, retain the same conservative mutation
conclusion, and attach a separate `cleanup_error_code` plus bounded recovery
locators. Access-policy changes remain distinct validation failures; mtime,
ctime, and directory link-count behavior are not deletion-identity signals.
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

For a required-quit snapshot, probe at preflight, as the final operation in the
before-rename callback, and immediately after no-replace publication before
success labeling, result-file publication, or return. A running/unknown
post-publication result invalidates writeback-grade use. While the original
publication parent and exact snapshot descriptor remain held, move that exact
object with a no-replace rename to an unpredictable hidden quarantine sibling.
Revalidate the parent, object identity, access policy, requested-destination
absence, quarantine identity, parent durability, and complete tree receipt.
Terminally prove the quarantine's descriptor-relative directory access policy
and public alias as well. Only after every one of those post-rename proofs
succeeds may the result return the original Notes-state code as primary with
`artifact_publication_state: quarantined`, `writeback_grade: false`, no
successful creation receipt, and the exact quarantine locator. If the exact
move is visible but any terminal proof fails, report
`artifact_publication_state: namespace-moved-unverified`,
`cleanup_state: inconclusive`, and the failed proof phase. Otherwise retain
committed-or-uncertain publication evidence. Classify every incomplete
quarantine sub-check separately as `snapshot-quarantine-inconclusive`; never
delete through a mutable path or label the requested destination successful.

Keep patch preparation separate from live replacement.
`stage-patch` and `preflight-writeback` are read-only with respect to the live container.

A writeback-grade backup must:

- use the exact `apple-notes-snapshot/v4` schema; a v3 snapshot is not
  writeback-grade and must fail closed rather than being inferred or upgraded;
- be captured with `--require-notes-quit`;
- retain its successful artifact-external manifest creation receipt;
- record that Notes was not running;
- still match its copied-file hashes;
- recover successfully with full SQLite integrity;
- bind the current live file set to the same source object identities, bytes, and access policies;
- carry an exact `apple-notes-live-source-binding/v1` receipt produced from the
  same held capture store as the copied files. The receipt binds the requested
  source root, terminal directory identity/access policy, complete ordered
  canonical component chain, the no-symlink/reparse policy, and either the
  complete registered Darwin alias receipt or explicit `null`. Directory
  timestamps, link count, and unrelated raw flags are evidence only and do not
  define the protected property.

A patch stage must contain only:

- `NoteStore.sqlite`;
- `patch-manifest.json`.

It must also retain its successful artifact-external manifest creation receipt. Preflight and
post-writeback verification require both the backup and stage receipts before consuming either
manifest.
Hold the staged database through SQLite integrity consumption. Its descriptor
byte capture and every identity, content, access-policy, or inconclusive
revalidation inside that boundary must use the patch-stage
`patch-file-*` / `patch-content-mismatch` taxonomy, not the prepared-output
publication taxonomy.

`preflight-writeback` and `verify-writeback` must hold the validated snapshot,
validated patch stage, and live source store together. Establish one joint
success linearization point while all three remain bound: revalidate both
artifacts, revalidate the live directory/component/alias binding and selected
file properties, complete the required comparison or recovery verification,
and prove Notes remains quit. Descriptor teardown after that point is
close-only. The receipt proves that point in time; it is not authorization for
a later write and cannot eliminate a same-UID mutation immediately afterward.

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
- live mode, owner, group, and Darwin access-controlling flag mask equal the
  baseline access policy;
- live WAL and SHM names are absent before Notes restarts;
- full SQLite integrity succeeds from an anonymous descriptor-backed verification image.

## Failure Classes

The helper emits stable error codes, including:

- `source-missing`, `source-missing-after-read`;
- `source-unreadable`, `source-revalidation-unreadable`;
- `source-revalidation-inconclusive`;
- `source-identity-mismatch`, `source-content-mismatch`;
- `source-access-policy-mismatch`;
- `store-file-set-mismatch`;
- `rollback-journal-present`;
- `directory-creation-identity-inconclusive`;
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
- `result-file-not-external`, `result-file-exists`;
- `result-file-scope-inconclusive`, `result-file-publication-failed`;
- `standalone-output-sidecar-present`;
- `standalone-output-sidecar-unreadable`;
- `standalone-output-sidecar-revalidation-inconclusive`;
- `destination-exists`, `destination-install-failed`;
- `destination-install-uncertain`;
- `recovery-output-inside-snapshot`, `recovery-output-scope-inconclusive`;
- `merge-output-inside-snapshot`, `merge-output-scope-inconclusive`;
- `notes-started-during-capture`, `snapshot-quarantine-inconclusive`;
- `post-writeback-identity-mismatch`, `post-writeback-file-set-mismatch`;
- `post-writeback-content-mismatch`, `post-writeback-access-policy-mismatch`.

Preserve the exact code in reports and automation.
Do not reinterpret a safety error as an empty result.

## Non-Guarantees

The helper does not:

- grant TCC or Full Disk Access;
- prove Notes remained quit continuously between process-state probes; required-quit capture
  narrows the unobserved windows with preflight, final pre-rename, and immediate post-publication
  checks and quarantines an exact published object when the final probe fails;
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
