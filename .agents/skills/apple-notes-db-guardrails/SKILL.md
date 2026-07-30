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
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- copy-db \
  --dest /tmp/<task-snapshot> \
  --result-file /tmp/<task-snapshot>.creation-result.json
```

Before creating even the destination parent, every write-producing command (`copy-db`, `merge-db`,
`recover-snapshot`, and `stage-patch`) enters the same live-container guard. It normalizes the
requested path with case-folded NFD components. Before binding any component or calling the
directory creator, it expands the destination and both Apple Notes live containers into their
distinct requested and exact registry-canonical alias forms and rejects every cross-form
ancestor/descendant overlap. This catches both `/tmp/live` against
`/private/tmp/live/...` and the reverse while the live leaf is still absent. It then binds the
nearest existing destination ancestor plus both live containers. Every absolute path component is
opened no-follow relative to its already-held parent; an initially absent live container remains
anchored to its nearest existing component and missing suffix. The same component chain authorizes
parent creation and remains held for creator receipts, publication, and terminal revalidation. It
rejects a normalized lexical overlap or a descriptor-ancestor identity match. It also rejects
`NoteStore.sqlite`, `-wal`, `-shm`, and `-journal` as path components anywhere in a destination,
even when that sidecar is currently absent. The guard runs before the first mkdir, file creation,
rename, partial, backup, receipt, or helper output.
The `NoteStorePaths` API object and CLI adapter freeze both live-container
inputs to lexical absolute paths using one captured working directory before
this preflight begins. A later CWD change cannot retarget either held-container
proof, source read, manifest `source_root`, or writeback equality check.
At the `merge-db` and `stage-patch` API/CLI boundaries, capture that working
directory once and freeze the source plus every output, including a stage
`--result-file`, before any destination preflight. Manifests and result payloads
use only those frozen source/output paths; a later CWD change cannot select a
different edited database for staging or writeback.
Apply the same one-shot rule to every public multi-path snapshot/stage
boundary. Freeze a copy destination before the Notes-state probe; freeze each
artifact root and its external receipt together; freeze a recovery artifact,
receipt, standalone output, and live-container pair together; and freeze the
backup artifact, patch stage, and both external receipts before writeback
preflight or verification. CLI dispatch captures its command CWD before parser
or callback execution and passes that exact snapshot through all internal
helpers. No helper may independently re-read CWD for one member of these
related path sets.

Missing destination-parent components and private partial directories are never created directly
at their target names. A trusted platform or supervisor creator must allocate an unpredictable
owner-private staging directory under the held parent and return the already-open descriptor plus
an `apple-notes-identity-bound-directory-creation/v1` attestation that binds the actual created
object, parent, access policy, and exclusive namespace handoff. POSIX/Darwin `mkdir`, `mkdirat`,
`mkdtemp`, and `mkdtempat_np` return no descriptor, so a later no-follow `open` is not creation
proof and is never an implicit fallback. The packaged production launcher creates an inherited,
already-connected `AF_UNIX`/`SOCK_DGRAM` channel, forks the bundled supervisor service, and starts
the DB helper with `--directory-creator-fd`. Current macOS and Linux public APIs expose no atomic
directory-create-and-return-FD primitive, so the bundled service validates the request and returns
the exact closed `unavailable-before-create` capability receipt without calling `mkdir`, `open`, or
sending a directory descriptor through `SCM_RIGHTS`. The helper accepts that no-mutation result
only when the response has the exact schema, nonce, null basename/proof, zero descriptors, and
canonical typed details; every near-match remains a conservative possible-mutation transport
failure. A caller may still supply an inherited channel for a genuinely stronger platform or
privileged authority that returns the actual created-object FD and normal creation attestation.
The launcher blocks termination signals before either child starts, atomically records the
`posix_spawn` worker PID under that mask, relocates the child channel if its source FD collides with
the preferred target, and temporarily normalizes `SIGCHLD` to a waitable default before either
child exists. The worker receives a default `SIGCHLD`, while the launcher keeps it blocked until
both owned children are reaped and then restores the caller's exact disposition/mask. An unexpected
`ECHILD` is a conservative worker failure, never an exception that can skip cleanup. The launcher
also restores the original child masks and latches the first parent signal without raising. It
ignores later termination signals until the worker and service have both been killed, drained, and
reaped, consumes only one bounded pending-signal snapshot, then restores the original handlers/mask
and re-delivers the first signal.
The helper sends the held parent descriptor and a request nonce with `SCM_RIGHTS`. A `created`
response must carry exactly one directory descriptor plus the matching attestation; the packaged
capability refusal must carry none. It never reconnects by socket pathname or accepts a direct
`mkdir`-then-`open` of the returned name. Without a stronger creator, creation fails after the
packaged capability request but before any filesystem mutation with
`directory-creation-identity-inconclusive`.
If that creator fails after entering the creation boundary, it must raise the packaged structured
create-then-fail exception and transfer the staging basename, already-open descriptor,
creation-time stat, proof, and recovery details to the helper. The helper records the handoff as
`creation-identity-inconclusive`, closes the transferred descriptor only after bounded evidence
capture, retains the namespace, and never retries or deletes it by name. A creator exception
without that structure is treated as possibly post-mutation with inconclusive cleanup, never as
`mutation_performed: false`. A successful call that returns `None`, an unexpected object, missing
fields, or wrong field types is inside the same possible-mutation boundary: the helper safely
extracts any recoverable basename/FD, captures conservative evidence, closes transferred FDs, and
unions malformed-result, provider-failure, and install locators with worst-case cleanup.
Supervisor `details` cross a closed, bounded schema before conservative merging; malformed nested
locator containers are rejected and recorded rather than converted with generic `dict(...)`.
Provider response schemas and basenames, proof keys/strings, documented details strings, unknown
details field names, and recovery-locator keys/strings must contain only Unicode scalar values and
encode with strict UTF-8; lone surrogates are rejected without entering recovery output. A
provider `publication_state` remains only an unverified claim inside the provider-scoped
normalization evidence and never merges into the top-level recovery state. Without local namespace
proof, a post-request transport failure reports top-level `publication_state: uncertain`.
CLI JSON uses ASCII escapes defensively so even an unexpected surrogate cannot make strict UTF-8
stdout fail before structured recovery is emitted.
Transport evidence is completed before the first received FD leaves the cleanup-owned list. If
normalization, evidence construction, or merging fails, every received FD is closed first and the
helper emits a fixed `mutation_performed: true`, `retry_safe: false`, inconclusive-cleanup
transport locator without retrying the failing provider structure.
After validating the returned descriptor/name pair, the helper installs that exact object with
atomic no-replace rename and revalidates the target around the carried scope checks. Replacement
or access-policy drift fails closed with a structured retained-object locator; unproved handoff
evidence is labeled `creation-identity-inconclusive`, never
`transaction-created-object-identity`. Metadata-only transitions remain benign. A platform
without atomic directory no-replace support is unsupported.
Immediately after a successful component install, the helper latches the exact
`creation_install_receipt` before another scope check. Every later parent-chain revalidation,
consumer failure, post-yield check, and descriptor teardown merges all already installed component
receipts with `mutation_performed: true` and `retry_safe: false`; a caller must never infer
zero mutation merely because the parent context did not reach its first yield.

On macOS, only the exact registry entries `/tmp -> /private/tmp`, `/var -> /private/var`, and
`/etc -> /private/etc` may bridge a root symlink. The helper binds the alias parent, alias entry and
target text, plus the canonical target and its parent, then performs writes through canonical held
descriptors while revalidating both namespaces. An arbitrary symlink, a case-folded spelling, an
NFC/NFD variant, a retarget, or an alias replacement fails closed before mutation. Live-container,
trusted-alias, and destination-ancestor identity and access policy are revalidated before the first
destination component creation and remain bound through publication. The exact alias binding
object is propagated into every derived directory/file
binding, a same-alias external receipt parent, creator-result scope evidence, and terminal
public-parent rebind; later boundaries must reuse it rather than authorizing a new alias or
falling back to the public pathname. When an artifact and its external receipt/result use
different registry entries, or only one uses a registered alias, do not carry the other scope's
alias object; independently bind and revalidate each exact root scope. Unrelated child-entry churn
is not a content mutation. Treat
`snapshot-destination-scope-inconclusive` as fail-closed, distinct from a proved
`snapshot-destination-inside-live-container` overlap.
Successful creator output records the alias-aware
`manifest_creation_destination_scope`, `terminal_destination_scope`, and
`descriptor_bound_destination` receipts.

For `copy-db` and `stage-patch`, artifact and `--result-file` destinations use
two explicit phases. The zero-write phase runs the Notes gate where applicable,
rejects an existing or live-overlapping artifact, proves normalized
requested/canonical artifact-result separation, and independently holds each
destination's live-container, trusted-alias, nearest-existing-ancestor, missing
suffix, and absent-leaf evidence. It revalidates the artifact proof after the
result proof completes. No identity-bound directory creator or `mkdir` may run
until both proofs succeed. The commit phase creates the artifact parent first
and does not create a missing result parent until artifact publication
succeeds. If artifact creation also creates a parent-prefix needed by the
result, the result phase may advance across only the exact component identities
and access policies carried by the artifact's no-replace creator receipts;
every other appeared component is a scope failure. Any error after a creator
boundary conservatively retains `mutation_performed: true`; an artifact-created
result transaction also retains `artifact_mutation_performed: true`.

The Notes-running gate executes only `/usr/bin/pgrep -x Notes` with a minimal fixed environment,
a hard deadline, and process-group cleanup. Only exit `0` plus one or more decimal PIDs means
running; only exit `1` with empty stdout/stderr means quit. Timeout, exec failure, diagnostics,
malformed output, or any other result is `notes-state-unknown` and never authorizes a writeback
preflight or verification.

For `copy-db --require-notes-quit`, one successful preflight probe is not
enough. Probe again as the final operation of the before-publication rename
callback, after all source and prepared-tree validation, and immediately after
the no-replace publication returns before success labeling or result-file
publication. If Notes is running or its state is unknown at the post-publication
probe, move the exact descriptor-held published snapshot with a no-replace
rename to an unpredictable owner-private hidden sibling under the same held
parent. Revalidate parent/object identity, access policy, namespace absence,
parent durability, the complete tree, and the terminal public alias before
reporting the quarantine as verified and retained. The command must fail with
`writeback_grade: false`, no successful creation receipt, and exact
primary/quarantine recovery evidence. If the namespace move is visible but any
of those terminal proofs fails, report
`artifact_publication_state: namespace-moved-unverified` with inconclusive
cleanup rather than `quarantined`; otherwise preserve a conservative
committed-or-uncertain recovery receipt. Never leave or describe the requested
destination as a successful writeback-grade backup.

Treat a snapshot captured while Notes is running as tentative.
Do not use it for absence claims, exact counts, patch planning, or writeback.

For critical analysis or a writeback baseline, quit Notes first and run:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- copy-db \
  --dest /tmp/<task-backup> \
  --require-notes-quit \
  --result-file /tmp/<task-backup>.creation-result.json
```

Keep `snapshot-manifest.json` with the copied file set, and separately preserve the successful
creation-result JSON outside the snapshot. Before artifact creation, `--result-file` only binds
and retains the external destination's nearest existing ancestor, missing suffix, live-container
scope, trusted alias, containment proof, and absent leaf; it does not create a missing parent.
After artifact publication succeeds, it commits that held parent scope, rejects pre-existing
regular files and symlinks, creates an unpredictable descriptor-relative temporary regular file
with `O_NOFOLLOW|O_CREAT|O_EXCL`, enforces the current effective owner/group and mode `0600` before
writing, fsyncs the file, and publishes it with an atomic no-replace rename plus held-parent fsync.
It revalidates identity, content, and the complete access policy before and after publication. Its
`manifest_creation_receipt` anchors the exact creation-time manifest SHA-256, size, identity, and
access policy. Before writing the result, the helper binds the reopened artifact's parent, root,
exact nested directory memberships, and every file's identity/access policy/SHA-256/size to the
successful creator payload's `descriptor_bound_destination` tree receipt; the manifest entry must
also equal `manifest_creation_receipt`. It holds those descriptors through result publication and
revalidates the full creation receipt immediately after commit, so a post-publication pre-bind
replacement or in-place mutation cannot publish stale creator evidence. Never regenerate a
receipt from a current artifact. Only a successful creator result is admissible; a partial or
error result is not. Once result-file publication returns its terminal receipt, that receipt is a
monotonic commit latch: any later result-scope teardown or post-yield revalidation failure remains
`result-file-publication-failed` with
`artifact_mutation_performed: true`, `result_file_publication_state: committed`,
`retry_safe: false`, the artifact's descriptor-bound recovery identity, and the exact
result-file receipt. The original zero-write destination preflights remain held through
artifact and result publication. If one of those original contexts fails while closing,
only a failure before its first held proof may claim `mutation_performed: false`; an
artifact-only committed transaction instead returns `destination-install-uncertain` with
`artifact_publication_state: committed`, `mutation_performed: true`, `retry_safe: false`,
and the descriptor-bound artifact receipt.
For a direct public API call that was not supplied a held creator preflight, the helper creates
the same zero-write destination proof and rechecks the requested leaf through its descriptor-bound
parent immediately before parent commit or partial creation. A destination that appears after the
initial lexical check therefore fails with `destination-exists` before the helper creates a
retained partial.
Snapshot publication is atomic and no-replace on supported macOS/Linux filesystems.
The live NoteStore is one descriptor transaction: bind the complete group-container path once,
one no-follow component at a time, then perform main/WAL/SHM/rollback-journal discovery, every
regular-file open, hashing/copying, membership checks, and final protected-property revalidation
only through the held group-container `dir_fd`. Do not restart discovery or open a source from a
full pathname. Every existing untrusted regular-file leaf open combines `O_NOFOLLOW` with
`O_NONBLOCK`; the same descriptor is then checked as regular and identity-bound. A regular-file
name swapped to a FIFO or device between the pre-open stat and open therefore cannot block before
the type mismatch is rejected. Before hashing, the helper also requires identical object identity
and complete access policy across the pre-open descriptor-relative path stat, opened descriptor
stat, and immediate post-open descriptor-relative path stat; it never adopts a policy first
observed after open as a new baseline.
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
Only after every bound live-source file completes that terminal double-hash check, the helper
revalidates the held source-directory chain, rescans the reserved main/WAL/SHM/rollback-journal
names through the held parent, compares them with the binding-time baseline, and revalidates the
directory chain again. A persistent late WAL or rollback journal and a persistent parent
replacement therefore fail closed. Transient unrelated child-entry churn remains benign when
directory identity, access policy, reserved membership, and bound-file content stay unchanged.
The access probe closes each successfully opened file descriptor, then performs one final
source-aware held-parent revalidation inside that file's result boundary before marking it
readable. Parent disappearance, unreadability, or another revalidation failure remains a
per-file source error instead of escaping through the generic prepared-directory taxonomy.
The live-source directory lifecycle also owns the final exit of its underlying generic
component-chain context. A generic teardown failure after the source-specific terminal check is
translated from its original cause: missing, unreadable, other stat failure, proved identity
replacement, and proved access-policy drift retain their corresponding `source-*` classes for
fingerprint, copy, and merge callers.
On an ordinary pre-publication failure, the helper
preserves the partial tree and attaches a creation-receipt-matched namespace locator plus a bounded
no-follow sensitive-file inventory to the original error. If the root is replaced or inventory is
inconclusive, the original error remains primary and reports the separate receipt failure.
Every retained or possibly retained partial receipt sets `mutation_performed: true`, overriding an
earlier false claim because the helper already created the partial namespace and may have copied
sensitive NoteStore bytes into it.
Each retained-partial pass lazily enumerates through held directory descriptors,
stops on the 65th entry before reading its metadata, and enforces a 4 KiB
aggregate raw-name ceiling across the complete recursive pass. It collects and
sorts only the already bounded names.
An individual file writer also retains its failed output: it never follows a separate `stat` with
an `unlink`, because the namespace leaf could be replaced between those syscalls. The error carries
the held parent/file descriptor receipt, point-in-time namespace observations, `cleanup_state:
retained`, and `retry_safe: false`.
For standalone recovery, bind the private `.tmp-*` database through the already-held output
parent immediately after `source_backup` returns and match it to the creation receipt before the
second source revalidation. Keep that descriptor open across creation-receipt comparison, the
second source revalidation, SQLite integrity, terminal file revalidation, and pre-publication
`fsync`. Any failure in that interval uses one pre-publication failure path: preserve the original
safety code, wrap an otherwise unclassified runtime failure as `prepared-operation-failed`, retain
the sensitive object without name-based deletion, and attach its descriptor-bound recovery
locator plus point-in-time namespace observations. If the writer-created leaf cannot be rebound,
retain its creation receipt and an explicitly unbound point-in-time namespace locator instead of
claiming descriptor authority. If recovery-evidence construction itself fails, keep the original
error primary and fall back to fixed inconclusive creation/descriptor/parent evidence.
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
  --snapshot-dir /tmp/<task-backup> \
  --manifest-creation-receipt-file \
    /tmp/<task-backup>.creation-result.json
```

Snapshot and stage API/CLI inputs are normalized once to absolute lexical paths without resolving
symlinks. Root, manifest, nested-store/database, and external-receipt paths are then derived from
that one policy object, so relative inputs do not mix relative children with an absolute bound
root. Component-wise no-follow binding still rejects aliases, replacement, and symlink traversal.

Validation requires the caller-preserved artifact-external receipt before parsing the v3
manifest. The validator binds the artifact root once before loading that receipt. Receipt
externality proof and loading, root membership scans, manifest binding, nested-store binding,
database-file binding, recovery-payload construction, SQLite integrity checking, and terminal scans all
reuse that exact root descriptor or child descriptors opened relative to it; no later artifact
consumer reopens the root pathname. It first compares the held manifest's identity, SHA-256, size,
and access policy with the external receipt, then consumes the manifest's creation-time
root/store/file receipts and holds the manifest and every declared database-file descriptor
through recovery-payload construction, SQLite integrity checking, standalone backup, and terminal
revalidation. No named recovery-clone directory is created. Object replacement, byte mutation,
and access-policy change have distinct failure codes; timestamp-only changes do not fail when the
protected properties remain stable.
Manifest and external-receipt JSON parsing is bounded independently of the
file-size ceiling: nesting and integer digits have fixed limits before any
untrusted structure is consumed. Limit failures and decoder recursion map to
`manifest-invalid` and `manifest-creation-receipt-invalid`, respectively,
without runtime-version-dependent exceptions.
Snapshot and patch-stage directory scans preserve their caller-specific missing, identity,
access-policy, membership, and inconclusive codes even when the lower descriptor scanner detects
the failure midway through a pass.
Every prepared/artifact directory scan receives its small expected raw-name
namespace first. It rejects an unexpected entry before its metadata is read,
caps each pass at 64 entries and 4 KiB of aggregate raw name bytes, rejects
raw/decoded-name collisions, and compares both raw-name/type and decoded-name/type
maps across the two scans.

## Recover For Analysis

Prefer `recover-snapshot` when a manifest is available:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- recover-snapshot \
  --snapshot-dir /tmp/<task-snapshot> \
  --out /tmp/<task-snapshot>-analysis.sqlite \
  --manifest-creation-receipt-file \
    /tmp/<task-snapshot>.creation-result.json
```

`recover-snapshot` consumes the manifest, store directory, main database, and declared sidecars
held by that exact validation pass. It never reopens the mutable snapshot paths after validation,
and it creates no named recovery-clone or `TemporaryDirectory`. Its recovery result carries the
snapshot manifest and database-file identity, SHA-256, size, and access-policy receipts from that
validation context rather than replacing them with only the SQLite integrity result.
Before recovery can build an in-memory payload or anonymous recovered-image descriptor, it binds
the snapshot, proves output/snapshot separation, and acquires the live-safe destination guard. A
direct group/app-container output, reserved store-name component, or symlink alias into a live
container therefore fails before recovery payload construction, SQLite backup, or any standalone
writer can run. The snapshot and destination guards remain held through publication and terminal
validation.
The output must be a sibling of, never a member of, the snapshot tree. The helper rejects
object-identity overlap before it can create an output parent: it binds the snapshot root and the
output's nearest existing ancestor, then traverses `..` through held descriptors and compares
directory device/inode identity. This catches case-insensitive macOS spellings and symlink aliases
without trusting path string case. Missing safe output-parent components are created and rebound
relative to that proved ancestor, preserving the snapshot's exact root member set for later
validation.
The recovery step retains the already-bound snapshot store directory, main database, and declared
WAL/SHM descriptors, then revalidates object identity, content, access policy, manifest receipts,
and exact name/type membership before and after each recovery boundary. A replacement or injected
entry between validation, sidecar inspection, payload construction, SQLite integrity, and backup
fails closed. Recovery applies the checksum-valid committed WAL prefix to the held main-database
bytes and gives SQLite only bytes reread from one anonymous descriptor-backed recovered image.
SQLite never reopens the mutable main, WAL, SHM, directory pathname, `/dev/fd`, or
`/proc/self/fd`. The helper copies the receipt-matched descriptor bytes into a native
SQLite-owned buffer, deserializes it read-only, and revalidates descriptor identity, content, and
access policy plus the buffer digest before and after integrity queries and backup.
Linux `TemporaryFile` may use `O_TMPFILE`, whose anonymous object is not required to survive
SQLite VFS full-path processing. The helper therefore never treats a successful Python
descriptor reopen probe as proof that SQLite can or should reopen that pseudo-path. For a
recovered image with an exact SQLite header, read/write versions `1/1` are preserved and only the
exact WAL pair `2/2` is normalized to rollback mode after the committed WAL prefix has been
applied. Mixed or invalid pairs fail before deserialization. The accepted bytes are written to and
receipted from the anonymous descriptor before SQLite consumes them.
Connection teardown precedes buffer release. Every ordinary native runtime or `ctypes` failure is
classified under the calling SQLite error code and carries structured `sqlite_input_cleanup`
evidence. If native close cannot be proved, the helper retains the buffer instead of freeing memory
SQLite may still reference; ordinary descriptor cleanup remains anchored to the still-held
temporary file object. Native backup cleanup likewise records `sqlite_backup_cleanup` and
independently attempts every still-safe backup-finish, serialized-buffer-free, and destination-close
step without retrying an ownership-ambiguous release. A `sqlite3_exec` row callback captures its
first `BaseException` inside the ctypes boundary. It classifies and latches an ordinary callback
failure before terminal buffer and descriptor-binding revalidation; if either also fails, the
revalidation remains primary and `sqlite_input_secondary_failure` retains the callback's nested
`sqlite_callback_failure`. Process-control exceptions retain their original semantics, run safe
input cleanup first, and are never translated into a safety error.
Initial discovery also detects `NoteStore.sqlite-journal` without following links. Any present
rollback journal is descriptor-bound and then rejected as `rollback-journal-present`; if it cannot
be bound as one stable regular file, the same reason code is returned as inconclusive. Recovery
never guesses whether SQLite had finished rollback or whether journal pages remain authoritative.
The native SQLite backup API writes first to an in-memory database; serialized database bytes are
then written directly to the exclusively created output descriptor. Full integrity checking opens
the prepared standalone file through that same held descriptor. Immediately after exclusive
creation and before truncating or writing sensitive bytes, the standalone writer corrects the
descriptor to the effective UID/GID and mode `0600`, then binds its Darwin
access-controlling flag mask, object identity, and descriptor-relative no-follow
name. Immutable, append-only, Data Vault, restricted, and no-unlink bits are
access policy; hidden, no-dump, compression, tracking, firmlink, and File
Provider/dataless transitions are retained as metadata. It also pre-binds the
serialized payload's expected SHA-256 and byte length. A post-write boundary
must still match that creation-time policy; the helper accepts a creation
receipt only after two consecutive same-descriptor readbacks plus size,
access-policy, and descriptor-relative pathname identity/access checks all match
the pre-bound expectation.
After the main file is published, fsynced, terminally rehashed, and path-verified, the helper keeps
its parent directory descriptor open and observes the output's `-wal`, `-shm`, and `-journal`
names twice without following links. It then rebinds the public parent pathname, proves that it is
still the held parent object with the same access policy, and revalidates the public main name's
identity, SHA-256, size, and access policy before success. Any present sidecar entry of any type,
permission failure, unverifiable observation, persistent parent replacement, or public-main
replacement makes the already-published result `destination-install-uncertain`. Preserve the main
and observed names, do not retry or delete, quiesce the writer, and rebind for inspection.
Once a sidecar-free standalone image has been validated and bound, later backup copies only that
held image. A newly injected adjacent WAL is neither discovered nor trusted.
An ephemeral namespace replace-and-restore during SQLite backup may not be reported, but it cannot
redirect the bytes SQLite consumes. Persistent missing, replacement, content, access-policy, or
directory-membership changes fail before output publication. This does not make a live
cross-file snapshot transactional; authoritative recovery still requires Notes to remain quit.

Use `merge-db` only for a copied database file without a snapshot manifest:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- merge-db \
  --src /tmp/<copy>/group.com.apple.notes/NoteStore.sqlite
```

When that source has the canonical copied-snapshot layout, omitting `--out`
creates a randomized owner-private standalone database in the snapshot
parent, never inside the snapshot tree. An explicit output must also be
external. Before output mutation, compare requested and registry-canonical
forms in both ancestor directions, bind the snapshot root and output ancestor
through descriptors, and reject a symlink/case/NFD/descriptor alias into or
around the snapshot as `merge-output-inside-snapshot`; incomplete containment
proof is `merge-output-scope-inconclusive`. Hold and revalidate the snapshot
root and output-parent separation through publication so the source snapshot
remains structurally valid.

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
For `recover-snapshot`, the output-parent, ancestor-exclusion, and held snapshot checks remain one
transaction after the standalone main file's public-path receipt completes. Any later parent,
ancestor, manifest, or snapshot-file identity/content/access-policy failure is still
`destination-install-uncertain` with `publication_state: uncertain`, `retry_safe: false`, and the
descriptor-bound destination receipt; it must not escape as a pre-publication prepared/snapshot
error.
After any no-replace publication has committed, every later ordinary exception from descriptor
stat/read, parent fsync, receipt construction, sidecar checks, public-path validation, or terminal
revalidation—including `ENOENT`, `EACCES`, `EIO`, and an unexpected runtime exception—has that
same uncertain, non-retryable result. Context-manager teardown and post-yield revalidation are
included. The unified `apple-notes-post-publication-failure/v1` recovery receipt records
`mutation_performed: true`, `publication_state: uncertain`, `retry_safe: false`, the phase,
descriptor-bound destination evidence when available, and the underlying machine code/type.
Recovery evidence remains descriptor-bound and records an inconclusive sub-check when a terminal
receipt cannot be completed. Process-control exceptions such as `KeyboardInterrupt` and
`SystemExit` are not translated.
The commit fact is latched monotonically as the first action after a no-replace rename returns
success, and likewise before any recovery-evidence construction when an error path proves that the
exact prepared object occupies the destination. Callers pass the same latch into the low-level
file or directory publisher; descriptor receipts are added only afterward. Evidence construction
cannot therefore fail through a still-uncommitted outer guard.

The packaged helper remains compatible with Python 3.9. Do not use newer runtime-only call
arguments, such as `zip(..., strict=True)`, without adding a consistent minimum-version gate.
The legacy-compatible `scripts/apple_notes_helper.py` module re-exports its
established public names, including `notes_is_running` and `emit_json`, without
starting a process or mutating the filesystem at import time. When executed,
its `copy-db`, `merge-db`, `recover-snapshot`, and `stage-patch` commands route
through the packaged directory-creator supervisor unless the caller supplied
an explicit `--directory-creator-fd`; read-only commands and explicit-FD
commands dispatch directly to the DB helper. The packaged route is a
pre-creation capability gate and currently fails closed when directory creation
is required; it is not itself a creation authority.

## Stage And Preflight A Patch

Prepare edits only on a copied or recovered database.
Normalize the edited database into a new patch stage:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_directory_supervisor.py" \
  --helper "$SKILL_DIR/scripts/apple_notes_db.py" -- stage-patch \
  --src /tmp/<edited>/NoteStore-edited.sqlite \
  --dest /tmp/<task-patch-stage> \
  --result-file /tmp/<task-patch-stage>.creation-result.json
```

Require the stage to contain only `NoteStore.sqlite` and `patch-manifest.json`.
Validation examines every no-follow directory entry and rejects extra directories, FIFOs, and
symlinks as well as extra regular files. The exact expected namespace is
checked before per-entry `stat`; both scans are bounded to 64 entries and
4 KiB of aggregate raw filename bytes.
Validate a stage independently when needed:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" validate-patch-stage \
  --stage-dir /tmp/<task-patch-stage> \
  --manifest-creation-receipt-file \
    /tmp/<task-patch-stage>.creation-result.json
```

The stage database remains bound through SQLite integrity consumption. Descriptor byte capture and
every file revalidation inside that integrity boundary use the patch-stage
`patch-file-*` / `patch-content-mismatch` taxonomy rather than prepared-output publication codes.

While Notes remains quit, bind the live store, fresh backup, and stage:

```bash
python3 "$SKILL_DIR/scripts/apple_notes_db.py" preflight-writeback \
  --backup-dir /tmp/<task-backup> \
  --stage-dir /tmp/<task-patch-stage> \
  --backup-manifest-creation-receipt-file \
    /tmp/<task-backup>.creation-result.json \
  --stage-manifest-creation-receipt-file \
    /tmp/<task-patch-stage>.creation-result.json
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
  --stage-dir /tmp/<task-patch-stage> \
  --backup-manifest-creation-receipt-file \
    /tmp/<task-backup>.creation-result.json \
  --stage-manifest-creation-receipt-file \
    /tmp/<task-patch-stage>.creation-result.json
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
- where the external snapshot/stage creation-result receipts were preserved;
- that preflight and verification do not make multi-file writeback atomic.

The external receipt is an anchor, not a signature or MAC. It detects artifact tampering only
while the caller preserves that receipt independently. If the same actor can rewrite both the
artifact and receipt file, the helper cannot establish creation-time authenticity.
