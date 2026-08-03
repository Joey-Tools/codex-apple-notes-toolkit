# Codex Apple Notes Toolkit

Generic Apple Notes guardrails and read-only database inspection helpers.

The canonical database workflow lives in
`.agents/skills/apple-notes-db-guardrails/`. Its packaged helper captures stable
SQLite/WAL/SHM snapshots, rejects descriptor-bound rollback journals before
capture, validates SQLite recovery, stages sidecar-free patches, publishes
snapshot/stage directories without replacing existing paths, and verifies
explicit writeback boundaries. SHM commit evidence requires checksum-valid,
identical native-order duplicate headers bound to the exact physical WAL commit
frame. Standalone recovery applies committed WAL frames
from descriptor-bound inputs before SQLite consumes a native read-only
deserialization buffer copied and revalidated from the same anonymous
descriptor. It never reopens `/dev/fd`, `/proc/self/fd`, or a mutable database
pathname, including when Linux `TemporaryFile` uses `O_TMPFILE`.
Only exact SQLite header version pairs are accepted: `1/1` remains unchanged and
`2/2` is normalized to `1/1`; mixed or invalid pairs fail closed. Native
deserialize and backup failures carry structured cleanup evidence, with
connection close preceding buffer free and independent backup cleanup steps
aggregated without unsafe release retries. Snapshot files,
the nested store, and the snapshot root are fsynced bottom-up before
publication. Publication uses held parent
descriptors for rename, fsync, and terminal revalidation; retained sensitive
partials and uncertain standalone destinations receive precise recovery
locators. Every output command rejects case/NFD, ancestor/descendant, and
descriptor-resolved overlap with either live Notes container before its first
write. Existing destination and live-container paths are bound one no-follow
component at a time; initially absent live containers retain their nearest
existing ancestor and missing suffix through creation and terminal checks.
Missing destination components and private partials are first created at
randomized owner-private staging names through a supervisor that returns a
continuously held object descriptor and a v2 proof naming the creation method
and threat model instead of claiming universal namespace exclusion.
The packaged launcher creates an inherited, already-connected
`AF_UNIX`/`SOCK_DGRAM` supervisor channel and starts the DB helper with
`--directory-creator-fd`. The packaged service uses a CSPRNG staging name,
descriptor-relative `mkdir`, immediate no-follow directory open, and repeated
FD/name/parent identity and access-policy validation before returning the FD.
This makes snapshot/stage usable under an explicitly cooperative same-UID
model; it does not defend against a hostile same-UID debugger or namespace
racer. The shell wrapper
and the legacy-compatible `scripts/apple_notes_helper.py`
entrypoint select this production launcher automatically for write-producing
commands; callers may still provide a stronger inherited supervisor channel.
Once Python has begun executing the compatibility wrapper, it no-follow /
nonblocking captures the fixed supervisor source under the same regular-file,
identity, access-policy, two-read, and 2-MiB constraints used for helper
source. It compile-executes those captured supervisor bytes directly, without
`SourceFileLoader` or source-tree bytecode, and re-exports only that module's
single captured helper instance. Write routing calls the same module's
`run_supervised`, so the compatibility API, parent/service protocol, and
worker all share its exact `HELPER_CAPTURE` / `HELPER`.
The launcher blocks and latches termination signals before child creation.
Before either child exists, the captured supervisor module has captured the
fixed packaged helper through a
no-follow/nonblocking regular-file descriptor, checks stable identity/access
policy and a 2-MiB ceiling, and requires two identical complete reads.
Arbitrary `--helper` paths are rejected before capture or execution. The
supervisor module and worker consume this same captured byte sequence. Its
CPython fork/exec launch uses child-side `close_fds=True` with the exact
supervisor channel and a launch-only anonymous source-pipe reader in
`pass_fds`, so a descriptor opened concurrently in the parent cannot enter the
worker after a stale parent inventory. A small fixed bootstrap receives a
length/SHA-256-bound frame under a hard deadline, rejects truncation and
trailing bytes, closes the source FD, restores the selected child signal
defaults/mask, and compiles the captured source in the same new session. The
recorded pathname is display metadata only; neither helper nor supervisor
pathname is reopened. The launcher normalizes inherited
`SIGCHLD=SIG_IGN` while it owns raw-waitpid children and keeps later signals
from interrupting bounded worker/service reap. An unexpected `ECHILD` fails
conservatively without bypassing cleanup or signaling a possibly reused PID.
It consumes one pending-signal snapshot before restoring and re-delivering
the first signal.
These capture guarantees begin only after the compatibility wrapper's own
source is already executing. They neither authenticate nor revalidate that
already-running wrapper object nor defend process memory against a malicious
same-UID process with debugging or `ptrace` access.
It transfers the held parent FD with `SCM_RIGHTS`; the packaged or stronger
external authority returns the actual opened directory FD plus a request-bound
attestation. A creator may claim `unavailable-before-create` only in the exact
typed closed form with no basename, proof, descriptor, or mutation. Malformed
near-matches remain conservative possible-mutation failures. The transport
never reconnects by socket path.
A held object is installed at the target name with atomic no-replace rename.
Identity and access policy are revalidated around carried scope checks; failed
installs retain structured evidence instead of using a racy name-based
directory cleanup. A trusted creator that fails after creation transfers the
created name, descriptor, creation stat, proof, and recovery details through a
structured exception. A normal return of `None`, missing fields, or wrong
field types is also treated as possibly post-mutation: recoverable FDs are
captured and closed, cleanup stays worst-case, and recovery locators are
unioned. Unstructured creator failures are never treated as retry-safe.
Exact Darwin root aliases such as `/tmp -> /private/tmp` are
registry-bound and continuously revalidated through the same carried alias
object across receipt loading, creator results, publication, and terminal
public-path checks; different registered roots and non-alias paths are bound
independently rather than borrowing another scope's alias authorization.
Arbitrary symlinks fail closed. Live NoteStore discovery,
open, hashing, membership checks, and terminal revalidation share one complete
held no-follow group-container component chain. Every existing untrusted
regular-file leaf is opened with both `O_NOFOLLOW` and `O_NONBLOCK`, then
descriptor-checked as regular, so a stat/open FIFO or device replacement
cannot block before type and identity rejection. The helper also requires the
pre-open path, opened descriptor, and immediate post-open path to agree on
identity and access policy before hashing. Snapshot recovery acquires
its output/live-container guard before validation and then consumes the held
snapshot store directly; recovery uses in-memory bytes and anonymous
temporary file descriptors, not named temporary or recovery-clone
directories. Its private standalone `.tmp-*` database is descriptor-bound and
matched to its creation receipt before the second source revalidation; every
pre-publication failure retains structured cleanup and recovery evidence.
Snapshot v4 also records an exact live-source binding from that same held
capture: the requested root, terminal directory identity/access policy,
complete canonical component chain, no-symlink policy, and registered Darwin
alias receipt or explicit null. Writeback preflight and verification bind the
snapshot, patch stage, and live store together and establish one common
point-in-time success boundary before close-only descriptor teardown. A v3
snapshot is not writeback-grade, and a preflight receipt never authorizes a
later live-store mutation.
Snapshot/stage API and CLI inputs use one absolute lexical path policy for the
root and every derived member, so relative paths cannot split parent authority.
The API path object and CLI adapter likewise freeze both live-container inputs
against one captured working directory before preflight, manifest generation,
or later equality checks.
`merge-db` and `stage-patch` also freeze their source and all output paths from
one API/CLI-entry CWD snapshot before destination preflight; stage manifests
and creator result files record only those frozen paths. When a `merge-db`
source belongs to a copied snapshot, its default output is a randomized
owner-private file outside that snapshot. Explicit outputs are rejected when
lexical, registered-canonical, or descriptor ancestry proves overlap in either
direction.
Notes process-state checks use fixed `/usr/bin/pgrep`, a minimal environment,
a hard deadline, process-group cleanup, and a closed fail-unknown result matrix.
For `copy-db --require-notes-quit`, the helper checks at preflight, at the end
of the before-rename callback, and immediately after publication before
emitting a successful result. If Notes starts after publication, the exact
held snapshot object is moved with no replacement to an owner-private hidden
quarantine sibling. The command fails with non-writeback-grade recovery
evidence and never leaves that exact object at the requested destination. It
claims a verified quarantine only after directory-policy, parent-durability,
complete-tree, and terminal-alias proofs; a visible rename with any missing
proof is `namespace-moved-unverified` with inconclusive cleanup.
The first action after a no-replace rename returns, or after an error path
proves that the exact object committed, is a monotonic publication latch.
Post-publication ordinary failures—including failures while constructing
terminal recovery evidence—therefore retain descriptor-bound, non-retryable
uncertain-state evidence. Snapshot sidecar and SQLite validation reuse the
capture-bound file descriptors, and uncertain directory publication records
an exact descriptor-bound tree receipt. Prepared and artifact directory scans
reject names outside the small expected namespace before per-entry metadata
reads, enforce 64-entry and 4-KiB aggregate raw-name limits, and compare
raw-name/type maps across both passes. `merge-db` retains the legacy
`merged_db` JSON key alongside `standalone_db`. The toolkit does not mutate
the live Notes store.

Creator result-file publication similarly latches its exact terminal receipt:
late result-scope teardown failures report the artifact mutation, committed
result-file state, receipt, and non-retryable classification. Standalone
recovery files bind effective ownership, group, mode, Darwin access-controlling
flags, and identity before the first sensitive write and revalidate that
baseline immediately after writing. Other Darwin flags, including hidden,
no-dump, compression, and File Provider state, remain metadata evidence rather
than access-policy mismatch signals.

`scripts/apple_notes_helper.sh` remains the top-level Notes/AppleScript wrapper
and delegates database subcommands to the skill-packaged helper.

## Project Records

Repository-wide state and backlog remain short in
[`docs/PROJECT_STATE.md`](docs/PROJECT_STATE.md) and
[`docs/PROJECT_TODO.md`](docs/PROJECT_TODO.md). Durable workstream records live
under [`docs/project_journal/`](docs/project_journal/).

## Test

```bash
bash -n scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
shellcheck scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
python3 -m unittest discover -s tests -p 'test_*.py'
```
