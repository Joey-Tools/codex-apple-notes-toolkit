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
from descriptor-bound inputs before SQLite consumes an anonymous
descriptor-backed image. Snapshot files, the nested store, and the snapshot
root are fsynced bottom-up before publication. Publication uses held parent
descriptors for rename, fsync, and terminal revalidation; retained sensitive
partials and uncertain standalone destinations receive precise recovery
locators. Every output command rejects case/NFD, ancestor/descendant, and
descriptor-resolved overlap with either live Notes container before its first
write. Existing destination and live-container paths are bound one no-follow
component at a time; initially absent live containers retain their nearest
existing ancestor and missing suffix through creation and terminal checks.
Missing destination components and private partials are first created at
randomized owner-private staging names only through a trusted creator that
returns the already-open object descriptor and an exclusive-handoff
attestation. A later `open` after `mkdir` is never accepted as creation proof;
the packaged production client instead accepts an inherited, already-connected
`AF_UNIX`/`SOCK_DGRAM` supervisor channel through
`--directory-creator-fd`. It transfers the held parent FD with `SCM_RIGHTS`
and accepts only the supervisor's continuously held created-directory FD plus
a request-bound attestation; it never reconnects by socket path or performs a
local create-then-open fallback. Without that capability, creation fails
before mutation with `directory-creation-identity-inconclusive`. The held
object is installed at the target name with atomic no-replace rename. Identity
and access policy are revalidated around carried scope checks; failed installs
retain structured evidence instead of using a racy name-based directory
cleanup. A trusted creator that fails after creation transfers the created
name, descriptor, creation stat, proof, and recovery details through a
structured exception. A normal return of `None`, missing fields, or wrong
field types is also treated as possibly post-mutation: recoverable FDs are
captured and closed, cleanup stays worst-case, and recovery locators are
unioned. Unstructured creator failures are never treated as retry-safe.
Exact Darwin root aliases such as `/tmp -> /private/tmp` are
registry-bound and continuously revalidated through the same carried alias
object across receipt loading, creator results, publication, and terminal
public-path checks; arbitrary symlinks fail closed. Live NoteStore discovery,
open, hashing, membership checks, and terminal revalidation share one complete
held no-follow group-container component chain. Every existing untrusted
regular-file leaf is opened with both `O_NOFOLLOW` and `O_NONBLOCK`, then
descriptor-checked as regular, so a stat/open FIFO or device replacement
cannot block before type and identity rejection. Snapshot recovery acquires
its output/live-container guard before validation and then consumes the held
snapshot store directly; recovery uses in-memory bytes and anonymous
temporary file descriptors, not named temporary or recovery-clone
directories.
Snapshot/stage API and CLI inputs use one absolute lexical path policy for the
root and every derived member, so relative paths cannot split parent authority.
Notes process-state checks use fixed `/usr/bin/pgrep`, a minimal environment,
a hard deadline, process-group cleanup, and a closed fail-unknown result matrix.
The first action after a no-replace rename returns, or after an error path
proves that the exact object committed, is a monotonic publication latch.
Post-publication ordinary failures—including failures while constructing
terminal recovery evidence—therefore retain descriptor-bound, non-retryable
uncertain-state evidence. Snapshot sidecar and SQLite validation reuse the
capture-bound file descriptors, and uncertain directory publication records
an exact descriptor-bound tree receipt. `merge-db` retains the legacy
`merged_db` JSON key alongside `standalone_db`. The toolkit does not mutate
the live Notes store.

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
python3 -m unittest tests.test_apple_notes_helper
```
