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
Exact Darwin root aliases such as `/tmp -> /private/tmp` are
registry-bound and continuously revalidated through the same carried alias
object across receipt loading, creator results, publication, and terminal
public-path checks; arbitrary symlinks fail closed. Snapshot recovery acquires
its output/live-container guard before validation can allocate temporary
storage, clone inputs, or invoke a writer.
Snapshot/stage API and CLI inputs use one absolute lexical path policy for the
root and every derived member, so relative paths cannot split parent authority.
Notes process-state checks use fixed `/usr/bin/pgrep`, a minimal environment,
a hard deadline, process-group cleanup, and a closed fail-unknown result matrix.
Post-publication ordinary failures retain descriptor-bound, non-retryable
uncertain-state evidence. Snapshot sidecar and SQLite validation reuse the
capture-bound file descriptors, and uncertain directory publication records an
exact descriptor-bound tree receipt. `merge-db` retains the legacy `merged_db`
JSON key alongside `standalone_db`. The toolkit does not mutate the live Notes
store.

`scripts/apple_notes_helper.sh` remains the top-level Notes/AppleScript wrapper
and delegates database subcommands to the skill-packaged helper.

## Test

```bash
bash -n scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
shellcheck scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
python3 -m unittest tests.test_apple_notes_helper
```
