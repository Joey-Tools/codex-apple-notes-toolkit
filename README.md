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
locators. Snapshot sidecar and SQLite validation reuse the capture-bound file
descriptors, and uncertain directory publication records an exact
descriptor-bound tree receipt. `merge-db` retains the legacy `merged_db` JSON
key alongside `standalone_db`. The toolkit does not mutate the live Notes store.

`scripts/apple_notes_helper.sh` remains the top-level Notes/AppleScript wrapper
and delegates database subcommands to the skill-packaged helper.

## Test

```bash
bash -n scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
shellcheck scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
python3 -m unittest tests.test_apple_notes_helper
```
