# Codex Apple Notes Toolkit

Generic Apple Notes guardrails and read-only database inspection helpers.

The canonical database workflow lives in
`.agents/skills/apple-notes-db-guardrails/`. Its packaged helper captures stable
SQLite/WAL/SHM snapshots, validates SQLite recovery, stages sidecar-free patches,
publishes snapshot/stage directories without replacing existing paths, and
verifies explicit writeback boundaries. It does not mutate the live Notes store.

`scripts/apple_notes_helper.sh` remains the top-level Notes/AppleScript wrapper
and delegates database subcommands to the skill-packaged helper.

## Test

```bash
bash -n scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
shellcheck scripts/apple_notes_helper.sh scripts/apple_notes_osascript_context_probe.sh
python3 -m unittest tests.test_apple_notes_helper
```
