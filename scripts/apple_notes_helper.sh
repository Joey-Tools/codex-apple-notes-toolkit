#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="${SCRIPT_DIR}/../.agents/skills/apple-notes-db-guardrails"
DB_HELPER="${SKILL_DIR}/scripts/apple_notes_db.py"
DIRECTORY_SUPERVISOR="${SKILL_DIR}/scripts/apple_notes_directory_supervisor.py"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OSASCRIPT_BIN="${OSASCRIPT_BIN:-/usr/bin/osascript}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/apple_notes_helper.sh probe-notes
  bash scripts/apple_notes_helper.sh list-folders
  bash scripts/apple_notes_helper.sh show-note-prefix --folder FOLDER --prefix PREFIX
  bash scripts/apple_notes_helper.sh probe-db-access
  bash scripts/apple_notes_helper.sh copy-db [--dest PATH] [--result-file PATH] [--require-notes-quit] [--directory-creator-fd FD]
  bash scripts/apple_notes_helper.sh merge-db --src PATH [--out PATH] [--directory-creator-fd FD]
  bash scripts/apple_notes_helper.sh validate-snapshot --snapshot-dir PATH --manifest-creation-receipt-file PATH
  bash scripts/apple_notes_helper.sh recover-snapshot --snapshot-dir PATH --out PATH --manifest-creation-receipt-file PATH [--directory-creator-fd FD]
  bash scripts/apple_notes_helper.sh stage-patch --src PATH --dest PATH [--result-file PATH] [--directory-creator-fd FD]
  bash scripts/apple_notes_helper.sh validate-patch-stage --stage-dir PATH --manifest-creation-receipt-file PATH
  bash scripts/apple_notes_helper.sh preflight-writeback --backup-dir PATH --stage-dir PATH --backup-manifest-creation-receipt-file PATH --stage-manifest-creation-receipt-file PATH
  bash scripts/apple_notes_helper.sh verify-writeback --backup-dir PATH --stage-dir PATH --backup-manifest-creation-receipt-file PATH --stage-manifest-creation-receipt-file PATH
  bash scripts/apple_notes_helper.sh note-tags --db PATH --title TITLE
  bash scripts/apple_notes_helper.sh fingerprint-db

Notes:
  - Notes app-level preflight is performed via osascript inside this wrapper.
  - DB-heavy subcommands delegate to the helper packaged with apple-notes-db-guardrails.
  - Use copy-db/stage-patch --result-file to atomically create the successful
    JSON outside the artifact for every consuming command.
  - Write-producing DB commands automatically launch the packaged pre-creation
    capability gate. It currently fails closed when directory creation is needed;
    an explicitly inherited supervisor FD remains available to a stronger authority.
  - No subcommand mutates the live Notes store; writeback remains an explicit separate phase.
  - In Codex, prefer this wrapper under an approved/escalated prefix when Notes automation is needed.
EOF
}

folders_json() {
  local raw
  if ! raw="$("$OSASCRIPT_BIN" -e 'tell application "Notes" to get name of folders')"; then
    return 1
  fi

  "$PYTHON_BIN" - "$raw" <<'PY'
import json
import sys

raw = sys.argv[1].strip()
if raw.startswith("(") and raw.endswith(")"):
    raw = raw[1:-1]

folders = []
if raw:
    folders = [{"account": "", "folder": item.strip()} for item in raw.split(", ") if item.strip()]

print(json.dumps(folders, ensure_ascii=False, indent=2))
PY
}

show_note_prefix() {
  local folder=""
  local prefix=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --folder)
        if [[ $# -lt 2 ]]; then
          printf 'show-note-prefix --folder requires a value.\n' >&2
          return 2
        fi
        folder="${2:-}"
        shift 2
        ;;
      --prefix)
        if [[ $# -lt 2 ]]; then
          printf 'show-note-prefix --prefix requires a value.\n' >&2
          return 2
        fi
        prefix="${2:-}"
        shift 2
        ;;
      *)
        printf 'Unsupported show-note-prefix argument: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done

  if [[ -z "$folder" || -z "$prefix" ]]; then
    printf 'show-note-prefix requires --folder FOLDER and --prefix PREFIX.\n' >&2
    return 2
  fi

  "$OSASCRIPT_BIN" - "$folder" "$prefix" <<'APPLESCRIPT'
on run argv
  set targetFolder to item 1 of argv
  set targetPrefix to item 2 of argv
  tell application "Notes"
    set targetFolderRef to folder targetFolder
    tell targetFolderRef
      set matchedNotes to {}
      repeat with n in notes
        set noteName to name of n
        if noteName starts with targetPrefix then
          set end of matchedNotes to n
        end if
      end repeat

      set matchCount to count of matchedNotes
      if matchCount is 0 then
        error "Note title prefix not found in folder " & targetFolder & ": " & targetPrefix number 44
      end if
      if matchCount is greater than 1 then
        error "Note title prefix is ambiguous in folder " & targetFolder & ": " & targetPrefix number 45
      end if

      set matchedNote to item 1 of matchedNotes
      return (name of matchedNote) & linefeed & "----" & linefeed & (plaintext of matchedNote)
    end tell
  end tell
end run
APPLESCRIPT
}

notes_running_json() {
  if pgrep -x Notes >/dev/null 2>&1; then
    printf 'true'
  else
    printf 'false'
  fi
}

main() {
  if [[ $# -eq 0 ]]; then
    usage
    return 2
  fi

  case "$1" in
    probe-notes)
      shift
      printf '{\n  "notes_running": %s,\n  "automation_ok": true,\n  "folders": %s\n}\n' \
        "$(notes_running_json)" \
        "$(folders_json)"
      ;;
    list-folders)
      shift
      printf '{\n  "folders": %s\n}\n' "$(folders_json)"
      ;;
    show-note-prefix)
      shift
      show_note_prefix "$@"
      ;;
    copy-db|merge-db|recover-snapshot|stage-patch)
      local has_directory_creator_fd="false"
      local argument
      for argument in "$@"; do
        case "$argument" in
          --directory-creator-fd|--directory-creator-fd=*)
            has_directory_creator_fd="true"
            ;;
        esac
      done
      if [[ "$has_directory_creator_fd" == "true" ]]; then
        exec "$PYTHON_BIN" "$DB_HELPER" "$@"
      fi
      exec "$PYTHON_BIN" "$DIRECTORY_SUPERVISOR" \
        --helper "$DB_HELPER" \
        --python "$PYTHON_BIN" \
        -- "$@"
      ;;
    probe-db-access|validate-snapshot|validate-patch-stage|preflight-writeback|verify-writeback|note-tags|fingerprint-db)
      exec "$PYTHON_BIN" "$DB_HELPER" "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      printf 'Unsupported command: %s\n\n' "$1" >&2
      usage >&2
      return 2
      ;;
  esac
}

main "$@"
