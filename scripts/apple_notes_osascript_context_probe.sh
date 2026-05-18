#!/usr/bin/env bash
set -euo pipefail

TARGET_SCRIPT='tell application "Notes" to get name of folders'

run_case() {
  local name="$1"
  shift

  echo "=== ${name} ==="

  local stdout_file stderr_file rc
  stdout_file="$(mktemp /tmp/apple-notes-probe-stdout.XXXXXX)"
  stderr_file="$(mktemp /tmp/apple-notes-probe-stderr.XXXXXX)"

  if "$@" >"$stdout_file" 2>"$stderr_file"; then
    rc=0
  else
    rc=$?
  fi

  echo "exit_code=${rc}"

  echo "--- stdout ---"
  if [[ -s "$stdout_file" ]]; then
    cat "$stdout_file"
  else
    echo "<empty>"
  fi

  echo "--- stderr ---"
  if [[ -s "$stderr_file" ]]; then
    cat "$stderr_file"
  else
    echo "<empty>"
  fi

  rm -f "$stdout_file" "$stderr_file"
  echo
}

run_case "direct-osascript" \
  /usr/bin/osascript -e "$TARGET_SCRIPT"

run_case "bash-lc-osascript" \
  /bin/bash -lc "/usr/bin/osascript -e '$TARGET_SCRIPT'"

run_case "zsh-lc-osascript" \
  /bin/zsh -lc "/usr/bin/osascript -e '$TARGET_SCRIPT'"

run_case "python-subprocess-list-argv" \
  /usr/bin/python3 -c \
  'import subprocess, sys
cmd = ["/usr/bin/osascript", "-e", sys.argv[1]]
result = subprocess.run(cmd, text=True, capture_output=True)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
raise SystemExit(result.returncode)' \
  "$TARGET_SCRIPT"

run_case "python-subprocess-shell-true" \
  /usr/bin/python3 -c \
  'import subprocess, sys
cmd = f"/usr/bin/osascript -e '"'"'{sys.argv[1]}'"'"'"
result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
raise SystemExit(result.returncode)' \
  "$TARGET_SCRIPT"
