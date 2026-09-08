#!/usr/bin/env bash
# Activate the test venv and start with: python3 app.py
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ -f "$ROOT/venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/venv/bin/activate"
elif [[ -f "$ROOT/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/.venv/bin/activate"
fi
exec python3 "$ROOT/app.py"
