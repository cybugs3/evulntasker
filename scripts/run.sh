#!/usr/bin/env bash
# Production-style launcher for the EVulnTasker Linux service.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"
if [[ -f "$ROOT/venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/venv/bin/activate"
elif [[ -f "$ROOT/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/.venv/bin/activate"
fi
exec python3 -m uvicorn app.main:app --host "${EVULNTASKER_HOST:-${VULNINTEL_HOST:-0.0.0.0}}" --port "${EVULNTASKER_PORT:-${VULNINTEL_PORT:-8080}}" --log-level info
