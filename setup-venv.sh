#!/usr/bin/env bash
# Build a Python 3.11 test venv on this RHEL host, then you can run: python3 app.py
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

die() { echo "ERROR: $*" >&2; exit 1; }

PYTHON=""
for cand in python3 python3.14 python3.13 python3.12 python3.11; do
  command -v "$cand" >/dev/null 2>&1 || continue
  if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    PYTHON="$cand"
    break
  fi
done

if [[ -z "$PYTHON" ]]; then
  die "Need Python 3.11+ (RHEL 8 /usr/bin/python3 is too old).
Install from AppStream, then re-run this script:
  sudo yum install python3.11 python3.11-pip python3.11-devel gcc
  # RHEL 9: sudo dnf install python3.11 python3.11-pip python3.11-devel gcc"
fi

echo "Using $($PYTHON --version) ($PYTHON)"

if [[ ! -x "$ROOT/venv/bin/python" ]]; then
  "$PYTHON" -m venv "$ROOT/venv" || die "python -m venv failed. Install python3.11 from AppStream."
  echo "Created $ROOT/venv"
fi

# shellcheck disable=SC1091
source "$ROOT/venv/bin/activate"
python -m pip install --upgrade pip
if [[ -d "$ROOT/vendor/wheels" ]] && ls "$ROOT/vendor/wheels"/*.whl >/dev/null 2>&1; then
  echo "Installing from local vendor/wheels (offline)"
  pip install --no-index --find-links "$ROOT/vendor/wheels" -r "$ROOT/requirements.lock.txt"
else
  pip install -r "$ROOT/requirements.txt"
fi

mkdir -p "$ROOT/data" "$ROOT/logs"
[[ -f "$ROOT/.env" ]] || cp "$ROOT/.env.example" "$ROOT/.env"

echo
echo "Test venv is ready. On this RHEL host run:"
echo "  python3 -m venv venv && source venv/bin/activate"
echo "  python3 app.py"
echo
echo "Then open http://127.0.0.1:8080"
echo "If you need access from another machine: sudo ./scripts/open-firewall.sh"
