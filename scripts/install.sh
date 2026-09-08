#!/usr/bin/env bash
# Offline installer for EVulnTasker on RHEL 8/9 (x86_64, Python 3.11).
# No internet is required. Wheels are read from vendor/wheels/.
#
# Usage (one command after unzip):
#   sudo ./install.sh
# or as a regular user:
#   ./install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'
ok() { echo -e "${GRN}[ok]${NC} $*"; }
warn() { echo -e "${YLW}[warn]${NC} $*"; }
die() { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

WHEELS="$ROOT/vendor/wheels"
LOCK="$ROOT/requirements.lock.txt"
[[ -d "$WHEELS" ]] || die "Missing $WHEELS — this is not a complete offline bundle."
[[ -f "$LOCK" ]] || die "Missing $LOCK"

# --- Python 3.11 ---
PYTHON=""
for cand in python3.11 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    PYTHON="$(command -v "$cand")"
    break
  fi
done
[[ -n "$PYTHON" ]] || die "Python 3.11 is required. On RHEL 8 AppStream:  yum install python3.11 python3.11-pip"

PYVER="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
[[ "$PYVER" == "3.11" || "$PYVER" == "3.12" ]] || \
  die "Need Python 3.11+ (found $PYVER at $PYTHON). Same ABI as the machine that built this ZIP."

ARCH="$(uname -m)"
[[ "$ARCH" == "x86_64" ]] || warn "Bundle was built on x86_64; this host is $ARCH."

ok "Using $PYTHON ($PYVER) on $ARCH"
ok "Wheels: $(ls -1 "$WHEELS"/*.whl 2>/dev/null | wc -l) files"

# --- venv from local wheels only ---
export PIP_NO_INDEX=1
export PIP_FIND_LINKS="$WHEELS"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  if ! "$PYTHON" -m venv "$ROOT/.venv" 2>/dev/null; then
    die "python -m venv failed. Install the matching venv package (python3.11) from local RPM media, then re-run."
  fi
  ok "Created virtualenv at $ROOT/.venv"
fi

PIP="$ROOT/.venv/bin/pip"
"$PYTHON" -m venv "$ROOT/.venv" >/dev/null 2>&1 || true

# Bootstrap pip from bundled wheels if ensurepip left a broken pip.
if [[ ! -x "$PIP" ]]; then
  "$ROOT/.venv/bin/python" -m ensurepip --upgrade --default-pip 2>/dev/null || true
fi
[[ -x "$PIP" ]] || die "pip is missing inside .venv"

"$PIP" install --no-index --find-links "$WHEELS" --upgrade pip setuptools wheel >/dev/null
ok "Installing application dependencies from local wheels (offline)…"
"$PIP" install --no-index --find-links "$WHEELS" -r "$LOCK"
ok "Dependencies installed"

mkdir -p "$ROOT/data" "$ROOT/logs"
if [[ ! -f "$ROOT/.env" ]]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  ok "Wrote $ROOT/.env from template — edit credentials as needed"
else
  ok "Keeping existing .env"
fi

chmod +x "$ROOT/scripts/run.sh" 2>/dev/null || true

# --- systemd (when running as root) ---
if [[ "$(id -u)" -eq 0 ]]; then
  RUN_USER="${SUDO_USER:-${INSTALL_USER:-guy}}"
  RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"
  UNIT=/etc/systemd/system/evulntasker.service
  cat > "$UNIT" <<EOF
[Unit]
Description=EVulnTasker Vulnerability Management Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${ROOT}
Environment=PYTHONPATH=${ROOT}
Environment=VULNINTEL_ENV=production
EnvironmentFile=-${ROOT}/.env
ExecStart=${ROOT}/.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --log-level info
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=evulntasker

[Install]
WantedBy=multi-user.target
EOF
  chown -R "$RUN_USER:$RUN_GROUP" "$ROOT/data" "$ROOT/logs" "$ROOT/.env" || true
  systemctl daemon-reload
  systemctl enable --now evulntasker
  ok "systemd unit enabled: $UNIT"
  echo
  echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):8080"
  echo "  Logs:       journalctl -u evulntasker -f"
  echo "  Health:     curl -s http://127.0.0.1:8080/healthz"
else
  warn "Not root — skipped systemd. Starting EVulnTasker in the background."
  nohup "$ROOT/.venv/bin/python" -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --log-level info \
    > "$ROOT/logs/evulntasker.out" 2>&1 &
  echo $! > "$ROOT/logs/evulntasker.pid"
  sleep 1
  ok "PID $(cat "$ROOT/logs/evulntasker.pid")  logs: $ROOT/logs/evulntasker.out"
  echo
  echo "  Dashboard:  http://127.0.0.1:8080"
  echo "  Health:     curl -s http://127.0.0.1:8080/healthz"
  echo "  To install as a service later:  sudo $ROOT/install.sh"
fi
