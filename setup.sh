#!/usr/bin/env bash
# Install or upgrade EVulnTasker on a Linux host.
#
#   sudo ./setup.sh                  # online install to /opt/evulntasker + systemd
#   sudo ./setup.sh --offline        # no internet; uses vendor/wheels
#   sudo ./setup.sh --offline --upgrade
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$SRC/scripts/evulntasker-lib.sh"

OFFLINE=0
UPGRADE=0
OPEN_FIREWALL=0
NO_SERVICE=0
PREFIX="/opt/evulntasker"
PORT="${VULNINTEL_PORT:-8080}"
RUN_USER="${SUDO_USER:-${USER:-root}}"

usage() {
  cat <<'EOF'
Usage: ./setup.sh [options]

  --offline           Install from vendor/wheels (no internet)
  --upgrade           Update code and Python packages; keep .env and database
  --prefix DIR        Install location (default: /opt/evulntasker)
  --port N            HTTP port (default: 8080)
  --user NAME         Service account (default: sudo user)
  --no-service        Do not install a systemd unit
  --open-firewall     Open TCP port in firewalld if present
  -h, --help          Show this help

Fresh install (always installs to /opt/evulntasker and enables systemd unit evulntasker):
  sudo ./setup.sh --offline

Upgrade (schema is only applied additively; existing rows are kept):
  sudo ./setup.sh --offline --upgrade
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --offline) OFFLINE=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --user) RUN_USER="${2:-}"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --open-firewall) OPEN_FIREWALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) evulntasker_die "Unknown option: $1 (see --help)" ;;
  esac
done

evulntasker_is_tree "$SRC" || evulntasker_die "setup.sh must live in a EVulnTasker tree (app.py + app/)."
[[ "$(id -u)" -eq 0 ]] || evulntasker_die "Run as root so EVulnTasker can install to /opt/evulntasker and register systemd:  sudo ./setup.sh"

if [[ -z "$PREFIX" ]]; then
  PREFIX="/opt/evulntasker"
fi
mkdir -p "$PREFIX"
PREFIX="$(cd "$PREFIX" && pwd)"

if [[ "$UPGRADE" -eq 1 ]]; then
  evulntasker_is_tree "$PREFIX" || evulntasker_die "--upgrade requires an existing EVulnTasker install at $PREFIX"
fi

WHEELS="$SRC/vendor/wheels"
REQ="$SRC/requirements.lock.txt"
[[ -f "$REQ" ]] || REQ="$SRC/requirements.txt"

if [[ "$OFFLINE" -eq 1 ]]; then
  [[ -d "$WHEELS" ]] || evulntasker_die "Missing $WHEELS. Build a bundle with ./package_offline.sh first."
  [[ -n "$(ls -A "$WHEELS"/*.whl 2>/dev/null)" ]] || evulntasker_die "No .whl files in $WHEELS"
fi

PYTHON="$(evulntasker_pick_python)" || evulntasker_die "Python 3.11+ is required (python3.11 on RHEL AppStream)."
evulntasker_info "Python: $PYTHON ($("$PYTHON" --version 2>&1))"
evulntasker_info "Prefix: $PREFIX"
[[ "$OFFLINE" -eq 1 ]] && evulntasker_info "Mode: offline" || evulntasker_info "Mode: online"
[[ "$UPGRADE" -eq 1 ]] && evulntasker_info "Mode: upgrade (database will be preserved)"

# --- copy / refresh application files ---
mkdir -p "$PREFIX"
if [[ "$SRC" != "$PREFIX" ]]; then
  evulntasker_info "Syncing application files to $PREFIX"
  mkdir -p "$PREFIX/data" "$PREFIX/logs"
  for item in app alembic scripts systemd tests app.py requirements.txt \
              requirements.lock.txt alembic.ini pytest.ini .env.example \
              EVulnTasker-ICON.png setup.sh setup-venv.sh uninstall.sh \
              package_offline.sh INSTALL.txt PLATFORM.txt; do
    if [[ -e "$SRC/$item" ]]; then
      rm -rf "$PREFIX/$item"
      cp -a "$SRC/$item" "$PREFIX/$item"
    fi
  done
  if [[ -d "$SRC/vendor/wheels" ]]; then
    mkdir -p "$PREFIX/vendor"
    rm -rf "$PREFIX/vendor/wheels"
    cp -a "$SRC/vendor/wheels" "$PREFIX/vendor/wheels"
  fi
fi
mkdir -p "$PREFIX/data" "$PREFIX/logs" "$PREFIX/vendor/wheels"

if [[ ! -f "$PREFIX/.env" ]]; then
  cp "$PREFIX/.env.example" "$PREFIX/.env"
  evulntasker_ok "Wrote $PREFIX/.env from template — edit credentials if needed"
else
  evulntasker_merge_env "$PREFIX/.env.example" "$PREFIX/.env"
  evulntasker_ok "Keeping existing .env (new keys merged from template, including GMAIL_*)"
fi

gmail_key_set() {
  local key="$1"
  grep -qE "^${key}=.+" "$PREFIX/.env" 2>/dev/null
}
if gmail_key_set GMAIL_SENDER_EMAIL && gmail_key_set GMAIL_APP_PASSWORD && gmail_key_set GMAIL_RECEIVER_EMAIL; then
  evulntasker_ok "Gmail Act tickets enabled (smtp.gmail.com:587 STARTTLS)"
else
  evulntasker_warn "Gmail Act tickets are off until GMAIL_SENDER_EMAIL, GMAIL_APP_PASSWORD, and GMAIL_RECEIVER_EMAIL are set in $PREFIX/.env (use a Google App Password, not the account password)"
fi

if [[ "$UPGRADE" -eq 1 ]]; then
  evulntasker_load_env "$PREFIX/.env"
  BACKUP_DIR="${EVulnTasker_BACKUP_DIR:-/var/backups/evulntasker}"
  [[ "$(id -u)" -eq 0 ]] || BACKUP_DIR="${EVulnTasker_BACKUP_DIR:-$HOME/evulntasker-backups}"
  evulntasker_stop_service "$PREFIX"
  evulntasker_backup_db "$PREFIX" "$BACKUP_DIR" || evulntasker_warn "Upgrade continues without a DB backup"
fi

if [[ "$SRC" != "$PREFIX" && -f "$SRC/.env.example" && -f "$SRC/.env" ]]; then
  evulntasker_merge_env "$SRC/.env.example" "$SRC/.env"
fi

# --- virtualenv + wheels ---
install_python_packages() {
  local venv_dir="$1"
  local pip="$venv_dir/bin/pip"
  local py="$venv_dir/bin/python"
  local wheels="$PREFIX/vendor/wheels"
  local req_txt="$PREFIX/requirements.txt"
  local req_lock="$PREFIX/requirements.lock.txt"
  [[ -f "$req_lock" ]] || req_lock="$req_txt"
  [[ -x "$pip" ]] || evulntasker_die "pip is missing inside $venv_dir"

  if [[ "$OFFLINE" -eq 1 ]]; then
    "$pip" install --no-index --find-links "$wheels" --upgrade pip setuptools wheel
    evulntasker_info "Installing dependencies from local wheels into $venv_dir"
    "$pip" install --no-index --find-links "$wheels" -r "$req_lock"
    if ls "$wheels"/aiosmtplib-*.whl >/dev/null 2>&1; then
      "$pip" install --no-index --find-links "$wheels" "aiosmtplib>=3.0.2"
    fi
  else
    "$pip" install --upgrade pip setuptools wheel
    evulntasker_info "Installing dependencies from PyPI into $venv_dir"
    "$pip" install -r "$req_lock"
    "$pip" install -r "$req_txt"
    "$pip" install "aiosmtplib>=3.0.2"
  fi
  if "$py" -c "import aiosmtplib" 2>/dev/null; then
    evulntasker_ok "aiosmtplib ready in $venv_dir (Gmail Act tickets)"
  else
    evulntasker_warn "aiosmtplib missing in $venv_dir — python3 app.py will start, but Gmail send is skipped until: $pip install aiosmtplib"
  fi
}

VENV="$PREFIX/venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  "$PYTHON" -m venv "$VENV" || evulntasker_die "python -m venv failed. Install the matching python3.x-venv package."
  evulntasker_ok "Created $VENV"
fi
if [[ ! -x "$VENV/bin/pip" ]]; then
  "$VENV/bin/python" -m ensurepip --upgrade 2>/dev/null || true
fi
install_python_packages "$VENV"

# Checkout venv used by `python3 app.py` (e.g. /home/guy/evulntasker/venv) is not /opt/evulntasker/venv.
if [[ -x "$SRC/venv/bin/python" && "$SRC/venv" != "$VENV" ]]; then
  evulntasker_info "Updating source-tree venv for python3 app.py: $SRC/venv"
  if [[ ! -x "$SRC/venv/bin/pip" ]]; then
    "$SRC/venv/bin/python" -m ensurepip --upgrade 2>/dev/null || true
  fi
  if [[ -x "$SRC/venv/bin/pip" ]]; then
    install_python_packages "$SRC/venv"
  else
    evulntasker_warn "Could not update $SRC/venv (pip missing). Run: $SRC/venv/bin/python -m pip install aiosmtplib"
  fi
fi

# --- schema: additive only (create missing tables; never drop data) ---
evulntasker_info "Applying database schema (create_all / alembic, non-destructive)"
(
  cd "$PREFIX"
  export PYTHONPATH="$PREFIX"
  if [[ -d "$PREFIX/alembic/versions" ]] && ls "$PREFIX/alembic/versions"/*.py >/dev/null 2>&1; then
    "$VENV/bin/alembic" upgrade head
  else
    "$VENV/bin/python" -c "from app.db.session import init_db; init_db()"
  fi
)
evulntasker_ok "Database schema is up to date"

# --- ownership ---
RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"
chown -R "$RUN_USER:$RUN_GROUP" "$PREFIX"
if [[ -d "$SRC/venv" && "$SRC/venv" != "$VENV" ]]; then
  chown -R "$RUN_USER:$RUN_GROUP" "$SRC/venv" || true
fi

# --- systemd unit: evulntasker ---
if [[ "$NO_SERVICE" -eq 1 ]]; then
  evulntasker_warn "--no-service: unit not installed. Start manually: $VENV/bin/python $PREFIX/app.py"
else
  command -v systemctl >/dev/null 2>&1 || evulntasker_die "systemd is required (systemctl not found)."
  [[ -d /etc/systemd/system ]] || evulntasker_die "systemd is required (/etc/systemd/system is missing)."
  UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
  cat > "$UNIT" <<EOF
[Unit]
Description=EVulnTasker — Elizarov Vulnrabilities Tasking Manager Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${PREFIX}
Environment=PYTHONPATH=${PREFIX}
Environment=VULNINTEL_ENV=production
EnvironmentFile=-${PREFIX}/.env
ExecStart=${VENV}/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --log-level info
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=evulntasker

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p "$PREFIX/systemd"
  install -m 0644 "$UNIT" "$PREFIX/systemd/${SERVICE_NAME}.service"
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  evulntasker_ok "systemd service enabled: ${SERVICE_NAME}.service"
fi

if [[ "$OPEN_FIREWALL" -eq 1 ]]; then
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${PORT}/tcp"
    firewall-cmd --reload
    evulntasker_ok "firewalld opened TCP $PORT"
  else
    evulntasker_warn "firewalld not found; skip --open-firewall"
  fi
fi

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
evulntasker_ok "EVulnTasker is ready"
echo "  Dashboard:  http://127.0.0.1:${PORT}"
[[ -n "$HOST_IP" ]] && echo "  LAN:        http://${HOST_IP}:${PORT}"
echo "  Install:    $PREFIX"
echo "  Config:     $PREFIX/.env"
echo "  Data:       $PREFIX/data"
echo "  Gmail Act:  set GMAIL_SENDER_EMAIL / GMAIL_APP_PASSWORD / GMAIL_RECEIVER_EMAIL in .env, then restart"
[[ -x "$SRC/venv/bin/python" && "$SRC/venv" != "$VENV" ]] && \
  echo "  Dev venv:   $SRC/venv (aiosmtplib installed for python3 app.py)"
echo
echo "  Service:"
echo "    sudo systemctl start ${SERVICE_NAME}"
echo "    sudo systemctl stop ${SERVICE_NAME}"
echo "    sudo systemctl restart ${SERVICE_NAME}"
echo "    sudo systemctl status ${SERVICE_NAME}"
echo "    sudo journalctl -u ${SERVICE_NAME} -f"
[[ "$UPGRADE" -eq 1 ]] && echo "  Existing database was kept (backup under ${BACKUP_DIR:-/var/backups/evulntasker})"
