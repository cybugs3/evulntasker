#!/usr/bin/env bash
# Remove EVulnTasker from this Linux host. A copy of the database is kept.
#
#   sudo ./uninstall.sh
#   sudo ./uninstall.sh --yes
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
if [[ -f "$HERE/scripts/evulntasker-lib.sh" ]]; then
  source "$HERE/scripts/evulntasker-lib.sh"
elif [[ -f /opt/evulntasker/scripts/evulntasker-lib.sh ]]; then
  source /opt/evulntasker/scripts/evulntasker-lib.sh
else
  printf '\033[0;31m[error]\033[0m Cannot find scripts/evulntasker-lib.sh\n' >&2
  exit 1
fi

PREFIX="/opt/evulntasker"
YES=0
BACKUP_DIR=""

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [options]

  --prefix DIR        Install location (default: /opt/evulntasker)
  --backup-dir DIR    Where to write the DB backup (default: /var/backups/evulntasker or ~/evulntasker-backups)
  --yes               Do not ask for confirmation
  -h, --help          Show this help

Stops the service, copies the database aside, then deletes the application,
virtualenv, systemd unit, logs, and .env (including GMAIL_APP_PASSWORD).
The database backup is not deleted and does not contain Gmail secrets.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --backup-dir) BACKUP_DIR="${2:-}"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) evulntasker_die "Unknown option: $1" ;;
  esac
done

if [[ -z "$PREFIX" ]]; then
  PREFIX="/opt/evulntasker"
fi
PREFIX="$(cd "$PREFIX" && pwd)"
evulntasker_is_tree "$PREFIX" || evulntasker_die "Not a EVulnTasker install: $PREFIX"

if [[ -z "$BACKUP_DIR" ]]; then
  if [[ "$(id -u)" -eq 0 ]]; then
    BACKUP_DIR="/var/backups/evulntasker"
  else
    BACKUP_DIR="$HOME/evulntasker-backups"
  fi
fi

echo "This will remove EVulnTasker from: $PREFIX"
echo "Database backup will be written to: $BACKUP_DIR"
echo "GMAIL_APP_PASSWORD in $PREFIX/.env is deleted with the install and is NOT copied into the DB backup."
if [[ "$YES" -ne 1 ]]; then
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "Aborted."; exit 1; }
fi

evulntasker_load_env "$PREFIX/.env"
evulntasker_stop_service "$PREFIX"

if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
  for svc in "$SERVICE_NAME" "${LEGACY_SERVICE_NAMES[@]}"; do
    systemctl disable --now "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
  done
  systemctl daemon-reload 2>/dev/null || true
  evulntasker_ok "systemd units removed"
fi

evulntasker_backup_db "$PREFIX" "$BACKUP_DIR" || evulntasker_warn "Proceeding without a successful DB backup"

# Drop Gmail App Password from disk before removing the tree. Never copy it into the DB backup.
if [[ -f "$PREFIX/.env" ]]; then
  if command -v shred >/dev/null 2>&1; then
    shred -u "$PREFIX/.env" 2>/dev/null || rm -f "$PREFIX/.env"
  else
    : > "$PREFIX/.env"
    rm -f "$PREFIX/.env"
  fi
  evulntasker_ok "Removed .env (GMAIL_APP_PASSWORD and other secrets are not in the database backup)"
fi

# Do not delete the backup directory even if it lives under PREFIX.
if [[ "$BACKUP_DIR" == "$PREFIX"* ]]; then
  evulntasker_warn "Backup dir is inside the install tree; copying it out first"
  SAFE="/var/backups/evulntasker"
  [[ "$(id -u)" -eq 0 ]] || SAFE="$HOME/evulntasker-backups"
  mkdir -p "$SAFE"
  cp -a "$BACKUP_DIR"/. "$SAFE/" 2>/dev/null || true
  BACKUP_DIR="$SAFE"
fi

rm -rf "$PREFIX/venv" "$PREFIX/.venv" "$PREFIX/logs"
if [[ "$PREFIX" == /opt/evulntasker || "$PREFIX" == /usr/local/evulntasker ]]; then
  rm -rf "$PREFIX"
  evulntasker_ok "Removed $PREFIX"
else
  # In-place tree (dev checkout): remove generated artefacts, keep source.
  rm -f "$PREFIX/.env" "$PREFIX/logs/evulntasker.pid"
  evulntasker_warn "Prefix looks like a source tree — left application files in $PREFIX"
  evulntasker_ok "Removed venv, logs, and .env (Gmail App Password wiped)"
fi

echo
evulntasker_ok "EVulnTasker has been uninstalled"
echo "  Database backup: $BACKUP_DIR"
if [[ "$HERE" != "$PREFIX" && -d "$HERE/venv" ]]; then
  evulntasker_warn "Left checkout venv in place: $HERE/venv (not part of $PREFIX)"
  echo "  To drop it:  rm -rf $HERE/venv"
fi
ls -lh "$BACKUP_DIR" 2>/dev/null | tail -n +1 || true
