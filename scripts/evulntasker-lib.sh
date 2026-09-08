#!/usr/bin/env bash
# Shared helpers for EVulnTasker setup.sh / uninstall.sh / package_offline.sh
# shellcheck shell=bash

evulntasker_ok()   { printf '\033[0;32m[ok]\033[0m %s\n' "$*"; }
evulntasker_warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
evulntasker_die()  { printf '\033[0;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
evulntasker_info() { printf '\033[0;36m[evulntasker]\033[0m %s\n' "$*"; }

SERVICE_NAME="${EVULNTASKER_SERVICE_NAME:-evulntasker}"
LEGACY_SERVICE_NAMES=(vaict vulnintel)

evulntasker_pick_python() {
  local cand ver
  for cand in python3.14 python3.13 python3.12 python3.11 python3; do
    command -v "$cand" >/dev/null 2>&1 || continue
    if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
      printf '%s\n' "$(command -v "$cand")"
      return 0
    fi
  done
  return 1
}

evulntasker_is_tree() {
  local root="$1"
  [[ -f "$root/app.py" && -f "$root/app/main.py" && -f "$root/requirements.txt" ]]
}

evulntasker_load_env() {
  local envfile="$1"
  [[ -f "$envfile" ]] || return 0
  set -a
  # shellcheck disable=SC1090
  source "$envfile"
  set +a
}

evulntasker_sqlite_path() {
  local url="${1:-}"
  local prefix="${2:-.}"
  case "$url" in
    sqlite:///*)
      local path="${url#sqlite:///}"
      if [[ "$path" != /* ]]; then
        path="$prefix/$path"
      fi
      printf '%s\n' "$path"
      ;;
    *)
      return 1
      ;;
  esac
}

evulntasker_backup_db() {
  local prefix="$1"
  local dest_dir="$2"
  mkdir -p "$dest_dir"
  local stamp
  stamp="$(date +%Y%m%d-%H%M%S)"
  local url="${VULNINTEL_DATABASE_URL:-sqlite:///./data/evulntasker.db}"
  local out

  if out="$(evulntasker_sqlite_path "$url" "$prefix")"; then
    if [[ -f "$out" ]]; then
      cp -a "$out" "$dest_dir/evulntasker-db-${stamp}.sqlite"
      evulntasker_ok "SQLite backup: $dest_dir/evulntasker-db-${stamp}.sqlite"
      return 0
    fi
    evulntasker_warn "SQLite file not found ($out) — nothing to back up."
    return 0
  fi

  if command -v pg_dump >/dev/null 2>&1; then
    local pgurl="${url/postgresql+psycopg2:/postgresql:}"
    pgurl="${pgurl/postgresql+psycopg:/postgresql:}"
    out="$dest_dir/evulntasker-db-${stamp}.sql"
    if pg_dump "$pgurl" > "$out" 2>/dev/null; then
      evulntasker_ok "PostgreSQL backup: $out"
      return 0
    fi
    rm -f "$out"
    evulntasker_warn "pg_dump failed — database was not backed up automatically."
    return 1
  fi

  evulntasker_warn "Unknown database URL and pg_dump is missing. No backup created."
  return 1
}

evulntasker_stop_service() {
  if command -v systemctl >/dev/null 2>&1; then
    for svc in "$SERVICE_NAME" "${LEGACY_SERVICE_NAMES[@]}"; do
      if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
        systemctl stop "$svc" 2>/dev/null || true
      fi
    done
  fi
  local prefix="${1:-}"
  if [[ -n "$prefix" && -f "$prefix/logs/evulntasker.pid" ]]; then
    kill "$(cat "$prefix/logs/evulntasker.pid")" 2>/dev/null || true
    rm -f "$prefix/logs/evulntasker.pid"
  fi
}

evulntasker_merge_env() {
  local example="$1"
  local target="$2"
  [[ -f "$example" ]] || return 0
  [[ -f "$target" ]] || { cp "$example" "$target"; return 0; }
  local line key
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    key="${line%%=*}"
    if ! grep -qE "^${key}=" "$target"; then
      printf '\n%s\n' "$line" >> "$target"
    fi
  done < "$example"
}
