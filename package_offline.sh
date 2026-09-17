#!/usr/bin/env bash
# Build a ZIP that can be installed on a Linux target with no internet.
# This host MAY use the network to download Python wheels once.
#
#   ./package_offline.sh
#   ./package_offline.sh --python python3.11 --output dist
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/evulntasker-lib.sh"

PYTHON=""
OUT_DIR="$ROOT/dist"
SKIP_DOWNLOAD=0

usage() {
  cat <<'EOF'
Usage: ./package_offline.sh [options]

  --python EXE     Python used to resolve and download wheels (default: auto)
  --output DIR     Where to write the ZIP (default: ./dist)
  --skip-download  Reuse vendor/wheels instead of fetching from PyPI
  -h, --help       Show this help

The ZIP contains application source, setup.sh, uninstall.sh,
README.md, FUNCTIONALITY.md, GAPS.md, and vendor/wheels/*.whl
(including aiosmtplib for Gmail Act tickets)
so the target can run:  sudo ./setup.sh --offline
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python) PYTHON="${2:-}"; shift 2 ;;
    --output) OUT_DIR="${2:-}"; shift 2 ;;
    --skip-download) SKIP_DOWNLOAD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) evulntasker_die "Unknown option: $1" ;;
  esac
done

cd "$ROOT"
evulntasker_is_tree "$ROOT" || evulntasker_die "Run this script from the EVulnTasker project root."

if [[ -z "$PYTHON" ]]; then
  PYTHON="$(evulntasker_pick_python)" || evulntasker_die "Need Python 3.11+ on this build host."
fi
PYVER="$("$PYTHON" -c 'import sys; print("%d%d" % sys.version_info[:2])')"
PYDOT="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
ARCH="$(uname -m)"
STAMP="$(date +%Y%m%d)"
NAME="EVulnTasker-offline-${ARCH}-py${PYVER}-${STAMP}"
STAGE="$OUT_DIR/staging/$NAME"
WHEELS="$ROOT/vendor/wheels"

evulntasker_info "Packaging $NAME with $PYTHON ($PYDOT) on $ARCH"

mkdir -p "$WHEELS"
if [[ "$SKIP_DOWNLOAD" -eq 0 ]]; then
  evulntasker_info "Downloading wheels into $WHEELS (build host only)…"
  "$PYTHON" -m pip download \
    --dest "$WHEELS" \
    -r "$ROOT/requirements.txt" \
    pip setuptools wheel
  # Pin Gmail SMTP explicitly so a stale lock file cannot drop the Act-step sender.
  "$PYTHON" -m pip download --dest "$WHEELS" "aiosmtplib>=3.0.2"
else
  [[ -n "$(ls -A "$WHEELS"/*.whl 2>/dev/null)" ]] || \
    evulntasker_die "--skip-download set but $WHEELS has no .whl files"
fi

if ! ls "$WHEELS"/aiosmtplib-*.whl >/dev/null 2>&1; then
  evulntasker_die "Missing aiosmtplib wheel in $WHEELS (needed for Gmail Act tickets). Re-run without --skip-download."
fi
evulntasker_ok "Gmail SMTP wheel present: $(basename "$(ls -1 "$WHEELS"/aiosmtplib-*.whl | head -1)")"

if [[ -x "$ROOT/venv/bin/pip" ]]; then
  "$ROOT/venv/bin/pip" freeze | grep -vE '^(pkg.resources|pip==|setuptools==|wheel==)' \
    > "$ROOT/requirements.lock.txt" || true
fi
if [[ ! -s "$ROOT/requirements.lock.txt" ]]; then
  cp "$ROOT/requirements.txt" "$ROOT/requirements.lock.txt"
fi
if ! grep -qiE '^aiosmtplib(==|>=)' "$ROOT/requirements.lock.txt"; then
  GMAIL_WHEEL="$(ls -1 "$WHEELS"/aiosmtplib-*.whl | head -1)"
  GMAIL_VER="$(basename "$GMAIL_WHEEL" | sed -n 's/^aiosmtplib-\([^-]*\)-.*/\1/p')"
  if [[ -n "$GMAIL_VER" ]]; then
    printf 'aiosmtplib==%s\n' "$GMAIL_VER" >> "$ROOT/requirements.lock.txt"
  else
    printf 'aiosmtplib>=3.0.2\n' >> "$ROOT/requirements.lock.txt"
  fi
  evulntasker_ok "Pinned aiosmtplib in requirements.lock.txt"
fi

# Keep the checkout venv used by `python3 app.py` in sync (build host).
if [[ -x "$ROOT/venv/bin/pip" ]]; then
  evulntasker_info "Installing aiosmtplib into $ROOT/venv"
  if "$ROOT/venv/bin/pip" install --no-index --find-links "$WHEELS" "aiosmtplib>=3.0.2" \
    || { [[ "$SKIP_DOWNLOAD" -eq 0 ]] && "$ROOT/venv/bin/pip" install "aiosmtplib>=3.0.2"; }; then
    evulntasker_ok "aiosmtplib installed in $ROOT/venv"
  else
    evulntasker_warn "Could not install aiosmtplib into $ROOT/venv — run: venv/bin/pip install aiosmtplib"
  fi
fi

evulntasker_info "Staging tree"
rm -rf "$STAGE"
mkdir -p "$STAGE/vendor" "$STAGE/scripts" "$STAGE/systemd" "$STAGE/data" "$STAGE/logs"

copy_tree() {
  local src="$1" dest="$2"
  [[ -e "$src" ]] || return 0
  mkdir -p "$(dirname "$dest")"
  cp -a "$src" "$dest"
}

copy_tree "$ROOT/app" "$STAGE/app"
copy_tree "$ROOT/alembic" "$STAGE/alembic"
copy_tree "$ROOT/tests" "$STAGE/tests"
copy_tree "$ROOT/systemd" "$STAGE/systemd"
copy_tree "$ROOT/scripts" "$STAGE/scripts"
copy_tree "$ROOT/vendor/wheels" "$STAGE/vendor/wheels"

for f in app.py setup.sh setup-venv.sh uninstall.sh package_offline.sh \
         requirements.txt requirements.lock.txt alembic.ini pytest.ini \
         README.md FUNCTIONALITY.md GAPS.md .env.example EVulnTasker-ICON.png; do
  [[ -f "$ROOT/$f" ]] && cp -a "$ROOT/$f" "$STAGE/$f"
done

chmod +x "$STAGE/setup.sh" "$STAGE/uninstall.sh" "$STAGE/package_offline.sh" \
         "$STAGE/setup-venv.sh" "$STAGE/app.py" "$STAGE/scripts/"*.sh 2>/dev/null || true

rm -f "$STAGE/.env"
find "$STAGE" -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name 'venv' -o -name '.venv' \) \
  -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -type f -name '*.pyc' -delete 2>/dev/null || true

WHEEL_COUNT="$(find "$STAGE/vendor/wheels" -name '*.whl' | wc -l | tr -d ' ')"

cat > "$STAGE/PLATFORM.txt" <<EOF
name=$NAME
product=EVulnTasker
version=$(grep -E '^__version__ =' "$ROOT/app/__init__.py" | head -1 | cut -d'"' -f2)
built=$(date -Iseconds)
python=$PYDOT
arch=$ARCH
wheel_count=$WHEEL_COUNT
gmail_smtp=aiosmtplib
EOF

cat > "$STAGE/INSTALL.txt" <<'EOF'
EVulnTasker — offline install on Linux
================================

This ZIP includes the application and every Python wheel.
The target server does not need internet access.

On the target:

  unzip EVulnTasker-offline-*.zip
  cd EVulnTasker-offline-*
  sudo ./setup.sh --offline

That installs to /opt/evulntasker and enables the systemd service:

  sudo systemctl start evulntasker
  sudo systemctl stop evulntasker
  sudo systemctl restart evulntasker
  sudo systemctl status evulntasker

Upgrade an existing install without wiping the database:

  sudo ./setup.sh --offline --upgrade

Uninstall (keeps a database backup including Internal systems; Gmail App Password in .env is deleted, not backed up):

  sudo ./uninstall.sh --yes

Docs in this tree: README.md, FUNCTIONALITY.md, GAPS.md (remaining work).

CMDB / Sonatype / ITNM are not CVE pipeline steps. They teach the Internal
systems catalog on a schedule (new equipment only) when a live host exists.

Gmail Act tickets (optional). After install, edit /opt/evulntasker/.env:

  GMAIL_SENDER_EMAIL=you@gmail.com
  GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
  GMAIL_RECEIVER_EMAIL=you@gmail.com

Use a Google App Password, not the Gmail account password. Then:

  sudo systemctl restart evulntasker

To run from the unzipped tree without systemd:

  python3 -m venv venv && source venv/bin/activate
  pip install --no-index --find-links vendor/wheels -r requirements.txt
  python3 app.py
EOF

mkdir -p "$OUT_DIR"
ZIP="$OUT_DIR/${NAME}.zip"
rm -f "$ZIP"
evulntasker_info "Writing $ZIP"
(
  cd "$OUT_DIR/staging"
  if command -v zip >/dev/null 2>&1; then
    zip -r -q "$ZIP" "$NAME"
  else
    "$PYTHON" - "$ZIP" "$NAME" <<'PY'
import sys, zipfile
from pathlib import Path
zip_path, name = Path(sys.argv[1]), sys.argv[2]
root = Path(name)
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for path in root.rglob("*"):
        if path.is_file():
            zf.write(path, path.relative_to(Path(".")))
PY
  fi
)

evulntasker_ok "Bundle ready: $ZIP ($WHEEL_COUNT wheels)"
echo
echo "Copy to the target Linux host, then:"
echo "  unzip $(basename "$ZIP")"
echo "  cd $NAME && sudo ./setup.sh --offline"
