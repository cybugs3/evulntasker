#!/usr/bin/env bash
# Build a ZIP that can be installed on a Linux target with no internet.
# Run this on a build host AFTER a git clone. This host MAY use the network
# to download Python wheels once.
#
#   git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker
#   cd evulntasker
#   ./package_offline.sh
#   ./package_offline.sh --python python3.11 --output dist
#
# Copy dist/EVulnTasker-offline-*.zip to the air-gapped host, unzip, then:
#   sudo ./setup.sh --offline
#
# Full steps: README.md → Install from scratch → Offline install.
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

Run this on a build host that can reach PyPI, from a git clone:

  git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker
  cd evulntasker
  ./package_offline.sh

  --python EXE     Python used to resolve and download wheels (default: auto)
  --output DIR     Where to write the ZIP (default: ./dist)
  --skip-download  Reuse vendor/wheels instead of fetching from PyPI
  -h, --help       Show this help

The ZIP contains application source, setup.sh, uninstall.sh,
README.md, FUNCTIONALITY.md, GAPS.md, PT-RISK-SURVEY.md, and vendor/wheels/*.whl
(including aiosmtplib for Gmail Act tickets).

On the air-gapped target (no internet):

  unzip EVulnTasker-offline-*.zip
  cd EVulnTasker-offline-*
  sudo ./setup.sh --offline

The service listens on HTTP :8080 (no TLS). Optional Basic Auth is in .env.
See README.md → Install from scratch.
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
         README.md FUNCTIONALITY.md GAPS.md PT-RISK-SURVEY.md .env.example EVulnTasker-ICON.png; do
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
EVulnTasker — install from scratch (offline ZIP)
================================================

This ZIP is the air-gapped half of the install. How it was built (build host
with internet):

  git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker
  cd evulntasker
  ./package_offline.sh

Online install (no ZIP) is: clone, then sudo ./setup.sh. See README.md.

On this target (no internet required):

  unzip EVulnTasker-offline-*.zip
  cd EVulnTasker-offline-*
  sudo ./setup.sh --offline

That copies the tree to /opt/evulntasker, creates the venv from vendor/wheels,
writes .env (mode 600), and enables systemd unit evulntasker on HTTP :8080.

  sudo systemctl status evulntasker
  sudo journalctl -u evulntasker -f

Open http://127.0.0.1:8080 then:

  1. Internal systems — add products or import CSV
  2. Settings → Feeds → Local — folder on this Linux host
  3. Input Sources — Enable / Sync now
  4. Settings → Ticketing / Message as needed

Upgrade without wiping the database:

  sudo ./setup.sh --offline --upgrade

Uninstall (keeps a database backup including Internal systems; .env secrets
including Gmail App Password, SMTP, and Basic Auth are deleted, not backed up):

  sudo ./uninstall.sh --yes

Docs in this tree: README.md, FUNCTIONALITY.md, GAPS.md, PT-RISK-SURVEY.md.

The service binds HTTP :8080 (no TLS). Production sets EVULNTASKER_ENV=production
and hides /docs. Optional HTTP Basic (no login page):

  EVULNTASKER_BASIC_AUTH_USER=lab
  EVULNTASKER_BASIC_AUTH_PASSWORD=change-me

Leave those blank for an open lab UI. Local folder ingest is limited to
/tmp, /var/evulntasker, /opt/evulntasker/inbox, and data/inbox
(add roots with EVULNTASKER_LOCAL_INGEST_ALLOW).

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
echo "Build host (already done if you ran this after git clone):"
echo "  git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker && cd evulntasker && ./package_offline.sh"
echo
echo "Copy to the air-gapped Linux target, then:"
echo "  unzip $(basename "$ZIP")"
echo "  cd $NAME && sudo ./setup.sh --offline"
echo "  open http://127.0.0.1:8080"
echo
echo "Online path (no ZIP): git clone … && cd evulntasker && sudo ./setup.sh"
echo "Full steps: README.md → Install from scratch"
