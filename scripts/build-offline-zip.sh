#!/usr/bin/env bash
# Build a fully offline ZIP for installing EVulnTasker on another RHEL host.
# This machine MAY use the network to fetch wheels once. The ZIP itself
# contains every Python package so the target host needs no internet.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="${ROOT}/.venv/bin/python"
PIP="${ROOT}/.venv/bin/pip"
[[ -x "$PY" ]] || { echo "Run from a tree that already has .venv (this build host)."; exit 1; }

STAMP="$(date +%Y%m%d)"
NAME="EVulnTasker-offline-el8-x86_64-py311"
DIST="$ROOT/dist"
STAGE="$DIST/staging/$NAME"
WHEELS="$ROOT/vendor/wheels"

echo "==> Freezing locked requirements from this venv"
"$PIP" freeze | grep -vE '^(pkg.resources|pip==)' > "$ROOT/requirements.lock.txt"

echo "==> Downloading wheels into $WHEELS (build host only)"
mkdir -p "$WHEELS"
"$PIP" download \
  --dest "$WHEELS" \
  -r "$ROOT/requirements.lock.txt" \
  pip setuptools wheel

echo "==> Staging tree"
rm -rf "$STAGE"
mkdir -p "$STAGE/vendor" "$STAGE/scripts" "$STAGE/systemd" "$STAGE/data" "$STAGE/logs"

# Application source
cp -a "$ROOT/app" "$STAGE/app"
cp -a "$ROOT/alembic" "$STAGE/alembic"
cp -a "$ROOT/tests" "$STAGE/tests"
cp -a "$ROOT/systemd" "$STAGE/systemd"
cp -a "$ROOT/vendor/wheels" "$STAGE/vendor/wheels"

cp "$ROOT/alembic.ini" "$ROOT/requirements.txt" "$ROOT/requirements.lock.txt" \
   "$ROOT/pytest.ini" "$ROOT/README.md" "$ROOT/.env.example" "$STAGE/"
cp "$ROOT/scripts/run.sh" "$ROOT/scripts/open-firewall.sh" "$STAGE/scripts/"
cp "$ROOT/scripts/install.sh" "$STAGE/install.sh"
chmod +x "$STAGE/install.sh" "$STAGE/scripts/"*.sh

# Never ship secrets or local DB/logs.
rm -f "$STAGE/.env"
find "$STAGE" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true

cat > "$STAGE/PLATFORM.txt" <<EOF
name=$NAME
built=$(date -Iseconds)
python=$("$PY" -c 'import sys; print(sys.version)')
arch=$(uname -m)
kernel=$(uname -r)
os=$(. /etc/os-release && echo "$NAME $VERSION_ID")
wheel_count=$(ls -1 "$WHEELS"/*.whl | wc -l)
EOF

cat > "$STAGE/INSTALL.txt" <<'EOF'
EVulnTasker — offline install on Red Hat Enterprise Linux
========================================================

This ZIP contains the application AND every Python wheel.
The target server does not need internet access.

Requirements on the target (from local RHEL ISO/AppStream, not PyPI):
  - RHEL 8 or 9, x86_64
  - python3.11 and python3.11 (venv module)
    RHEL 8:  yum install python3.11

One command after unzip:

  unzip EVulnTasker-offline-el8-x86_64-py311.zip
  cd EVulnTasker-offline-el8-x86_64-py311
  sudo ./install.sh

That creates .venv from vendor/wheels, writes .env, and enables
the systemd service on port 8080.

Without sudo (foreground/background process only):

  ./install.sh

Open the dashboard at http://127.0.0.1:8080
If a Windows browser cannot reach the VM IP, forward port 8080 over SSH
or run:  sudo ./scripts/open-firewall.sh
EOF

mkdir -p "$DIST"
ZIP="$DIST/${NAME}.zip"
rm -f "$ZIP"
echo "==> Writing $ZIP"
(
  cd "$DIST/staging"
  if command -v zip >/dev/null 2>&1; then
    zip -r -q "$ZIP" "$NAME"
  else
    "$PY" - <<PY
import pathlib, zipfile
root = pathlib.Path(r"$DIST/staging")
zip_path = pathlib.Path(r"$ZIP")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for path in root.rglob("*"):
        if path.is_file():
            zf.write(path, path.relative_to(root))
PY
  fi
)

echo
echo "Bundle ready:"
ls -lh "$ZIP"
echo
echo "Copy to the other RHEL host, then:"
echo "  unzip $(basename "$ZIP")"
echo "  cd $NAME && sudo ./install.sh"
